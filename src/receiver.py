# SentinelAI - Receiver TCP
# Recebe eventos enviados pelos agentes em tempo real.
#
# Uso: python receiver.py

import os
import sys
import json
import socket
import ssl
import threading
import logging
import time
from datetime import datetime
from collections import defaultdict, deque

from app_config import load_app_config
from app_config import secret_fingerprint
from event_utils import has_valid_auth_token, normalize_event, strip_auth_token
from runtime_paths import get_app_root

# ============================================================
# PATHS
# ============================================================

BASE_DIR = str(get_app_root(__file__))
LOG_FILE    = os.path.join(BASE_DIR, "logs", "receiver.log")

MAX_CLIENTS = 64
MAX_LINE_BYTES = 64 * 1024
MAX_BUFFER_BYTES = 128 * 1024
MAX_ALERT_BUFFER = 5000
CLIENT_TIMEOUT_SECONDS = 30
RATE_WINDOW_SECONDS = 10
RATE_LIMIT_EVENTS = 200


def load_config() -> dict:
    return load_app_config(__file__, create_if_missing=True)

# ============================================================
# CORES NO TERMINAL
# ============================================================

C = {
    "RED":    "\033[91m",
    "ORANGE": "\033[93m",
    "BLUE":   "\033[94m",
    "GREEN":  "\033[92m",
    "CYAN":   "\033[96m",
    "BOLD":   "\033[1m",
    "RESET":  "\033[0m",
}

SEV_COLOR = {"CRITICAL": "RED", "HIGH": "ORANGE", "MEDIUM": "BLUE", "LOW": "GREEN"}

def col(text, color):
    return f"{C.get(color, '')}{text}{C['RESET']}"

# ============================================================
# ESTADO GLOBAL
# ============================================================

agent_stats = defaultdict(lambda: {"events": 0, "alerts": 0, "last_seen": None, "ip": None})
stats_lock  = threading.Lock()
alert_buffer = deque(maxlen=MAX_ALERT_BUFFER)
buffer_lock  = threading.Lock()
client_slots = threading.BoundedSemaphore(MAX_CLIENTS)
rate_lock = threading.Lock()
rate_counters = defaultdict(deque)
nonce_lock = threading.Lock()
seen_nonces = defaultdict(deque)

# ============================================================
# PROCESSAMENTO
# ============================================================

def process_event(event: dict, agent_ip: str):
    host      = event.get("Computer", agent_ip)
    rule_name = event.get("rule_name", "Evento Desconhecido")
    severity  = event.get("severity", "LOW")
    eid       = event.get("EventID", "?")
    channel   = event.get("Channel", "")
    cmd       = event.get("CommandLine", "")
    ts        = event.get("TimeCreated", "")[:19]
    color     = SEV_COLOR.get(severity, "RESET")

    with stats_lock:
        agent_stats[host]["events"]   += 1
        agent_stats[host]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        agent_stats[host]["ip"]        = agent_ip
        if severity in ("CRITICAL", "HIGH", "MEDIUM"):
            agent_stats[host]["alerts"] += 1

    with buffer_lock:
        alert_buffer.append(event)

    print(f"\n{col('-' * 60, color)}")
    print(f"{col(f'[{severity}] {rule_name}', 'BOLD')}")
    print(f"  {col('Host   :', 'CYAN')} {host}  {col(f'({agent_ip})', 'RESET')}")
    print(f"  {col('Canal  :', 'CYAN')} {channel}  |  EventID: {eid}")
    if cmd:
        display = cmd[:100] + "..." if len(cmd) > 100 else cmd
        print(f"  {col('Comando:', 'CYAN')} {display}")
    if ts:
        print(f"  {col('Hora   :', 'CYAN')} {ts}")
    print(col('-' * 60, color))

    logging.info(f"ALERTA | {severity} | {rule_name} | {host} | {cmd[:80]}")


def process_heartbeat(data: dict, agent_ip: str):
    host = data.get("host", agent_ip)
    with stats_lock:
        agent_stats[host]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        agent_stats[host]["ip"]        = agent_ip
    logging.info(f"HEARTBEAT | {host} ({agent_ip})")
    print(f"  {col('Heartbeat:', 'CYAN')} {host} ({agent_ip})")


def allow_event_from_ip(agent_ip: str) -> bool:
    now = time.time()
    with rate_lock:
        events = rate_counters[agent_ip]
        while events and now - events[0] > RATE_WINDOW_SECONDS:
            events.popleft()
        if len(events) >= RATE_LIMIT_EVENTS:
            return False
        events.append(now)
        return True


def accept_nonce(agent_ip: str, nonce: str) -> bool:
    if not nonce:
        return False

    now = time.time()
    with nonce_lock:
        nonces = seen_nonces[agent_ip]
        while nonces and now - nonces[0][1] > 300:
            nonces.popleft()
        if any(item[0] == nonce for item in nonces):
            return False
        nonces.append((nonce, now))
        return True


# ============================================================
# HANDLER DE CLIENTE
# ============================================================

def handle_client(conn: socket.socket, addr: tuple, expected_token: str):
    agent_ip = addr[0]
    logging.info(f"Agente ligado: {agent_ip}:{addr[1]}")
    print(f"\n{col('Agente ligado:', 'GREEN')} {col(agent_ip, 'BOLD')}")

    buf = ""
    buf_bytes = 0
    try:
        conn.settimeout(CLIENT_TIMEOUT_SECONDS)
        while True:
            try:
                chunk = conn.recv(4096)
            except (socket.timeout, ConnectionResetError):
                break
            if not chunk:
                break
            buf_bytes += len(chunk)
            if buf_bytes > MAX_BUFFER_BYTES:
                logging.warning(f"Buffer excedido por {agent_ip}; ligacao terminada.")
                break
            data = chunk.decode("utf-8", errors="ignore")
            buf += data
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                buf_bytes = len(buf.encode("utf-8", errors="ignore"))
                line = line.strip()
                if not line:
                    continue
                if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                    logging.warning(f"Linha demasiado grande de {agent_ip}; descartada.")
                    continue
                if not allow_event_from_ip(agent_ip):
                    logging.warning(f"Rate limit excedido por {agent_ip}; ligacao terminada.")
                    return
                try:
                    event = json.loads(line)
                    if not event.get("AuthSignature"):
                        logging.warning(f"Ligacao rejeitada por assinatura HMAC ausente: {agent_ip}")
                        return
                    if not has_valid_auth_token(event, expected_token):
                        logging.warning(
                            f"Ligacao rejeitada por token invalido: {agent_ip} "
                            f"(token_id_esperado={secret_fingerprint(expected_token)} "
                            f"token_id_recebido={event.get('AuthTokenId', 'N/A')})"
                        )
                        return
                    if not accept_nonce(agent_ip, str(event.get("AuthNonce", ""))):
                        logging.warning(f"Replay rejeitado para {agent_ip}")
                        return
                    event = normalize_event(strip_auth_token(event))
                    if event.get("type") == "heartbeat":
                        process_heartbeat(event, agent_ip)
                    else:
                        process_event(event, agent_ip)
                except json.JSONDecodeError as e:
                    logging.warning(f"JSON invalido de {agent_ip}: {e}")
    except Exception as e:
        logging.error(f"Erro com agente {agent_ip}: {e}")
    finally:
        conn.close()
        logging.info(f"Agente desligado: {agent_ip}")
        print(f"\n{col('Agente desligado:', 'RED')} {agent_ip}")
        client_slots.release()


# ============================================================
# THREAD DE ESTATÍSTICAS
# ============================================================

def stats_loop():
    import time
    while True:
        time.sleep(30)
        with stats_lock:
            if not agent_stats:
                continue
            print(f"\n{col('-' * 60, 'CYAN')}")
            print(col('ESTADO DOS AGENTES', 'BOLD'))
            print(f"  {'HOST':<25} {'IP':<16} {'EVENTOS':<10} {'ALERTAS':<10} {'ULTIMO'}")
            print(f"  {'-'*25} {'-'*15} {'-'*9} {'-'*9} {'-'*8}")
            for host, s in sorted(agent_stats.items()):
                print(f"  {host:<25} {s['ip'] or 'N/A':<16} "
                      f"{s['events']:<10} {s['alerts']:<10} {s['last_seen'] or 'N/A'}")
            print(col('-' * 60, 'CYAN'))


# ============================================================
# SERVIDOR PRINCIPAL
# ============================================================

def build_tls_context(cfg: dict):
    if not cfg.get("receiver_tls_enabled"):
        return None

    certfile = cfg.get("receiver_tls_certfile", "")
    keyfile = cfg.get("receiver_tls_keyfile", "")
    if not certfile or not keyfile:
        raise RuntimeError("TLS ativo requer receiver_tls_certfile e receiver_tls_keyfile.")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    ca_file = cfg.get("receiver_tls_ca_file", "")
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def run_server(host: str, port: int, auth_token: str, cfg: dict | None = None):
    if not auth_token:
        raise RuntimeError("receiver_auth_token e obrigatorio. O modo sem autenticacao foi removido.")

    cfg = cfg or {}
    tls_context = build_tls_context(cfg)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
    except OSError as e:
        logging.error(f"Erro ao ligar em {host}:{port} - {e}")
        print(f"\n{col(f'ERRO: Nao foi possivel abrir a porta {port}', 'RED')}")
        sys.exit(1)

    server.listen(50)

    print(col("=" * 60, "CYAN"))
    print(col("   SentinelAI - Receiver TCP", "BOLD"))
    print(col("=" * 60, "CYAN"))
    print(f"  {col('Endereco :', 'CYAN')} {host}:{port}")
    print(f"  {col('Protocolo:', 'CYAN')} {'TLS' if tls_context else 'TCP'} / JSON Lines")
    print(f"  {col('Auth     :', 'CYAN')} HMAC obrigatorio")
    print(f"  {col('Log      :', 'CYAN')} {LOG_FILE}")
    print(col("=" * 60, "CYAN"))
    print(f"\n  {col('A espera de agentes...', 'BOLD')} (Ctrl+C para parar)\n")

    logging.info(f"Receiver iniciado em {host}:{port}")
    threading.Thread(target=stats_loop, daemon=True).start()

    try:
        while True:
            conn, addr = server.accept()
            if not client_slots.acquire(blocking=False):
                logging.warning(f"Limite de clientes excedido; rejeitado {addr[0]}:{addr[1]}")
                conn.close()
                continue
            if tls_context:
                try:
                    conn = tls_context.wrap_socket(conn, server_side=True)
                except ssl.SSLError as e:
                    logging.warning(f"Handshake TLS falhou para {addr[0]}:{addr[1]} - {e}")
                    conn.close()
                    client_slots.release()
                    continue
            threading.Thread(target=handle_client, args=(conn, addr, auth_token), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        print(f"\n{col('Receiver terminado.', 'BOLD')}")


def main():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ]
    )
    cfg  = load_config()
    host = cfg.get("receiver_host", "0.0.0.0")
    port = int(cfg.get("receiver_port", 9000))
    auth_token = cfg.get("receiver_auth_token", "").strip()
    if not auth_token:
        raise RuntimeError("receiver_auth_token e obrigatorio. Defina-o na configuracao.")
    run_server(host, port, auth_token, cfg)


if __name__ == "__main__":
    main()
