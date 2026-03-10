# receiver.py
# SentinelAI - Servidor de Receção de Logs (TCP)
# Recebe eventos de todos os agentes em tempo real
#
# Uso: python receiver.py  (ou integrar no menu.py opção 9)

import os
import sys
import json
import socket
import threading
import logging
from datetime import datetime
from collections import defaultdict

# ============================================================
# PATHS
# ============================================================

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(BASE_DIR, "sentinelai_config.json")
LOG_FILE    = os.path.join(BASE_DIR, "receiver.log")

# ============================================================
# CONFIG
# ============================================================

DEFAULT_CONFIG = {
    "receiver_port": 9000,
    "receiver_host": "0.0.0.0",
}

def load_config() -> dict:
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception:
        return DEFAULT_CONFIG.copy()

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
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

def col(text, color):
    return f"{C.get(color, '')}{text}{C['RESET']}"

# ============================================================
# ESTADO GLOBAL
# ============================================================

agent_stats = defaultdict(lambda: {"events": 0, "alerts": 0, "last_seen": None, "ip": None})
stats_lock  = threading.Lock()
alert_buffer = []
buffer_lock  = threading.Lock()

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
    emoji     = SEV_EMOJI.get(severity, "⚪")
    color     = SEV_COLOR.get(severity, "RESET")

    with stats_lock:
        agent_stats[host]["events"]   += 1
        agent_stats[host]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        agent_stats[host]["ip"]        = agent_ip
        if severity in ("CRITICAL", "HIGH", "MEDIUM"):
            agent_stats[host]["alerts"] += 1

    with buffer_lock:
        alert_buffer.append(event)

    print(f"\n{col('─'*60, color)}")
    print(f"{col(f'{emoji} [{severity}] {rule_name}', 'BOLD')}")
    print(f"  {col('Host   :', 'CYAN')} {host}  {col(f'({agent_ip})', 'RESET')}")
    print(f"  {col('Canal  :', 'CYAN')} {channel}  |  EventID: {eid}")
    if cmd:
        display = cmd[:100] + "..." if len(cmd) > 100 else cmd
        print(f"  {col('Comando:', 'CYAN')} {display}")
    if ts:
        print(f"  {col('Hora   :', 'CYAN')} {ts}")
    print(col('─'*60, color))

    logging.info(f"ALERTA | {severity} | {rule_name} | {host} | {cmd[:80]}")


def process_heartbeat(data: dict, agent_ip: str):
    host = data.get("host", agent_ip)
    with stats_lock:
        agent_stats[host]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        agent_stats[host]["ip"]        = agent_ip
    logging.info(f"HEARTBEAT | {host} ({agent_ip})")
    print(f"  {col('💓 Heartbeat:', 'CYAN')} {host} ({agent_ip})")


# ============================================================
# HANDLER DE CLIENTE
# ============================================================

def handle_client(conn: socket.socket, addr: tuple):
    agent_ip = addr[0]
    logging.info(f"Agente ligado: {agent_ip}:{addr[1]}")
    print(f"\n{col('✅ Agente ligado:', 'GREEN')} {col(agent_ip, 'BOLD')}")

    buf = ""
    try:
        conn.settimeout(120)
        while True:
            try:
                data = conn.recv(4096).decode("utf-8", errors="ignore")
            except (socket.timeout, ConnectionResetError):
                break
            if not data:
                break
            buf += data
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if event.get("type") == "heartbeat":
                        process_heartbeat(event, agent_ip)
                    else:
                        process_event(event, agent_ip)
                except json.JSONDecodeError as e:
                    logging.warning(f"JSON inválido de {agent_ip}: {e}")
    except Exception as e:
        logging.error(f"Erro com agente {agent_ip}: {e}")
    finally:
        conn.close()
        logging.info(f"Agente desligado: {agent_ip}")
        print(f"\n{col('❌ Agente desligado:', 'RED')} {agent_ip}")


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
            print(f"\n{col('─'*60, 'CYAN')}")
            print(col('📊 AGENTES ACTIVOS', 'BOLD'))
            print(f"  {'HOST':<25} {'IP':<16} {'EVENTOS':<10} {'ALERTAS':<10} {'ÚLTIMO'}")
            print(f"  {'-'*25} {'-'*15} {'-'*9} {'-'*9} {'-'*8}")
            for host, s in sorted(agent_stats.items()):
                print(f"  {host:<25} {s['ip'] or 'N/A':<16} "
                      f"{s['events']:<10} {s['alerts']:<10} {s['last_seen'] or 'N/A'}")
            print(col('─'*60, 'CYAN'))


# ============================================================
# SERVIDOR PRINCIPAL
# ============================================================

def run_server(host: str, port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
    except OSError as e:
        logging.error(f"Erro ao ligar em {host}:{port} — {e}")
        print(f"\n{col(f'ERRO: Não foi possível abrir a porta {port}', 'RED')}")
        sys.exit(1)

    server.listen(50)

    print(col("═"*60, "CYAN"))
    print(col("   SentinelAI — Receiver TCP", "BOLD"))
    print(col("═"*60, "CYAN"))
    print(f"  {col('Endereço :', 'CYAN')} {host}:{port}")
    print(f"  {col('Protocolo:', 'CYAN')} TCP / JSON Lines")
    print(f"  {col('Log      :', 'CYAN')} {LOG_FILE}")
    print(col("═"*60, "CYAN"))
    print(f"\n  {col('À espera de agentes...', 'BOLD')} (Ctrl+C para parar)\n")

    logging.info(f"Receiver iniciado em {host}:{port}")
    threading.Thread(target=stats_loop, daemon=True).start()

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        print(f"\n{col('Receiver parado.', 'BOLD')}")


def main():
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
    run_server(host, port)


if __name__ == "__main__":
    main()