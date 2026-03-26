# SentinelAI - Agente EDR
# Monitoriza eventos Windows em tempo real e encaminha alertas.
#
# Compilacao:
#   pyinstaller --onefile --noconsole --icon=logo.ico agent.py

import os
import sys
import json
import time
import argparse
import socket
import threading
import subprocess
import xml.etree.ElementTree as ET
import urllib.request
import logging
from datetime import datetime

from app_config import get_config_path, load_app_config
from event_utils import attach_auth_token
from runtime_paths import get_app_root

# ============================================================
# VERSAO E CONSTANTES
# ============================================================

VERSION        = "v2.0.0"
CHECK_INTERVAL = 3
BATCH_SIZE     = 100
COOLDOWN       = 60
HEARTBEAT_INT  = 30
RECONNECT_WAIT = 10

CHANNELS = [
    "Security",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
]

MONITORED_IDS = [
    "1", "3",
    "4624", "4625", "4648", "4672", "4688",
    "4697", "4698", "4720", "4726", "4732",
    "4103", "4104",
    "7045",
]

RULES = [
    ("PowerShell Suspeito", "CRITICAL", lambda e:
        "powershell" in e.get("CommandLine", "").lower() and
        any(x in e.get("CommandLine", "").lower() for x in
            ["-enc", "-nop", "bypass", "hidden", "iex", "downloadstring"])),

    ("LOLBin Detetado", "HIGH", lambda e: any(
        x in e.get("CommandLine", "").lower()
        for x in ["certutil", "mshta", "rundll32 javascript", "regsvr32", "bitsadmin"])),

    ("Conta de Utilizador Criada", "CRITICAL", lambda e:
        "net user" in e.get("CommandLine", "").lower() and
        "/add" in e.get("CommandLine", "").lower()),

    ("Adicionado a Administradores", "CRITICAL", lambda e:
        "net localgroup" in e.get("CommandLine", "").lower() and
        "administrator" in e.get("CommandLine", "").lower()),

    ("Dump de Credenciais", "CRITICAL", lambda e: any(
        x in e.get("CommandLine", "").lower()
        for x in ["mimikatz", "procdump", "lsass", "sekurlsa", "comsvcs.dll"])),

    ("Tarefa Agendada Criada", "HIGH", lambda e:
        "schtasks" in e.get("CommandLine", "").lower() and
        "/create" in e.get("CommandLine", "").lower()),

    ("Persistencia no Registry", "HIGH", lambda e:
        "currentversion\\run" in e.get("CommandLine", "").lower() or
        "currentversion\\run" in e.get("TargetObject", "").lower()),

    ("Movimento Lateral", "CRITICAL", lambda e: any(
        x in e.get("CommandLine", "").lower()
        for x in ["psexec", "wmic /node"])),

    ("Download Remoto", "HIGH", lambda e:
        any(x in e.get("CommandLine", "").lower()
            for x in ["http://", "https://", "downloadstring", "downloadfile"]) and
        any(x in e.get("CommandLine", "").lower()
            for x in ["powershell", "certutil", "bitsadmin", "msiexec"])),

    ("Novo Servico Instalado", "HIGH", lambda e:
        e.get("EventID") in ("4697", "7045")),

    ("Conta Criada (EventID)", "HIGH", lambda e:
        e.get("EventID") == "4720"),

    ("Login Falhado", "MEDIUM", lambda e:
        e.get("EventID") == "4625"),

    ("PowerShell Script Block", "HIGH", lambda e:
        e.get("EventID") == "4104" and len(e.get("Message", "")) > 100),
]

COLORS = {
    "CRITICAL": 0xe74c3c,
    "HIGH":     0xe67e22,
    "MEDIUM":   0xf1c40f,
    "LOW":      0x2ecc71,
}

# ============================================================
# PATHS
# ============================================================

_BASE        = str(get_app_root(__file__))
_CONFIG_FILE = str(get_config_path(__file__))
_STATE_FILE  = os.path.join(_BASE, "agent_state.json")
_LOG_FILE    = os.path.join(_BASE, "logs", "agent.log")

# ============================================================
# CONFIG
# ============================================================

def load_config() -> dict:
    config_exists = os.path.exists(_CONFIG_FILE)
    cfg = load_app_config(__file__, create_if_missing=True)
    if not config_exists:
        logging.warning(
            f"Configuracao criada em {_CONFIG_FILE}. "
            "Preencher discord_webhook e/ou receiver_server antes da execucao."
        )
    return cfg


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SentinelAI agent")
    parser.add_argument("--receiver-server", dest="receiver_server", default=None)
    parser.add_argument("--receiver-port", dest="receiver_port", type=int, default=None)
    parser.add_argument("--receiver-token", dest="receiver_auth_token", default=None)
    parser.add_argument("--discord-webhook", dest="discord_webhook", default=None)
    parser.add_argument("--self-test", action="store_true", help="Envia um evento sintetico para validar a ligacao.")
    return parser


def apply_cli_overrides(cfg: dict, args) -> dict:
    updated = dict(cfg)
    for key in ("receiver_server", "receiver_port", "receiver_auth_token", "discord_webhook"):
        value = getattr(args, key, None)
        if value is not None:
            updated[key] = value
    return updated

# ============================================================
# ESTADO E COOLDOWNS
# ============================================================

_cooldowns = {}

def load_state() -> dict:
    try:
        with open(_STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state: dict):
    try:
        with open(_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass

def in_cooldown(key: str) -> bool:
    return (time.time() - _cooldowns.get(key, 0)) < COOLDOWN

def set_cooldown(key: str):
    _cooldowns[key] = time.time()

# ============================================================
# DISCORD
# ============================================================

def send_discord(webhook_url: str, rule_name: str, severity: str, event: dict):
    hostname = event.get("Computer", socket.gethostname())
    eid      = event.get("EventID", "?")
    cmd      = event.get("CommandLine", "")
    msg      = event.get("Message", "")[:300]
    channel  = event.get("Channel", "")
    ts       = event.get("TimeCreated", "")[:19]

    description = f"**Host:** `{hostname}`\n**Canal:** `{channel}`\n**Event ID:** `{eid}`\n"
    if cmd:
        description += f"**Comando:**\n```{cmd[:300]}```\n"
    elif msg:
        description += f"**Detalhes:**\n```{msg[:300]}```\n"
    description += f"**Hora:** `{ts}`"

    payload = json.dumps({
        "embeds": [{
            "title":       f"[{severity}] {rule_name}",
            "description": description,
            "color":       COLORS.get(severity, 0x95a5a6),
            "footer":      {"text": f"SentinelAI Agent {VERSION} | {hostname}"},
            "timestamp":   datetime.utcnow().isoformat() + "Z",
        }]
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
        logging.info(f"Discord enviado: {severity} - {rule_name} | {hostname}")
    except Exception as e:
        logging.error(f"Erro Discord: {e}")

# ============================================================
# TCP SENDER
# ============================================================

class TCPSender:
    """
    Mantem uma ligacao TCP persistente ao receiver.
    Reconecta automaticamente quando necessario.
    """
    def __init__(self, server: str, port: int, auth_token: str = ""):
        self.server  = server
        self.port    = port
        self.auth_token = auth_token
        self.sock    = None
        self.lock    = threading.Lock()
        self.running = True
        self._connect()

        # A thread de heartbeat mantem o receiver informado sobre o estado do agente.
        t = threading.Thread(target=self._heartbeat_loop, daemon=True)
        t.start()

    def _connect(self):
        self._close_socket()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.server, self.port))
            sock.settimeout(None)
            self.sock = sock
            logging.info(f"Ligado ao receiver {self.server}:{self.port}")
            return True
        except Exception as e:
            logging.warning(f"Sem ligação ao receiver ({e}).")
            self._close_socket()
            return False

    def _close_socket(self):
        if self.sock is None:
            return
        try:
            self.sock.close()
        except Exception:
            pass
        finally:
            self.sock = None

    def send(self, data: dict):
        payload = attach_auth_token(data, self.auth_token)
        line = json.dumps(payload, ensure_ascii=False) + "\n"
        with self.lock:
            for attempt in range(3):
                if self.sock is None and not self._connect():
                    if attempt < 2:
                        time.sleep(RECONNECT_WAIT)
                    continue
                try:
                    self.sock.sendall(line.encode("utf-8"))
                    return True
                except Exception as e:
                    logging.warning(f"Erro a enviar (tentativa {attempt+1}): {e}")
                    self._close_socket()
                    if attempt < 2:
                        time.sleep(RECONNECT_WAIT)
        return False

    def _heartbeat_loop(self):
        while self.running:
            time.sleep(HEARTBEAT_INT)
            self.send({
                "type":    "heartbeat",
                "host":    socket.gethostname(),
                "version": VERSION,
                "ts":      datetime.utcnow().isoformat() + "Z",
            })

    def stop(self):
        self.running = False
        self._close_socket()

# ============================================================
# LEITOR DE EVENTOS
# ============================================================

def read_events(channel: str, last_id: int) -> list:
    events = []
    try:
        ids_filter = " or ".join([f"EventID={i}" for i in MONITORED_IDS])
        query      = f"*[System[({ids_filter}) and EventRecordID > {last_id}]]"
        cmd        = ["wevtutil", "qe", channel,
                      f"/q:{query}", f"/c:{BATCH_SIZE}", "/f:XML", "/rd:false"]

        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=10, creationflags=0x08000000)
        if result.returncode != 0 or not result.stdout.strip():
            return []

        try:
            root = ET.fromstring(f"<root>{result.stdout}</root>")
        except ET.ParseError:
            return []

        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        for ev_el in root.findall("e:Event", ns):
            sys_el  = ev_el.find("e:System", ns)
            if sys_el is None:
                continue
            eid_el  = sys_el.find("e:EventID", ns)
            rid_el  = sys_el.find("e:EventRecordID", ns)
            ts_el   = sys_el.find("e:TimeCreated", ns)
            comp_el = sys_el.find("e:Computer", ns)

            eid  = str(int(eid_el.text)) if eid_el  is not None else "0"
            rid  = int(rid_el.text)      if rid_el  is not None else 0
            ts   = ts_el.attrib.get("SystemTime", "") if ts_el is not None else ""
            comp = comp_el.text          if comp_el is not None else socket.gethostname()

            ev = {
                "type":        "event",
                "RecordId":    rid,
                "EventID":     eid,
                "Channel":     channel,
                "Computer":    comp,
                "TimeCreated": ts,
                "CommandLine": "",
                "TargetObject": "",
                "Message":     "",
            }

            ev_data = ev_el.find("e:EventData", ns)
            if ev_data is not None:
                parts = []
                for data in ev_data.findall("e:Data", ns):
                    name = data.attrib.get("Name", "")
                    val  = data.text or ""
                    if name == "CommandLine":     ev["CommandLine"]  = val
                    if name == "TargetObject":    ev["TargetObject"] = val
                    if name == "SubjectUserName": ev["User"]         = val
                    parts.append(f"{name}: {val}" if name else val)
                ev["Message"] = "\n".join(parts)[:500]

            events.append(ev)

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        logging.error(f"Erro canal {channel}: {e}")

    return events


def build_self_test_event(hostname: str) -> dict:
    return {
        "type": "event",
        "RecordId": 0,
        "EventID": "4688",
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "Computer": hostname,
        "TimeCreated": datetime.utcnow().isoformat() + "Z",
        "CommandLine": "powershell.exe -nop -w hidden -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQA=",
        "TargetObject": "",
        "Message": "SentinelAI self-test event",
        "rule_name": "PowerShell Suspeito",
        "severity": "CRITICAL",
    }


def run_self_test(cfg: dict) -> int:
    webhook = cfg.get("discord_webhook", "").strip()
    server = cfg.get("receiver_server", "").strip()
    port = int(cfg.get("receiver_port", 9000))
    auth_token = cfg.get("receiver_auth_token", "").strip()
    hostname = socket.gethostname()
    event = build_self_test_event(hostname)
    delivered = False

    logging.info("A executar self-test do agente.")

    if webhook:
        send_discord(webhook, event["rule_name"], event["severity"], event)
        delivered = True

    if server:
        tcp = TCPSender(server, port, auth_token)
        try:
            delivered = tcp.send(event) or delivered
        finally:
            tcp.stop()

    if delivered:
        logging.info("Self-test enviado.")
        return 0

    logging.error("Self-test falhou: nenhum destino configurado ou indisponivel.")
    return 1

# ============================================================
# LOOP PRINCIPAL
# ============================================================

def run_agent(cfg: dict):
    webhook = cfg.get("discord_webhook", "").strip()
    server  = cfg.get("receiver_server", "").strip()
    port    = int(cfg.get("receiver_port", 9000))
    auth_token = cfg.get("receiver_auth_token", "").strip()

    hostname = socket.gethostname()
    logging.info(f"SentinelAI Agent {VERSION} | Host: {hostname}")

    # O resumo de destinos regista como os alertas serao encaminhados.
    modes = []
    if webhook:
        modes.append("Discord")
    if server:
        modes.append(f"TCP {server}:{port}")
    if not modes:
        logging.warning("Nenhum destino configurado. Os alertas nao serao enviados.")
        modes.append("sem destinos configurados")
    logging.info(f"Destinos: {' | '.join(modes)}")

    # O emissor TCP e criado apenas quando existe um destino remoto configurado.
    tcp = None
    if server:
        logging.info(f"A ligar ao receiver {server}:{port}...")
        if not auth_token:
            logging.warning("Receiver configurado sem token de autenticacao.")
        tcp = TCPSender(server, port, auth_token)

    state = load_state()

    # O estado arranca no ultimo EventRecordID observado para evitar reenvio historico.
    for ch in CHANNELS:
        if ch not in state:
            state[ch] = 0
            try:
                r = subprocess.run(
                    ["wevtutil", "qe", ch, "/c:1", "/rd:true", "/f:XML"],
                    capture_output=True, text=True, timeout=5, creationflags=0x08000000
                )
                if r.returncode == 0 and r.stdout.strip():
                    root = ET.fromstring(f"<root>{r.stdout}</root>")
                    ns   = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    for ev in root.findall("e:Event", ns):
                        sys_el = ev.find("e:System", ns)
                        rid_el = sys_el.find("e:EventRecordID", ns) if sys_el else None
                        if rid_el is not None:
                            state[ch] = int(rid_el.text)
            except Exception:
                pass

    save_state(state)
    logging.info("Monitorizacao em tempo real iniciada.")

    while True:
        for channel in CHANNELS:
            last_id = state.get(channel, 0)
            events  = read_events(channel, last_id)

            for ev in events:
                rid = ev.get("RecordId", 0)
                if rid > state.get(channel, 0):
                    state[channel] = rid

                for rule_name, severity, check_fn in RULES:
                    try:
                        if not check_fn(ev):
                            continue
                    except Exception:
                        continue

                    key = f"{ev.get('Computer', '')}_{rule_name}"
                    if in_cooldown(key):
                        continue
                    set_cooldown(key)

                    # O evento recebe metadados de alerta antes do encaminhamento.
                    ev["rule_name"] = rule_name
                    ev["severity"]  = severity

                    # O webhook e utilizado quando configurado.
                    if webhook:
                        send_discord(webhook, rule_name, severity, ev)

                    # O receiver TCP recebe o mesmo evento quando ativo.
                    if tcp:
                        tcp.send(ev)

                    break  # O evento e limitado a uma regra por ciclo.

        save_state(state)
        time.sleep(CHECK_INTERVAL)

# ============================================================
# ENTRY POINT
# ============================================================

def main():
    args = build_argument_parser().parse_args()
    os.makedirs(os.path.dirname(_LOG_FILE), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(_LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ]
    )

    cfg = apply_cli_overrides(load_config(), args)

    try:
        if args.self_test:
            sys.exit(run_self_test(cfg))
        run_agent(cfg)
    except KeyboardInterrupt:
        logging.info("Agente parado.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Erro fatal: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
