# agent.py
# SentinelAI - Agente EDR v2.0
# Monitoriza eventos Windows em tempo real
# Envia alertas para Discord E/OU para o Receiver TCP
#
# Compilar:
#   pyinstaller --onefile --noconsole --icon=logo.ico agent.py

import os
import sys
import json
import time
import socket
import threading
import subprocess
import xml.etree.ElementTree as ET
import urllib.request
import logging
from datetime import datetime

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

SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

# ============================================================
# PATHS  ← CORRIGIDO: nome do ficheiro com underscore
# ============================================================

_BASE        = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
_CONFIG_FILE = os.path.join(_BASE, "sentinelai_config.json")   # <-- corrigido
_STATE_FILE  = os.path.join(_BASE, "agent_state.json")
_LOG_FILE    = os.path.join(_BASE, "agent.log")

# ============================================================
# CONFIG
# ============================================================

DEFAULT_CONFIG = {
    "discord_webhook": "",
    "receiver_server": "",
    "receiver_port":   9000,
}

def load_config() -> dict:
    if not os.path.exists(_CONFIG_FILE):
        with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        logging.warning(f"Config criado em {_CONFIG_FILE} — preenche o discord_webhook e/ou receiver_server!")
        return DEFAULT_CONFIG.copy()
    try:
        with open(_CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception as e:
        logging.error(f"Erro a ler config: {e}")
        return DEFAULT_CONFIG.copy()

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
    emoji    = SEV_EMOJI.get(severity, "⚪")

    description = f"**Host:** `{hostname}`\n**Canal:** `{channel}`\n**Event ID:** `{eid}`\n"
    if cmd:
        description += f"**Comando:**\n```{cmd[:300]}```\n"
    elif msg:
        description += f"**Detalhes:**\n```{msg[:300]}```\n"
    description += f"**Hora:** `{ts}`"

    payload = json.dumps({
        "embeds": [{
            "title":       f"{emoji} [{severity}] {rule_name}",
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
        logging.info(f"Discord OK: {emoji} {severity} - {rule_name} | {hostname}")
    except Exception as e:
        logging.error(f"Erro Discord: {e}")

# ============================================================
# TCP SENDER
# ============================================================

class TCPSender:
    """
    Mantém uma ligação TCP persistente ao receiver.
    Reconecta automaticamente se cair.
    """
    def __init__(self, server: str, port: int):
        self.server  = server
        self.port    = port
        self.sock    = None
        self.lock    = threading.Lock()
        self.running = True
        self._connect()

        # Thread de heartbeat
        t = threading.Thread(target=self._heartbeat_loop, daemon=True)
        t.start()

    def _connect(self):
        while self.running:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((self.server, self.port))
                self.sock.settimeout(None)
                logging.info(f"Ligado ao receiver {self.server}:{self.port}")
                return
            except Exception as e:
                logging.warning(f"Sem ligação ao receiver ({e}). A tentar em {RECONNECT_WAIT}s...")
                time.sleep(RECONNECT_WAIT)

    def send(self, data: dict):
        line = json.dumps(data, ensure_ascii=False) + "\n"
        with self.lock:
            for attempt in range(3):
                try:
                    self.sock.sendall(line.encode("utf-8"))
                    return True
                except Exception as e:
                    logging.warning(f"Erro a enviar (tentativa {attempt+1}): {e}")
                    self._connect()
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
        try:
            self.sock.close()
        except Exception:
            pass

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

# ============================================================
# LOOP PRINCIPAL
# ============================================================

def run_agent(cfg: dict):
    webhook = cfg.get("discord_webhook", "").strip()
    server  = cfg.get("receiver_server", "").strip()
    port    = int(cfg.get("receiver_port", 9000))

    hostname = socket.gethostname()
    logging.info(f"SentinelAI Agent {VERSION} | Host: {hostname}")

    # Mostrar modo de operação
    modes = []
    if webhook:
        modes.append("Discord ✅")
    if server:
        modes.append(f"TCP → {server}:{port} ✅")
    if not modes:
        logging.warning("AVISO: Nem Discord nem TCP configurado! Os alertas não serão enviados.")
        modes.append("Nenhum destino configurado ⚠️")
    logging.info(f"Destinos: {' | '.join(modes)}")

    # Iniciar TCP sender se configurado
    tcp = None
    if server:
        logging.info(f"A ligar ao receiver {server}:{port}...")
        tcp = TCPSender(server, port)

    state = load_state()

    # Inicializar estado com último ID atual (não reenviar histórico)
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
    logging.info("Pronto! A monitorizar em tempo real...")

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

                    # Adicionar metadados ao evento antes de enviar
                    ev["rule_name"] = rule_name
                    ev["severity"]  = severity

                    # Enviar para Discord
                    if webhook:
                        send_discord(webhook, rule_name, severity, ev)

                    # Enviar para TCP receiver
                    if tcp:
                        tcp.send(ev)

                    break  # uma regra por evento

        save_state(state)
        time.sleep(CHECK_INTERVAL)

# ============================================================
# ENTRY POINT
# ============================================================

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(_LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ]
    )

    cfg = load_config()

    try:
        run_agent(cfg)
    except KeyboardInterrupt:
        logging.info("Agente parado.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Erro fatal: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()