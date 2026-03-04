# parser.py - UTIL
# SentinelAI - Suporte a Windows (EVTX) e Linux (auditd, syslog)
import os
import re
import json
import xml.etree.ElementTree as ET

try:
    import Evtx.Evtx as evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False
    print("[AVISO] python-evtx não instalado. Suporte a .evtx desativado.")

XML_NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# EventIDs relevantes
WINDOWS_EVENT_IDS = {
    '1':  'Process Creation (Sysmon)',
    '3':  'Network Connection (Sysmon)',
    '11': 'File Created (Sysmon)',
    '12': 'Registry Object Created (Sysmon)',
    '13': 'Registry Value Set (Sysmon)',
    '4624': 'Logon Success (Security)',
    '4625': 'Logon Failure (Security)',
    '4688': 'Process Creation (Security)',
    '4698': 'Scheduled Task Created (Security)',
    '4720': 'User Account Created (Security)',
}

# ============================================================
# WINDOWS — EVTX
# ============================================================

def parse_evtx(filepath: str) -> list:
    """Lê ficheiro .evtx e devolve lista de eventos normalizados."""
    if not EVTX_AVAILABLE:
        print(f"[ERRO] python-evtx não disponível para ler: {filepath}")
        return []

    all_events = []
    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    xml_content = record.xml()
                    root = ET.fromstring(xml_content)
                    system = root.find(f"{XML_NAMESPACE}System")
                    event_id = system.find(f"{XML_NAMESPACE}EventID").text

                    if event_id not in WINDOWS_EVENT_IDS:
                        continue

                    event = {
                        "source":      "windows",
                        "format":      "evtx",
                        "EventID":     event_id,
                        "EventType":   WINDOWS_EVENT_IDS.get(event_id, "Unknown"),
                        "Computer":    system.find(f"{XML_NAMESPACE}Computer").text,
                        "TimeCreated": system.find(f"{XML_NAMESPACE}TimeCreated").get("SystemTime"),
                    }

                    event_data = root.find(f"{XML_NAMESPACE}EventData")
                    if event_data is not None:
                        for data in event_data.findall(f"{XML_NAMESPACE}Data"):
                            name = data.get("Name")
                            if name:
                                event[name] = data.text

                    all_events.append(event)

                except (ET.ParseError, AttributeError):
                    continue

    except FileNotFoundError:
        print(f"[ERRO] Ficheiro não encontrado: {filepath}")

    return all_events

# ============================================================
# LINUX — AUDITD
# ============================================================

# Exemplos de linhas auditd:
# type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 ...
# type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="ls" a1="-la" ...
# type=PATH msg=audit(1234567890.123:456): item=0 name="/bin/bash" ...

AUDITD_SUSPICIOUS_SYSCALLS = {'59', '322', '2'}  # execve, execveat, open

def parse_auditd_line(line: str) -> dict | None:
    """Parseia uma linha de log auditd."""
    try:
        # Extrair tipo
        type_match = re.match(r'type=(\w+)', line)
        if not type_match:
            return None
        event_type = type_match.group(1)

        # Só nos interessam SYSCALL e EXECVE
        if event_type not in ('SYSCALL', 'EXECVE', 'PATH'):
            return None

        # Extrair timestamp
        ts_match = re.search(r'audit\((\d+\.\d+):(\d+)\)', line)
        timestamp = ts_match.group(1) if ts_match else None

        # Extrair pares chave=valor
        fields = {}
        for match in re.finditer(r'(\w+)=(".*?"|[\S]+)', line):
            key, val = match.group(1), match.group(2).strip('"')
            fields[key] = val

        event = {
            "source":      "linux",
            "format":      "auditd",
            "EventID":     event_type,
            "EventType":   f"Auditd {event_type}",
            "TimeCreated": timestamp,
            "Computer":    fields.get("hostname", fields.get("node", "linux-host")),
        }

        # Campos relevantes para deteção
        if "exe" in fields:
            event["Image"] = fields["exe"]
        if "comm" in fields:
            event["ProcessName"] = fields["comm"]
        if "syscall" in fields:
            event["Syscall"] = fields["syscall"]

        # Construir CommandLine a partir de EXECVE
        if event_type == "EXECVE":
            argc = int(fields.get("argc", 0))
            args = [fields.get(f"a{i}", "") for i in range(argc)]
            event["CommandLine"] = " ".join(args)

        return event

    except Exception:
        return None

def parse_auditd(filepath: str) -> list:
    """Lê ficheiro de logs auditd."""
    all_events = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = parse_auditd_line(line)
                if event:
                    all_events.append(event)
    except FileNotFoundError:
        print(f"[ERRO] Ficheiro não encontrado: {filepath}")

    return all_events

# ============================================================
# LINUX — SYSLOG
# ============================================================

# Exemplos:
# Mar  4 10:23:01 hostname sshd[1234]: Failed password for root from 192.168.1.1
# Mar  4 10:23:05 hostname sudo: user : command not allowed

SYSLOG_PATTERNS = [
    {
        "name": "SSH Failed Login",
        "pattern": re.compile(r'Failed password for (\S+) from ([\d.]+)'),
        "EventID": "SSH_FAIL",
        "extractor": lambda m: {"User": m.group(1), "SourceIP": m.group(2)}
    },
    {
        "name": "SSH Accepted Login",
        "pattern": re.compile(r'Accepted \w+ for (\S+) from ([\d.]+)'),
        "EventID": "SSH_OK",
        "extractor": lambda m: {"User": m.group(1), "SourceIP": m.group(2)}
    },
    {
        "name": "Sudo Command",
        "pattern": re.compile(r'sudo:\s+(\S+)\s+:.*?COMMAND=(.+)'),
        "EventID": "SUDO_CMD",
        "extractor": lambda m: {"User": m.group(1), "CommandLine": m.group(2).strip()}
    },
    {
        "name": "Sudo Failure",
        "pattern": re.compile(r'sudo:\s+(\S+)\s+:.*?command not allowed'),
        "EventID": "SUDO_FAIL",
        "extractor": lambda m: {"User": m.group(1)}
    },
    {
        "name": "Cron Job",
        "pattern": re.compile(r'CRON\[\d+\].*CMD \((.+)\)'),
        "EventID": "CRON",
        "extractor": lambda m: {"CommandLine": m.group(1)}
    },
]

# Mar  4 10:23:01 hostname process[pid]: message
SYSLOG_HEADER = re.compile(
    r'^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)'
)

def parse_syslog_line(line: str) -> dict | None:
    """Parseia uma linha de syslog."""
    header = SYSLOG_HEADER.match(line)
    if not header:
        return None

    timestamp, host, process, pid, message = header.groups()

    for rule in SYSLOG_PATTERNS:
        match = rule["pattern"].search(message)
        if match:
            event = {
                "source":      "linux",
                "format":      "syslog",
                "EventID":     rule["EventID"],
                "EventType":   rule["name"],
                "TimeCreated": timestamp,
                "Computer":    host,
                "Process":     process,
                "PID":         pid,
                "RawMessage":  message,
            }
            event.update(rule["extractor"](match))
            return event

    return None

def parse_syslog(filepath: str) -> list:
    """Lê ficheiro syslog."""
    all_events = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = parse_syslog_line(line)
                if event:
                    all_events.append(event)
    except FileNotFoundError:
        print(f"[ERRO] Ficheiro não encontrado: {filepath}")

    return all_events

# ============================================================
# INTERFACE PRINCIPAL — deteção automática de formato
# ============================================================

# ============================================================
# JSON LINES (.jsonl) — logs sintéticos gerados pelo log_generator
# ============================================================

def parse_jsonl(filepath: str) -> list:
    """Lê ficheiro .jsonl (um JSON por linha)."""
    all_events = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    all_events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[ERRO] Ficheiro não encontrado: {filepath}")
    return all_events

def get_events(filepath: str) -> list:
    """
    Deteção automática de formato pelo tipo de ficheiro.
    Suporta: .evtx (Windows), .jsonl (sintético), .log/.audit (auditd), syslog
    """
    if not os.path.exists(filepath):
        print(f"[ERRO] Ficheiro não encontrado: {filepath}")
        return []

    ext      = os.path.splitext(filepath)[1].lower()
    filename = os.path.basename(filepath).lower()

    if ext == ".evtx":
        print(f"  [Parser] Windows EVTX → {filepath}")
        return parse_evtx(filepath)

    elif ext == ".jsonl":
        print(f"  [Parser] JSON Lines → {filepath}")
        return parse_jsonl(filepath)

    elif ext in (".audit",) or "audit" in filename:
        print(f"  [Parser] Linux auditd → {filepath}")
        return parse_auditd(filepath)

    elif ext in (".log", ".txt") or any(x in filename for x in ["syslog", "auth", "secure", "messages"]):
        print(f"  [Parser] Linux syslog → {filepath}")
        return parse_syslog(filepath)

    else:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()
            if first_line.startswith("{"):
                print(f"  [Parser] JSON Lines (detetado) → {filepath}")
                return parse_jsonl(filepath)
            elif "type=SYSCALL" in first_line or "type=EXECVE" in first_line:
                print(f"  [Parser] Linux auditd (detetado) → {filepath}")
                return parse_auditd(filepath)
            else:
                print(f"  [Parser] Linux syslog (fallback) → {filepath}")
                return parse_syslog(filepath)
        except Exception:
            print(f"[ERRO] Não foi possível detetar o formato de: {filepath}")
            return []

def get_events_from_folder(folder: str) -> list:
    """
    Lê todos os ficheiros de logs de uma pasta recursivamente.
    """
    all_events = []
    supported = (".evtx", ".log", ".audit", ".txt", ".jsonl")

    if not os.path.exists(folder):
        print(f"  [ERRO] Pasta não encontrada: {folder}")
        return []

    for root, dirs, files in os.walk(folder):
        for filename in files:
            if any(filename.lower().endswith(ext) for ext in supported):
                filepath = os.path.join(root, filename)
                print(f"  [Parser] A ler: {filepath}")
                events = get_events(filepath)
                print(f"  [Parser] → {len(events)} eventos")
                for e in events:
                    e["_source_file"] = filepath
                    e["_category"] = _infer_category(filepath)
                all_events.extend(events)

    print(f"\n  [Parser] Total de eventos lidos: {len(all_events)}")
    return all_events

def _infer_category(filepath: str) -> str:
    """Infere a categoria do ataque pelo caminho do ficheiro."""
    path_lower = filepath.lower()
    if "persistence"      in path_lower: return "persistence"
    if "execution"        in path_lower: return "execution"
    if "lateral"          in path_lower: return "lateral_movement"
    if "credential"       in path_lower: return "credential_access"
    if "normal"           in path_lower: return "normal"
    return "unknown"