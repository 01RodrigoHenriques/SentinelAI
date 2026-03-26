# SentinelAI - Parser de logs Windows
import os
import json
import xml.etree.ElementTree as ET

from event_utils import normalize_event

try:
    import Evtx.Evtx as evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False
    print("[AVISO] python-evtx nao instalado. Suporte a .evtx desativado.")

XML_NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"

WINDOWS_EVENT_IDS = {
    "1": "Process Creation (Sysmon)",
    "3": "Network Connection (Sysmon)",
    "11": "File Created (Sysmon)",
    "12": "Registry Object Created (Sysmon)",
    "13": "Registry Value Set (Sysmon)",
    "4624": "Logon Success (Security)",
    "4625": "Logon Failure (Security)",
    "4688": "Process Creation (Security)",
    "4697": "Service Installed (Security)",
    "4698": "Scheduled Task Created (Security)",
    "4720": "User Account Created (Security)",
    "4726": "User Account Deleted (Security)",
    "7045": "Service Installed (System)",
    "4103": "PowerShell Module Logging",
    "4104": "PowerShell Script Block Logging",
}


def parse_evtx(filepath: str) -> list:
    """Le ficheiro .evtx e devolve eventos Windows normalizados."""
    if not EVTX_AVAILABLE:
        print(f"[ERRO] python-evtx nao disponivel para ler: {filepath}")
        return []

    all_events = []
    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                    system = root.find(f"{XML_NAMESPACE}System")
                    if system is None:
                        continue

                    event_id_node = system.find(f"{XML_NAMESPACE}EventID")
                    if event_id_node is None or event_id_node.text is None:
                        continue

                    event_id = str(int(event_id_node.text))
                    if event_id not in WINDOWS_EVENT_IDS:
                        continue

                    computer = system.find(f"{XML_NAMESPACE}Computer")
                    time_created = system.find(f"{XML_NAMESPACE}TimeCreated")

                    event = {
                        "source": "windows",
                        "format": "evtx",
                        "EventID": event_id,
                        "EventType": WINDOWS_EVENT_IDS.get(event_id, "Unknown"),
                        "Computer": computer.text if computer is not None else "unknown",
                        "TimeCreated": time_created.get("SystemTime", "") if time_created is not None else "",
                    }

                    event_data = root.find(f"{XML_NAMESPACE}EventData")
                    if event_data is not None:
                        for data in event_data.findall(f"{XML_NAMESPACE}Data"):
                            name = data.get("Name")
                            if name:
                                event[name] = data.text

                    user_data = root.find(f"{XML_NAMESPACE}UserData")
                    if user_data is not None:
                        event["UserData"] = ET.tostring(user_data, encoding="unicode")

                    all_events.append(normalize_event(event))
                except (ET.ParseError, AttributeError, ValueError):
                    continue
    except FileNotFoundError:
        print(f"[ERRO] Ficheiro nao encontrado: {filepath}")

    return all_events


def parse_jsonl(filepath: str) -> list:
    """Le ficheiro .jsonl com eventos Windows sinteticos ou recebidos por rede."""
    all_events = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = normalize_event(json.loads(line))
                except json.JSONDecodeError:
                    continue

                event["source"] = "windows"
                all_events.append(event)
    except FileNotFoundError:
        print(f"[ERRO] Ficheiro nao encontrado: {filepath}")
    return all_events


def get_events(filepath: str) -> list:
    """Deteta e processa formatos suportados para eventos Windows."""
    if not os.path.exists(filepath):
        print(f"[ERRO] Ficheiro nao encontrado: {filepath}")
        return []

    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".evtx":
        print(f"  [Parser] Windows EVTX -> {filepath}")
        return parse_evtx(filepath)

    if ext == ".jsonl":
        print(f"  [Parser] JSON Lines -> {filepath}")
        return parse_jsonl(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            first_line = f.readline().lstrip()
        if first_line.startswith("{"):
            print(f"  [Parser] JSON Lines (detetado) -> {filepath}")
            return parse_jsonl(filepath)
    except Exception:
        pass

    print(f"  [Parser] Formato nao suportado (Windows-only) -> {filepath}")
    return []


def get_events_from_folder(folder: str) -> list:
    """Le todos os ficheiros de logs Windows numa pasta recursivamente."""
    all_events = []
    supported = (".evtx", ".jsonl")

    if not os.path.exists(folder):
        print(f"  [ERRO] Pasta nao encontrada: {folder}")
        return []

    for root, dirs, files in os.walk(folder):
        dirs.sort()
        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            if not filename.lower().endswith(supported):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        first_line = f.readline().lstrip()
                    if not first_line.startswith("{"):
                        continue
                except Exception:
                    continue

            print(f"  [Parser] A ler: {filepath}")
            events = get_events(filepath)
            print(f"  [Parser] -> {len(events)} eventos")
            for event in events:
                event["_source_file"] = filepath
                event["_category"] = _infer_category(filepath)
            all_events.extend(events)

    print(f"\n  [Parser] Total de eventos lidos: {len(all_events)}")
    return all_events


def _infer_category(filepath: str) -> str:
    """Infere a categoria de ataque pelo caminho do ficheiro."""
    path_lower = filepath.lower()
    if "persistence" in path_lower:
        return "persistence"
    if "execution" in path_lower:
        return "execution"
    if "lateral" in path_lower:
        return "lateral_movement"
    if "credential" in path_lower:
        return "credential_access"
    if "normal" in path_lower:
        return "normal"
    return "unknown"
