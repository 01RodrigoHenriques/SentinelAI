# correlator.py
# SentinelAI - Motor de Correlacao de Eventos
# Deteta cadeias de ataque multi-evento no mesmo host dentro de uma janela temporal

from datetime import datetime
from collections import defaultdict

# ============================================================
# CONFIGURACAO
# ============================================================

# Janela de tempo para correlacionar eventos do mesmo host
CORRELATION_WINDOW_MINUTES = 60

# Cadeias de ataque conhecidas (ordered sequences)
# Cada cadeia define uma sequencia de regras que juntas indicam um ataque mais grave
ATTACK_CHAINS = [
    {
        "id": "C001",
        "name": "Comprometimento Total de Host Windows",
        "description": "Execucao suspeita seguida de dump de credenciais e persistencia",
        "rules": ["R004", "R006", "R001"],  # PowerShell -> Credential Dump -> Persistence
        "severity": "CRITICAL",
        "risk_boost": 95,
        "mitre_tactic": "Execution -> Credential Access -> Persistence",
    },
    {
        "id": "C002",
        "name": "Movimento Lateral Apos Roubo de Credenciais",
        "description": "Dump de credenciais seguido de movimento lateral",
        "rules": ["R006", "R007"],  # Credential Dump -> Lateral Movement
        "severity": "CRITICAL",
        "risk_boost": 90,
        "mitre_tactic": "Credential Access -> Lateral Movement",
    },
    {
        "id": "C003",
        "name": "Persistencia Apos Execucao Suspeita",
        "description": "LOLBin ou PowerShell suspeito seguido de persistencia",
        "rules": ["R003", "R001"],  # LOLBin -> Registry Persistence
        "severity": "HIGH",
        "risk_boost": 80,
        "mitre_tactic": "Execution -> Persistence",
    },
    {
        "id": "C004",
        "name": "Persistencia Apos Execucao Suspeita (PS)",
        "description": "PowerShell suspeito seguido de scheduled task",
        "rules": ["R004", "R002"],  # PowerShell -> Scheduled Task
        "severity": "HIGH",
        "risk_boost": 82,
        "mitre_tactic": "Execution -> Persistence",
    },
    {
        "id": "C006",
        "name": "Criacao de Conta e Persistencia",
        "description": "Adicao de utilizador seguida de persistencia no registo",
        "rules": ["R005", "R001"],  # Add User -> Registry Persistence
        "severity": "CRITICAL",
        "risk_boost": 92,
        "mitre_tactic": "Persistence -> Persistence",
    },
]

# ============================================================
# PARSING DE TIMESTAMPS
# ============================================================

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
]

def parse_timestamp(ts: str):
    """Tenta fazer parse de varios formatos de timestamp."""
    if not ts:
        return None
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None

# ============================================================
# MOTOR DE CORRELACAO
# ============================================================

def build_host_timeline(alerts: list) -> dict:
    """
    Expande os alertas agrupados em eventos individuais por host,
    ordenados por timestamp.
    """
    timeline = defaultdict(list)

    for alert in alerts:
        rule_id  = alert.get("rule", "")
        severity = alert.get("severity", "LOW")
        if not rule_id:
            continue

        # Preferir eventos expandidos por host/timestamp quando disponíveis.
        expanded_events = alert.get("events") or []
        if expanded_events:
            for event in expanded_events:
                host = event.get("Computer") or alert.get("sample_event", {}).get("Computer", "unknown")
                timeline[host].append({
                    "alert":      alert,
                    "rule_id":    rule_id,
                    "timestamp":  parse_timestamp(event.get("TimeCreated")),
                    "severity":   severity,
                    "source_event": event,
                })
            continue

        hosts  = alert.get("hosts", [])
        sample = alert.get("sample_event", {})
        ts     = parse_timestamp(sample.get("TimeCreated"))

        if not hosts:
            hosts = [sample.get("Computer", "unknown")]

        for host in hosts:
            timeline[host].append({
                "alert":      alert,
                "rule_id":    rule_id,
                "timestamp":  ts,
                "severity":   severity,
                "source_event": sample,
            })

    # Ordenar cada host por timestamp
    for host in timeline:
        timeline[host].sort(key=lambda x: (x["timestamp"] is None, x["timestamp"] or datetime.max))

    return dict(timeline)


def _match_span_minutes(match: list):
    timestamps = [event["timestamp"] for event in match if event.get("timestamp") is not None]
    if len(timestamps) != len(match):
        return None
    return int((timestamps[-1] - timestamps[0]).total_seconds() / 60)

def check_chain(host_events: list, chain: dict, window_minutes: int) -> list:
    """
    Verifica se a cadeia ocorre pela ordem definida.
    Quando existem timestamps, exige que a sequência caiba na janela temporal.
    """
    required_rules = chain["rules"]
    host_rules = {event["rule_id"] for event in host_events}
    if not all(rule_id in host_rules for rule_id in required_rules):
        return []

    best_match = None
    best_span = None

    for start_index, first_event in enumerate(host_events):
        if first_event["rule_id"] != required_rules[0]:
            continue

        match = [first_event]
        first_ts = first_event.get("timestamp")
        search_index = start_index + 1

        for next_rule in required_rules[1:]:
            candidate = None
            candidate_index = None

            for idx in range(search_index, len(host_events)):
                event = host_events[idx]
                if event["rule_id"] != next_rule:
                    continue

                current_ts = event.get("timestamp")
                if first_ts is not None and current_ts is not None:
                    delta_minutes = (current_ts - first_ts).total_seconds() / 60
                    if delta_minutes < 0:
                        continue
                    if delta_minutes > window_minutes:
                        break

                candidate = event
                candidate_index = idx
                break

            if candidate is None:
                match = []
                break

            match.append(candidate)
            search_index = candidate_index + 1

        if not match:
            continue

        span = _match_span_minutes(match)
        if span is not None and span > window_minutes:
            continue

        if best_match is None:
            best_match = match
            best_span = span
            continue

        if span is not None and (best_span is None or span < best_span):
            best_match = match
            best_span = span

    return [best_match] if best_match else []

def run_correlation_engine(alerts: list) -> list:
    """
    Motor principal de correlacao.
    Recebe os alertas do motor de regras e deteta cadeias de ataque.
    """
    print("\n--- Motor de Correlacao ----------------------------------")

    if not alerts:
        print("  [*] Sem alertas para correlacionar.")
        return []

    timeline      = build_host_timeline(alerts)
    correlations  = []

    print(f"  [*] A analisar {len(timeline)} hosts na janela de {CORRELATION_WINDOW_MINUTES} minutos...")

    for host, host_events in timeline.items():
        if len(host_events) < 2:
            continue

        for chain in ATTACK_CHAINS:
            # Verificar se o host tem todas as regras da cadeia
            host_rules = set(e["rule_id"] for e in host_events)
            if not all(r in host_rules for r in chain["rules"]):
                continue

            matches = check_chain(host_events, chain, CORRELATION_WINDOW_MINUTES)

            for match in matches:
                first_ts = match[0]["timestamp"]
                last_ts  = match[-1]["timestamp"]
                duration = None
                if first_ts and last_ts and first_ts != last_ts:
                    delta = (last_ts - first_ts).total_seconds() / 60
                    duration = int(abs(delta))

                correlation = {
                    "chain_id":    chain["id"],
                    "chain_name":  chain["name"],
                    "severity":    chain["severity"],
                    "risk_score":  chain["risk_boost"],
                    "host":        host,
                    "mitre_tactic": chain["mitre_tactic"],
                    "description": chain["description"],
                    "duration_minutes": duration,
                    "steps": [
                        {
                            "rule_id":   e["rule_id"],
                            "rule_name": e["alert"].get("rule_name", ""),
                            "timestamp": e["timestamp"].isoformat() if e["timestamp"] else None,
                        }
                        for e in match
                    ],
                }
                correlation["sequence"] = list(correlation["steps"])

                print(f"\n  [!!!] [{chain['severity']}] {chain['name']} (Cadeia {chain['id']})")
                print(f"        Host     : {host}")
                print(f"        Tatica   : {chain['mitre_tactic']}")
                print(f"        Duracao  : {f'~{duration} minutos' if duration is not None else 'N/A (eventos agrupados)'}")
                print(f"        Sequencia:")
                for step in correlation["steps"]:
                    ts_str = step["timestamp"][:19] if step["timestamp"] else "N/A"
                    print(f"          [{ts_str}] {step['rule_name']} ({step['rule_id']})")
                print(f"        Risk Score : {chain['risk_boost']}/100")

                correlations.append(correlation)

    if not correlations:
        print("  [*] Nenhuma cadeia de ataque detetada.")

    print(f"\n  [+] Total de cadeias detetadas: {len(correlations)}")
    return correlations
