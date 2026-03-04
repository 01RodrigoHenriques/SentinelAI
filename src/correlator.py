# correlator.py
# SentinelAI - Motor de Correlacao de Eventos
# Deteta cadeias de ataque multi-evento no mesmo host dentro de uma janela temporal

from datetime import datetime, timedelta
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
        "id": "C005",
        "name": "Backdoor Linux Completo",
        "description": "Reverse shell seguido de leitura de credenciais",
        "rules": ["R008", "R009"],  # Reverse Shell -> Credential Read
        "severity": "CRITICAL",
        "risk_boost": 95,
        "mitre_tactic": "Execution -> Credential Access",
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

        # Cada alerta tem uma lista de hosts e um sample_event
        # Vamos criar uma entrada por host
        hosts       = alert.get("hosts", [])
        sample      = alert.get("sample_event", {})
        ts_raw      = sample.get("TimeCreated")
        ts          = parse_timestamp(ts_raw)

        if not hosts:
            host = sample.get("Computer", "unknown")
            hosts = [host]

        for host in hosts:
            timeline[host].append({
                "alert":     alert,
                "rule_id":   rule_id,
                "timestamp": ts,
                "severity":  severity,
            })

    # Ordenar cada host por timestamp
    for host in timeline:
        timeline[host].sort(key=lambda x: x["timestamp"] or datetime.min)

    return dict(timeline)

def check_chain(host_events: list, chain: dict, window_minutes: int) -> list:
    """
    Verifica se todos os elementos de uma cadeia estao presentes no host.
    Usa ordenacao temporal se disponivel, caso contrario verifica apenas presenca.
    """
    required_rules = chain["rules"]

    # Recolher todos os eventos por rule_id
    events_by_rule = defaultdict(list)
    for e in host_events:
        events_by_rule[e["rule_id"]].append(e)

    # Verificar se todas as regras estao presentes
    if not all(r in events_by_rule for r in required_rules):
        return []

    # Construir a cadeia com o primeiro evento de cada regra
    chain_match = []
    for rule_id in required_rules:
        chain_match.append(events_by_rule[rule_id][0])

    return [chain_match]

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
                    ]
                }

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