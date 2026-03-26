# host_scorer.py
# SentinelAI - Score de Risco por Host
# Agrega alertas e cadeias de ataque por host e calcula um score de risco individual

from collections import defaultdict

# ============================================================
# PESOS DE SEVERIDADE
# ============================================================

SEVERITY_WEIGHTS = {
    "CRITICAL": 30,
    "HIGH":     15,
    "MEDIUM":    5,
    "LOW":       2,
}

CHAIN_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH":     12,
    "MEDIUM":    5,
    "LOW":       2,
}

RULE_TECHNIQUES = {
    "R001": "T1547 - Boot or Logon Autostart Execution",
    "R002": "T1053 - Scheduled Task/Job",
    "R003": "T1218 - System Binary Proxy Execution",
    "R004": "T1059 - Command and Scripting Interpreter",
    "R005": "T1136 - Create Account",
    "R006": "T1003 - OS Credential Dumping",
    "R007": "T1021 - Remote Services",
}

# ============================================================
# CALCULO DE SCORE POR HOST
# ============================================================

def calculate_host_scores(all_alerts: list, correlations: list) -> dict:
    """
    Calcula o score de risco para cada host com base em:
    - Alertas do motor de regras e anomalias
    - Cadeias de ataque detetadas pelo correlacionador
    Retorna: { "hostname": { score, nivel, alertas, cadeias, tecnicas } }
    """
    host_data = defaultdict(lambda: {
        "alerts":     [],
        "chains":     [],
        "tecnicas":   set(),
        "raw_score":  0,
    })

    # Processar alertas
    for alert in all_alerts:
        severity = alert.get("severity", "LOW")
        weight   = SEVERITY_WEIGHTS.get(severity, 2)
        hosts    = alert.get("hosts", [])

        for host in hosts:
            rule_id = alert.get("rule", "")
            host_data[host]["alerts"].append({
                "rule":     rule_id,
                "name":     alert.get("rule_name", "Anomalia"),
                "severity": severity,
            })
            host_data[host]["raw_score"] += weight

            # Registar tecnica MITRE se disponivel
            tech = alert.get("ai_analysis", {}).get("technique") or RULE_TECHNIQUES.get(rule_id)
            if tech:
                host_data[host]["tecnicas"].add(tech)

    # Processar cadeias de ataque
    for chain in correlations:
        host     = chain.get("host", "unknown")
        severity = chain.get("severity", "LOW")
        weight   = CHAIN_WEIGHTS.get(severity, 2)

        host_data[host]["chains"].append({
            "chain_id":   chain.get("chain_id"),
            "name":       chain.get("chain_name"),
            "severity":   severity,
            "risk_score": chain.get("risk_score", 0),
            "tactic":     chain.get("mitre_tactic"),
        })
        host_data[host]["raw_score"] += weight
        if chain.get("mitre_tactic"):
            host_data[host]["tecnicas"].add(chain["mitre_tactic"])

    # Normalizar scores para 0-100 e calcular nivel de risco
    results = {}
    for host, data in host_data.items():
        raw   = data["raw_score"]
        score = min(100, int(raw * 1.2))  # escalar ligeiramente

        if score >= 80:
            nivel = "CRITICO"
        elif score >= 55:
            nivel = "ALTO"
        elif score >= 30:
            nivel = "MEDIO"
        else:
            nivel = "BAIXO"

        results[host] = {
            "score":          score,
            "nivel":          nivel,
            "total_alertas":  len(data["alerts"]),
            "total_cadeias":  len(data["chains"]),
            "alertas":        data["alerts"],
            "cadeias":        data["chains"],
            "tecnicas":       list(data["tecnicas"]),
        }

    return results

# OUTPUT

def print_host_scores(host_scores: dict):
    """Imprime o ranking de risco por host."""
    if not host_scores:
        print("  [*] Sem dados de hosts para calcular scores.")
        return

    sorted_hosts = sorted(host_scores.items(), key=lambda x: -x[1]["score"])

    print("\n--- Score de Risco por Host ------------------------------")
    print(f"\n  {'HOST':<25} {'SCORE':<12} {'NIVEL':<10} {'ALERTAS':<10} {'CADEIAS'}")
    print(f"  {'-'*25} {'-'*11} {'-'*9} {'-'*9} {'-'*7}")

    for host, data in sorted_hosts:
        score   = data["score"]
        nivel   = data["nivel"]
        alertas = data["total_alertas"]
        cadeias = data["total_cadeias"]
        print(f"  {host:<25} {score:<3}/100      {nivel:<10} {alertas:<10} {cadeias}")

    # Detalhe dos hosts criticos
    criticos = [(h, d) for h, d in sorted_hosts if d["nivel"] == "CRITICO"]
    if criticos:
        print(f"\n  [!] Hosts Criticos ({len(criticos)}):")
        for host, data in criticos:
            chain_names = list(dict.fromkeys(c["name"] for c in data["cadeias"]))[:3]
            alert_names = list(dict.fromkeys(a["name"] for a in data["alertas"]))[:3]
            print(f"\n  Host : {host}")
            print(f"  Score: {data['score']}/100")
            if alert_names:
                print(f"  Alertas  : {', '.join(alert_names)}")
            if chain_names:
                print(f"  Cadeias  : {', '.join(chain_names)}")
