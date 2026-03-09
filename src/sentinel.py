# sentinel.py - MAIN
# SentinelAI - Motor de Analise Comportamental
import os
import json
import requests
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from parser import get_events, get_events_from_folder
from train import predict, check_hard_rules
from correlator import run_correlation_engine
from host_scorer import calculate_host_scores, print_host_scores
from report_writer import generate_txt_report

# --- Configuracao ---
OLLAMA_URL      = "http://localhost:11434/api/generate"
OLLAMA_MODEL    = "mistral"

# BASE DIR - funciona como .py e como .exe compilado
import sys as _sys
_BASE_DIR = os.path.dirname(_sys.executable) if getattr(_sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))

MODELS_DIR      = os.path.join(_BASE_DIR, "models")
MODEL_PATH      = os.path.join(MODELS_DIR, "security_model.pkl")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")

# Paths configurados pelo menu via variaveis de ambiente
OUTPUT_DIR = os.environ.get("SENTINELAI_OUTPUT_DIR", os.path.join(_BASE_DIR, "output", "reports"))
LOGS_DIR   = os.environ.get("SENTINELAI_LOGS_DIR",   os.path.join(_BASE_DIR, "logs"))

# ============================================================
# OLLAMA - Analise Global no Final (uma unica chamada)
# ============================================================

def get_global_ai_analysis(all_alerts: list, correlations: list) -> dict:
    """
    Faz UMA unica chamada ao Ollama no final com o resumo compacto
    de todos os alertas e cadeias detetadas.
    """
    print("\n  [ SentinelAI ] A consultar IA local (Ollama)...", end=" ", flush=True)

    # Resumo compacto — top 5 alertas mais graves e top 5 cadeias
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    top_alerts = sorted(all_alerts, key=lambda a: severity_order.get(a.get("severity", "LOW"), 99))[:5]
    top_chains = sorted(correlations, key=lambda c: -c.get("risk_score", 0))[:5]

    alert_summary = [
        {
            "nome":       a.get("rule_name", "Anomalia ML"),
            "severidade": a.get("severity", "N/A"),
            "hosts":      a.get("hosts", [])[:3],
            "exemplo":    str(a.get("sample_event", {}).get("CommandLine",
                          a.get("sample_event", {}).get("TargetObject",
                          a.get("command", "N/A"))))[:60]
        }
        for a in top_alerts
    ]

    chain_summary = [
        {
            "cadeia": c.get("chain_name"),
            "host":   c.get("host"),
            "tatica": c.get("mitre_tactic"),
            "risco":  c.get("risk_score")
        }
        for c in top_chains
    ]

    prompt = f"""És um analista de segurança SOC sénior. Analisa este relatório e responde APENAS em JSON válido, sem texto extra. Usa português de Portugal (PT-PT).

TOP ALERTAS ({len(all_alerts)} total):
{json.dumps(alert_summary, indent=2, ensure_ascii=False)}

TOP CADEIAS DE ATAQUE ({len(correlations)} total):
{json.dumps(chain_summary, indent=2, ensure_ascii=False)}

Responde APENAS com este JSON:
{{
  "risk_score_global": <inteiro 0-100>,
  "nivel_ameaca": "<CRITICO|ALTO|MEDIO|BAIXO>",
  "resumo_executivo": "<resumo geral em 2-3 frases, PT-PT>",
  "principais_ameacas": ["<ameaca 1>", "<ameaca 2>", "<ameaca 3>"],
  "hipotese_ataque": "<narrativa do ataque em 1-2 frases, PT-PT>",
  "hosts_criticos": ["<host 1>", "<host 2>", "<host 3>"],
  "acoes_imediatas": ["<acao 1>", "<acao 2>", "<acao 3>"],
  "tecnicas_mitre": ["<T1xxx - nome>", "<T1xxx - nome>"]
}}"""

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "num_predict": 600
            }
        }, timeout=240)

        raw = response.json().get("response", "{}")
        result = json.loads(raw)
        print("OK")
        return result

    except requests.exceptions.ReadTimeout:
        print("TIMEOUT - a usar fallback.")
        return _fallback_global(all_alerts, correlations)
    except requests.exceptions.ConnectionError:
        print("SEM LIGACAO - a usar fallback.")
        return _fallback_global(all_alerts, correlations)
    except (json.JSONDecodeError, KeyError):
        print("ERRO JSON - a usar fallback.")
        return _fallback_global(all_alerts, correlations)

def _fallback_global(all_alerts: list, correlations: list) -> dict:
    """Analise global calculada a partir dos dados reais, sem necessidade do Ollama."""
    from collections import Counter

    critical = [a for a in all_alerts if a.get("severity") == "CRITICAL"]
    high     = [a for a in all_alerts if a.get("severity") == "HIGH"]

    # Hosts mais afetados (por numero de alertas)
    host_counts = Counter()
    for a in all_alerts:
        for h in a.get("hosts", []):
            host_counts[h] += 1
    top_hosts = [h for h, _ in host_counts.most_common(5)]

    # Risk score baseado na gravidade real
    if len(critical) >= 3 or len(correlations) >= 10:
        risk = 95
        nivel = "CRITICO"
    elif len(critical) >= 1 or len(correlations) >= 5:
        risk = 80
        nivel = "ALTO"
    else:
        risk = 60
        nivel = "MEDIO"

    # Principais ameacas
    principais = [a.get("rule_name", "Anomalia") for a in
                  sorted(all_alerts, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2}.get(x.get("severity","LOW"),3))[:3]]

    # Tecnicas MITRE baseadas nas regras detetadas
    mitre_map = {
        "R001": "T1547 - Boot or Logon Autostart Execution",
        "R002": "T1053 - Scheduled Task/Job",
        "R003": "T1218 - System Binary Proxy Execution",
        "R004": "T1059 - Command and Scripting Interpreter",
        "R005": "T1136 - Create Account",
        "R006": "T1003 - OS Credential Dumping",
        "R007": "T1021 - Remote Services",
        "R008": "T1059 - Command and Scripting Interpreter",
        "R009": "T1003 - OS Credential Dumping",
    }
    tecnicas = list(dict.fromkeys(
        mitre_map[a.get("rule","")]
        for a in all_alerts if a.get("rule","") in mitre_map
    ))[:4]

    # Narrativa do ataque baseada nas cadeias
    chain_names = list(dict.fromkeys(c.get("chain_name","") for c in correlations))
    if chain_names:
        hipotese = f"Detetadas {len(correlations)} cadeias de ataque em {len(host_counts)} hosts, incluindo: {', '.join(chain_names[:2])}."
    else:
        hipotese = f"Multiplos alertas criticos em {len(host_counts)} hosts sugerem comprometimento activo da rede."

    resumo = (
        f"Foram detetados {len(all_alerts)} alertas ({len(critical)} criticos, {len(high)} elevados) "
        f"e {len(correlations)} cadeias de ataque em {len(host_counts)} hosts distintos. "
        f"Os hosts mais afectados sao: {', '.join(top_hosts[:3])}."
    )

    return {
        "risk_score_global": risk,
        "nivel_ameaca":      nivel,
        "resumo_executivo":  resumo,
        "principais_ameacas": principais,
        "hipotese_ataque":   hipotese,
        "hosts_criticos":    top_hosts,
        "acoes_imediatas":   [
            "Isolar imediatamente os hosts criticos da rede",
            "Revogar e repor todas as credenciais dos hosts afectados",
            "Analisar trafico de rede para identificar exfiltracao de dados"
        ],
        "tecnicas_mitre": tecnicas
    }

def print_global_analysis(analysis: dict):
    """Imprime a analise global da IA de forma clara."""
    risk  = int(analysis.get("risk_score_global", 0))
    nivel = analysis.get("nivel_ameaca", "N/A")

    print(f"""
  +--[ SentinelAI - Analise Global IA ]---------------------+
  | Risk Score Global : {risk}/100 ({nivel})
  |
  | Resumo Executivo:
  |   {analysis.get('resumo_executivo', 'N/A')}
  |
  | Hipotese de Ataque:
  |   {analysis.get('hipotese_ataque', 'N/A')}
  |
  | Principais Ameacas:""")
    for t in analysis.get("principais_ameacas", []):
        print(f"  |   - {t}")
    print("  |")
    print("  | Hosts Criticos:")
    for h in analysis.get("hosts_criticos", []):
        print(f"  |   - {h}")
    print("  |")
    print("  | Tecnicas MITRE ATT&CK:")
    for m in analysis.get("tecnicas_mitre", []):
        print(f"  |   - {m}")
    print("  |")
    print("  | Acoes Imediatas:")
    for a in analysis.get("acoes_imediatas", []):
        print(f"  |   - {a}")
    print("  +---------------------------------------------------------+")

# ============================================================
# MOTOR DE REGRAS
# ============================================================

RULES = [
    {
        "id": "R001",
        "name": "Persistencia via Chave Run",
        "event_id": "13",
        "check": lambda e: "run" in e.get("TargetObject", "").lower(),
        "severity": "HIGH"
    },
    {
        "id": "R002",
        "name": "Criacao de Scheduled Task Suspeita",
        "event_id": "1",
        "check": lambda e: "schtasks" in e.get("CommandLine", "").lower() and "/create" in e.get("CommandLine", "").lower(),
        "severity": "HIGH"
    },
    {
        "id": "R003",
        "name": "LOLBin Detetado",
        "event_id": "1",
        "check": lambda e: any(lb in e.get("CommandLine", "").lower() for lb in ["certutil", "mshta", "rundll32", "regsvr32", "wscript", "bitsadmin"]),
        "severity": "MEDIUM"
    },
    {
        "id": "R004",
        "name": "PowerShell Suspeito",
        "event_id": "1",
        "check": lambda e: "powershell" in e.get("CommandLine", "").lower() and
                           any(flag in e.get("CommandLine", "").lower() for flag in ["-enc", "-nop", "bypass", "hidden", "iex", "downloadstring"]),
        "severity": "HIGH"
    },
    {
        "id": "R005",
        "name": "Adicao de Utilizador ao Sistema",
        "event_id": "1",
        "check": lambda e: "net user" in e.get("CommandLine", "").lower() and "/add" in e.get("CommandLine", "").lower(),
        "severity": "CRITICAL"
    },
    {
        "id": "R006",
        "name": "Dump de Credenciais",
        "event_id": "1",
        "check": lambda e: any(x in e.get("CommandLine", "").lower() for x in ["mimikatz", "procdump", "lsass", "sekurlsa"]),
        "severity": "CRITICAL"
    },
    {
        "id": "R007",
        "name": "Movimento Lateral via WMI ou PsExec",
        "event_id": "1",
        "check": lambda e: any(x in e.get("CommandLine", "").lower() for x in ["psexec", "wmic /node"]),
        "severity": "HIGH"
    },
    {
        "id": "R008",
        "name": "Reverse Shell Linux",
        "event_id": "EXECVE",
        "check": lambda e: any(x in e.get("CommandLine", "").lower() for x in ["/dev/tcp", "nc -e", "bash -i"]),
        "severity": "CRITICAL"
    },
    {
        "id": "R009",
        "name": "Leitura de Ficheiros de Credenciais Linux",
        "event_id": "EXECVE",
        "check": lambda e: any(x in e.get("CommandLine", "").lower() for x in ["cat /etc/shadow", "cat /etc/passwd", "id_rsa"]),
        "severity": "HIGH"
    },
]

def run_rule_engine(events: list) -> list:
    print("\n--- Motor de Regras --------------------------------------")

    rule_hits: dict = {}
    for event in events:
        for rule in RULES:
            if event.get("EventID") == rule["event_id"] and rule["check"](event):
                rule_hits.setdefault(rule["id"], {"rule": rule, "events": []})
                rule_hits[rule["id"]]["events"].append(event)

    if not rule_hits:
        print("  [*] Nenhuma regra acionada.")
        return []

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_hits = sorted(rule_hits.items(), key=lambda x: severity_order.get(x[1]["rule"]["severity"], 99))

    alerts = []
    for rule_id, data in sorted_hits:
        rule        = data["rule"]
        rule_events = data["events"]
        severity    = rule["severity"]

        print(f"\n  [!] [{severity}] {rule['name']} (Regra {rule['id']})")
        print(f"      Ocorrencias : {len(rule_events)}")
        print(f"      Hosts       : {', '.join(sorted(set(e.get('Computer','N/A') for e in rule_events)))}")
        print(f"      Exemplo     : {rule_events[0].get('TargetObject', rule_events[0].get('CommandLine','N/A'))[:80]}")

        alerts.append({
            "rule":         rule["id"],
            "rule_name":    rule["name"],
            "severity":     severity,
            "occurrences":  len(rule_events),
            "hosts":        sorted(set(e.get("Computer", "N/A") for e in rule_events)),
            "sample_event": rule_events[0],
        })

    return alerts

# ============================================================
# MOTOR DE ANOMALIAS (Isolation Forest + ML Model)
# ============================================================

def calculate_entropy(text: str) -> float:
    if not text: return 0
    probs = pd.Series(list(text)).value_counts(normalize=True)
    return -np.sum(probs * np.log2(probs))

def run_anomaly_engine(events: list) -> list:
    print("\n--- Motor de Anomalias -----------------------------------")
    alerts = []

    proc_events = [e for e in events if e.get("EventID") in ('1', 'EXECVE') and e.get("CommandLine")]
    if len(proc_events) < 2:
        print("  [*] Eventos insuficientes para analise de anomalias.")
        return alerts

    df = pd.DataFrame(proc_events)
    df['cmd_length']  = df['CommandLine'].str.len()
    df['cmd_entropy'] = df['CommandLine'].apply(calculate_entropy)
    df['num_args']    = df['CommandLine'].apply(lambda x: len(x.split()))

    features = df[['cmd_length', 'cmd_entropy', 'num_args']]
    iso = IsolationForest(contamination='auto', random_state=42)
    iso.fit(features)
    df['anomaly_score'] = -iso.decision_function(features)

    model_available = os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH)
    if model_available:
        df['ml_result'] = df['CommandLine'].apply(predict)
        df['ml_label']  = df['ml_result'].apply(lambda r: r['label'])
        df['ml_conf']   = df['ml_result'].apply(lambda r: r['confidence'])
        df['ml_reason'] = df['ml_result'].apply(lambda r: r.get('reason', 'ML Model'))

    print(f"\n  [+] Top 5 Comandos Mais Anomalos:")
    top_5 = df.sort_values(by='anomaly_score', ascending=False).head(5)

    seen_commands = set()
    for _, row in top_5.iterrows():
        cmd   = row['CommandLine']
        score = row['anomaly_score']

        ml_info = ""
        if model_available:
            ml_info = f" | {row['ml_label']} ({row['ml_conf']}%) [{row['ml_reason']}]"

        print(f"\n  Anomaly Score : {score:.2f}{ml_info}")
        print(f"  Comando       : {cmd[:80]}")

        cmd_key = cmd[:60]
        if model_available and row['ml_label'] == "MALICIOSO" and row['ml_conf'] >= 70 and cmd_key not in seen_commands:
            seen_commands.add(cmd_key)
            alerts.append({
                "type":           "anomaly",
                "rule_name":      "Anomalia ML",
                "severity":       "HIGH",
                "command":        cmd,
                "hosts":          [str(row.get("Computer", "N/A"))],
                "anomaly_score":  round(score, 4),
                "ml_confidence":  row['ml_conf'],
                "sample_event":   {"CommandLine": cmd, "Computer": str(row.get("Computer", "N/A"))}
            })

    return alerts

# ============================================================
# RELATORIO FINAL
# ============================================================

def save_report(all_alerts: list, correlations: list, ai_analysis: dict, host_scores: dict = {}):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(OUTPUT_DIR, f"report_{timestamp}.json")

    report = {
        "timestamp":      timestamp,
        "total_alerts":   len(all_alerts),
        "total_chains":   len(correlations),
        "total_hosts":    len(host_scores),
        "ai_analysis":    ai_analysis,
        "host_scores":    host_scores,
        "alerts":         all_alerts,
        "attack_chains":  correlations,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  [+] Relatorio JSON guardado em: {path}")

    # Relatorio TXT legivel
    txt_path = path.replace(".json", ".txt")
    generate_txt_report(all_alerts, correlations, host_scores, ai_analysis, txt_path)

# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("   SentinelAI - Motor de Analise Comportamental")
    print("=" * 60)

    all_alerts = []

    # 1. Motor de Regras
    print("\n[1] A analisar logs de ataque (Motor de Regras)...")
    attack_events = get_events_from_folder(LOGS_DIR)
    if attack_events:
        alerts = run_rule_engine(attack_events)
        all_alerts.extend(alerts)

    # 2. Motor de Anomalias + ML
    print("\n[2] A analisar comportamento anomalo (Motor de Anomalias)...")
    all_events = get_events_from_folder(LOGS_DIR)
    if all_events:
        alerts = run_anomaly_engine(all_events)
        all_alerts.extend(alerts)

    # 3. Motor de Correlacao
    print("\n[3] A correlacionar eventos (Motor de Correlacao)...")
    correlations = run_correlation_engine(all_alerts)

    # 4. Score de risco por host
    print("\n[4] A calcular score de risco por host...")
    host_scores = calculate_host_scores(all_alerts, correlations)
    print_host_scores(host_scores)

    # 5. Analise global com Ollama (uma unica chamada)
    print("\n[5] A gerar analise global com IA...")
    # Acordar o Ollama antes da chamada principal
    try:
        requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL, "prompt": "ok", "stream": False,
            "options": {"num_predict": 1}
        }, timeout=60)
    except Exception:
        pass
    ai_analysis = get_global_ai_analysis(all_alerts, correlations)
    print_global_analysis(ai_analysis)

    # 6. Relatorio final
    print("\n--- Sumario Final ----------------------------------------")
    print(f"  Alertas detetados : {len(all_alerts)}")
    print(f"  Cadeias de ataque : {len(correlations)}")
    print(f"  Hosts analisados  : {len(host_scores)}")
    criticos = sum(1 for d in host_scores.values() if d["nivel"] == "CRITICO")
    print(f"  Hosts criticos    : {criticos}")
    if all_alerts or correlations:
        save_report(all_alerts, correlations, ai_analysis, host_scores)

    print("\n" + "=" * 60)
    print("   Analise Concluida")
    print("=" * 60)

if __name__ == "__main__":
    main()