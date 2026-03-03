# sentinel.py - MAIN
from parser import get_events
import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np

# --- Placeholder para a IA Local ---
def get_local_ai_explanation(alert_context):
    print("\n [ SentinelAI ] A pensar...")
    simulated_explanation = (
        "Análise da IA (Simulada): O processo suspeito '{}' criou uma entrada numa chave de registo 'Run'. "
        "Isto é uma técnica de persistência comum usada por malware para garantir que é executado sempre que o sistema arranca. "
        "O risco é alto, pois indica que o sistema pode estar comprometido de forma permanente."
    ).format(alert_context.get('Image', 'desconhecido'))
    return simulated_explanation

# --- Motor de Regras ---
def rule_suspicious_run_key(event):
    if event.get("EventID") != '13': return False
    target_object = event.get("TargetObject", "")
    return "run" in target_object.lower()

def run_rule_engine(events):
    print("\n--- (Motor de Regras) A executar análise de regras ---")
    alerts_found = 0
    for event in events:
        if rule_suspicious_run_key(event):
            alerts_found += 1
            print("\n[!!!] ALERTA DE REGRA: Persistência via Chave 'Run'!")
            explanation = get_local_ai_explanation(event)
            print("\n--- Análise do [ SentinelAI ] ---")
            print(explanation)
            print("---------------------")
    if alerts_found == 0:
        print("[*] Nenhuma regra acionada.")

# --- Motor de Análise de Anomalias ---
def calculate_entropy(text):
    if not text: return 0
    probs = pd.Series(list(text)).value_counts(normalize=True)
    return -np.sum(probs * np.log2(probs))

def run_anomaly_engine(events):
    print("\n--- (Motor de Anomalias) A analisar Command Lines ---")
    proc_events = [e for e in events if e.get("EventID") == '1' and e.get("CommandLine")]
    if len(proc_events) < 2:
        print("[*] Não há eventos suficientes para a análise de anomalias.")
        return
    df = pd.DataFrame(proc_events)
    df['cmd_length'] = df['CommandLine'].str.len()
    df['cmd_entropy'] = df['CommandLine'].apply(calculate_entropy)
    df['num_args'] = df['CommandLine'].apply(lambda x: len(x.split()))
    features = df[['cmd_length', 'cmd_entropy', 'num_args']]
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(features)
    df['anomaly_score'] = -model.decision_function(features)
    print("\n[+] Top 5 Comandos Mais Anómalos (Isolation Forest):")
    top_5 = df.sort_values(by='anomaly_score', ascending=False).head(5)
    for index, row in top_5.iterrows():
        print(f"  - Score: {row['anomaly_score']:.2f} | Comando: {row['CommandLine']}")

# --- Função Principal ---
def main():
    print("--- [ SentinelAI ] : Início da Análise Completa ---")
    
    # 1. Analisar o ficheiro de ataque de registo com o motor de regras
    print("\n[1] A analisar logs de ataque de registo...")
    registry_events = get_events("log_registry_attack.evtx")
    if registry_events:
        run_rule_engine(registry_events)
        
    # 2. Analisar o ficheiro de command lines com o motor de anomalias
    print("\n[2] A analisar logs de command lines...")
    command_line_events = get_events("log_commandlines.evtx")
    if command_line_events:
        run_anomaly_engine(command_line_events)
        
    print("\n--- [ SentinelAI ] : Fim da Análise ---")

if __name__ == "__main__":
    main()
