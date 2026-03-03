# sentinel.py - MAIN
from parser import get_events
import pandas as pd
from sklearn.ensemble import IsolationForest # Importamos o algoritmo a sério
from collections import Counter
import numpy as np # Usamos para a parte da entropia

# --- Motor de Regras (vamos ignorá-lo por agora) ---
def run_rule_engine(events):
    pass

# --- Motor de Análise de Anomalias (com Isolation Forest) ---

def calculate_entropy(text):
    """Calcula a entropia de Shannon para uma string."""
    if not text:
        return 0
    # value_counts() conta a frequência de cada caracter
    # normalize=True transforma em probabilidades
    probs = pd.Series(list(text)).value_counts(normalize=True)
    # Fórmula da entropia
    entropy = -np.sum(probs * np.log2(probs))
    return entropy

def run_anomaly_engine(events):
    print("\n--- (Motor de Anomalias) A analisar Command Lines com Isolation Forest ---")

    # 1. Filtrar eventos e garantir que têm CommandLine
    proc_events = [e for e in events if e.get("EventID") == '1' and e.get("CommandLine")]
    if len(proc_events) < 2: # O algoritmo precisa de pelo menos 2 eventos para comparar
        print("[*] Não há eventos suficientes para a análise de anomalias.")
        return

    # 2. Criar DataFrame
    df = pd.DataFrame(proc_events)

    # 3. Engenharia de Features (as características que o modelo vai analisar)
    df['cmd_length'] = df['CommandLine'].str.len()
    df['cmd_entropy'] = df['CommandLine'].apply(calculate_entropy)
    # Adicionamos uma nova feature: número de palavras/argumentos
    df['num_args'] = df['CommandLine'].apply(lambda x: len(x.split()))

    # Selecionamos apenas as colunas com as nossas features numéricas
    features = df[['cmd_length', 'cmd_entropy', 'num_args']]

    # 4. Treinar o Modelo Isolation Forest
    # contamination='auto' deixa o modelo decidir a percentagem de anomalias
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(features)

    # 5. Obter o Score de Anomalia
    # O modelo devolve scores, onde valores mais baixos são mais anómalos.
    # Nós invertemos o sinal para que scores mais altos sejam mais anómalos.
    df['anomaly_score'] = -model.decision_function(features)

    # 6. Mostrar os 5 comandos mais anómalos
    print("\n[+] Top 5 Comandos Mais Anómalos (Isolation Forest):")
    top_5 = df.sort_values(by='anomaly_score', ascending=False).head(5)
    for index, row in top_5.iterrows():
        print(f"  - Score: {row['anomaly_score']:.2f} | Comando: {row['CommandLine']}")

# --- Função Principal ---
def main():
    print("--- SentinelAI ---")
    
    # Usamos o ficheiro com muitas command lines
    command_line_events = get_events("log_commandlines.evtx")
    
    if command_line_events:
        run_anomaly_engine(command_line_events)
        
    print("\n--- Fim ---")

if __name__ == "__main__":
    main()
