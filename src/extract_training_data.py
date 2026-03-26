# extract_training_data.py
# SentinelAI - Extrator de dados de treino a partir de EVTX reais
# Uso: python extract_training_data.py
# Resultado: gera ficheiro training_data_real.json com comandos extraidos

import os
import sys
import json
import xml.etree.ElementTree as ET
from collections import defaultdict

from runtime_paths import get_app_root

try:
    import Evtx.Evtx as evtx
    EVTX_AVAILABLE = True
except ImportError:
    print("[ERRO] python-evtx nao instalado.")
    print("       Corre: pip install python-evtx")
    sys.exit(1)

# ============================================================
# CONFIGURACAO
# ============================================================

BASE_DIR = str(get_app_root(__file__))
SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))

# Pasta com os EVTX. Pode ser ajustada por argumento ou variavel de ambiente.
DEFAULT_EVTX_DIR = os.path.join(BASE_DIR, "logs")
EVTX_DIR = os.getenv("SENTINELAI_EVTX_DIR", DEFAULT_EVTX_DIR)
OUTPUT_FILE = os.path.join(SOURCE_DIR, "training_data_real.json")

XML_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# EventIDs com CommandLine util para treino
RELEVANT_IDS = {"1", "4688"}

# Inferir label pelo caminho da pasta
MALICIOUS_FOLDERS = {
    "credential access":  1,
    "defense evasion":    1,
    "execution":          1,
    "lateral movement":   1,
    "persistence":        1,
}

# ============================================================
# EXTRATOR
# ============================================================

def infer_label(filepath: str) -> int:
    """1 = malicioso, 0 = normal, baseado na pasta."""
    path_lower = filepath.lower()
    for folder, label in MALICIOUS_FOLDERS.items():
        if folder in path_lower:
            return label
    return 0

def extract_command_line(root) -> str:
    """Extrai CommandLine de um evento XML."""
    event_data = root.find(f"{XML_NS}EventData")
    if event_data is None:
        return ""
    for data in event_data.findall(f"{XML_NS}Data"):
        if data.get("Name") in ("CommandLine", "ProcessCommandLine"):
            return (data.text or "").strip()
    return ""

def extract_from_evtx(filepath: str, label: int) -> list:
    """Extrai comandos de um ficheiro .evtx."""
    results = []
    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    root     = ET.fromstring(record.xml())
                    system   = root.find(f"{XML_NS}System")
                    event_id = system.find(f"{XML_NS}EventID").text

                    if event_id not in RELEVANT_IDS:
                        continue

                    cmd = extract_command_line(root)
                    if not cmd or len(cmd) < 5:
                        continue

                    # Ignorar comandos obviamente do sistema
                    cmd_lower = cmd.lower()
                    if cmd_lower in ("", "-", "n/a"):
                        continue

                    results.append({
                        "command": cmd,
                        "label":   label,
                        "source":  os.path.basename(filepath),
                        "folder":  os.path.basename(os.path.dirname(filepath)),
                    })

                except (ET.ParseError, AttributeError):
                    continue
    except Exception as e:
        print(f"  [AVISO] Erro a ler {os.path.basename(filepath)}: {e}")

    return results

# ============================================================
# MAIN
# ============================================================

def main():
    global EVTX_DIR

    if len(sys.argv) > 1:
        EVTX_DIR = sys.argv[1]

    print("=" * 55)
    print("  SentinelAI - Extrator de Dados de Treino")
    print(f"  Pasta: {EVTX_DIR}")
    print("=" * 55)

    if not os.path.exists(EVTX_DIR):
        print(f"\n[ERRO] Pasta nao encontrada: {EVTX_DIR}")
        print("       Define SENTINELAI_EVTX_DIR ou passa a pasta como argumento.")
        sys.exit(1)

    # Encontrar todos os .evtx
    evtx_files = []
    for root, dirs, files in os.walk(EVTX_DIR):
        for f in files:
            if f.lower().endswith(".evtx"):
                evtx_files.append(os.path.join(root, f))

    print(f"\n  Ficheiros .evtx encontrados: {len(evtx_files)}")
    print()

    all_data    = []
    stats       = defaultdict(int)
    empty_files = 0

    for i, filepath in enumerate(evtx_files, 1):
        label    = infer_label(filepath)
        folder   = os.path.basename(os.path.dirname(filepath))
        filename = os.path.basename(filepath)

        print(f"  [{i:3}/{len(evtx_files)}] {folder}/{filename}", end=" ... ")

        results = extract_from_evtx(filepath, label)

        if results:
            all_data.extend(results)
            stats[folder] += len(results)
            print(f"{len(results)} comandos")
        else:
            empty_files += 1
            print("sem CommandLine")

    # Remover duplicados mantendo label
    seen     = {}
    unique   = []
    for item in all_data:
        cmd = item["command"].lower().strip()
        if cmd not in seen:
            seen[cmd] = True
            unique.append(item)

    print(f"\n  Total extraido  : {len(all_data)}")
    print(f"  Unico           : {len(unique)}")
    print(f"  Maliciosos      : {sum(1 for x in unique if x['label'] == 1)}")
    print(f"  Normais         : {sum(1 for x in unique if x['label'] == 0)}")
    print(f"  Ficheiros vazios: {empty_files}")
    print()
    print("  Por pasta:")
    for folder, count in sorted(stats.items()):
        print(f"    {folder:<30} {count} comandos")

    # Guardar resultado
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique, f, indent=2, ensure_ascii=False)

    print(f"\n  [+] Guardado em: {OUTPUT_FILE}")
    print()
    print("  Proximo passo: corre 'python update_training.py'")
    print("  para atualizar o train.py com estes dados reais.")

if __name__ == "__main__":
    main()
