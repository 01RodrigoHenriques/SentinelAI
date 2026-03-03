import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import json # output "bonito"
from collections import Counter # Importamos o Counter para nos ajudar a contar

XML_NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"
EVTX_FILE_PATH = "logs.evtx"

def parse_record(record ):
    try:
        xml_content = record.xml()
        root = ET.fromstring(xml_content)
        system_element = root.find(f"{XML_NAMESPACE}System")
        event_id_element = system_element.find(f"{XML_NAMESPACE}EventID")
        if event_id_element.text != '1':
            return None
        event_data_element = root.find(f"{XML_NAMESPACE}EventData")
        if event_data_element is None:
            return None
        data_dict = {}
        for data_element in event_data_element.findall(f"{XML_NAMESPACE}Data"):
            name = data_element.get("Name")
            value = data_element.text
            data_dict[name] = value
        return data_dict
    except (ET.ParseError, AttributeError):
        return None

def main():
    print(f"[*] A processar o ficheiro: {EVTX_FILE_PATH}")
    process_creation_events = []
    with evtx.Evtx(EVTX_FILE_PATH) as log:
        for record in log.records():
            parsed_data = parse_record(record)
            if parsed_data:
                process_creation_events.append(parsed_data)

    print(f"[*] Processamento concluído.")
    print(f"[*] Encontrados {len(process_creation_events)} eventos de Criação de Processo (ID 1).")

    # --- INÍCIO DA ANÁLISE EXPLORATÓRIA ---
    if process_creation_events:
        print("\n--- ANÁLISE EXPLORATÓRIA ---")

        # 1. Quais são os processos mais comuns?
        # Criamos uma lista com todos os nomes de processos (Image)
        process_names = [event.get("Image", "N/A") for event in process_creation_events]
        # O Counter conta as ocorrências de cada item na lista
        process_counts = Counter(process_names)
        print("\n[+] Contagem de processos criados:")
        for name, count in process_counts.most_common(): # .most_common() ordena do mais para o menos comum
            print(f"  - {name}: {count} vez(es)")

        # 2. Quais são os processos "pai" mais comuns?
        parent_names = [event.get("ParentImage", "N/A") for event in process_creation_events]
        parent_counts = Counter(parent_names)
        print("\n[+] Contagem de processos pai:")
        for name, count in parent_counts.most_common():
            print(f"  - {name}: {count} vez(es)")
            
        # 3. Que utilizadores estão a criar mais processos?
        users = [event.get("User", "N/A") for event in process_creation_events]
        user_counts = Counter(users)
        print("\n[+] Contagem de processos por utilizador:")
        for name, count in user_counts.most_common():
            print(f"  - {name}: {count} vez(es)")
    # --- FIM DA ANÁLISE EXPLORATÓRIA ---


if __name__ == "__main__":
    main()
