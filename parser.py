import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import json

# --- Constantes ---
XML_NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"
# Vamos usar o novo ficheiro de log para este teste
EVTX_FILE_PATH = "log_registry_attack.evtx" 

# --- Funções de Parsing ---

def parse_record(record ):
    """
    Recebe um registo e o processa, chamando a função de parsing específica para o seu EventID.
    """
    try:
        xml_content = record.xml()
        root = ET.fromstring(xml_content)
        
        system_element = root.find(f"{XML_NAMESPACE}System")
        event_id_element = system_element.find(f"{XML_NAMESPACE}EventID")
        event_id = event_id_element.text

        # Extrai os dados comuns a todos os eventos
        common_data = {
            "EventID": event_id,
            "Computer": system_element.find(f"{XML_NAMESPACE}Computer").text,
            "TimeCreated": system_element.find(f"{XML_NAMESPACE}TimeCreated").get("SystemTime")
        }

        event_data_element = root.find(f"{XML_NAMESPACE}EventData")
        if event_data_element is None:
            return None

        # Chama a função de parsing específica para o EventID
        if event_id == '1':
            specific_data = parse_event_id_1(event_data_element)
        elif event_id == '13':
            specific_data = parse_event_id_13(event_data_element)
        else:
            # Ignoramos outros EventIDs por agora
            return None
        
        # Combina os dados comuns com os dados específicos do evento
        if specific_data:
            return {**common_data, **specific_data}
        return None

    except (ET.ParseError, AttributeError):
        return None

def parse_event_data_fields(event_data_element):
    """Função auxiliar para extrair todos os campos de <EventData>."""
    data_dict = {}
    for data_element in event_data_element.findall(f"{XML_NAMESPACE}Data"):
        name = data_element.get("Name")
        value = data_element.text
        data_dict[name] = value
    return data_dict

def parse_event_id_1(event_data_element):
    """Extrai dados de um evento de Criação de Processo (ID 1)."""
    return parse_event_data_fields(event_data_element)

def parse_event_id_13(event_data_element):
    """Extrai dados de um evento de Alteração de Registo (ID 13)."""
    return parse_event_data_fields(event_data_element)

# --- Motor de Regras ---

def rule_suspicious_run_key(event):
    """
    Regra: Deteta se uma chave de registo 'Run' foi modificada.
    As chaves 'Run' são um local comum para malware criar persistência.
    """
    # A regra só se aplica a eventos de alteração de registo
    if event.get("EventID") != '13':
        return False
    
    target_object = event.get("TargetObject", "")
    
    # Verificamos se o caminho da chave de registo contém as palavras "Run"
    # Usamos .lower() para ignorar maiúsculas/minúsculas
    if "run" in target_object.lower():
        return True
        
    return False

def run_rule_engine(events):
    """
    Recebe uma lista de eventos e aplica todas as regras a cada um.
    """
    print("\n--- A EXECUTAR O MOTOR DE REGRAS ---")
    
    alerts_found = 0
    for event in events:
        # Aplicamos a nossa primeira regra
        if rule_suspicious_run_key(event):
            alerts_found += 1
            print("\n[!!!] ALERTA: POSSÍVEL PERSISTÊNCIA VIA CHAVE DE REGISTO 'RUN' DETETADA!")
            print(f"  - Computador: {event.get('Computer')}")
            print(f"  - Hora: {event.get('TimeCreated')}")
            print(f"  - Processo que fez a alteração: {event.get('Image')}")
            print(f"  - Chave de Registo afetada: {event.get('TargetObject')}")
            print(f"  - Valor escrito: {event.get('Details')}")
            
    if alerts_found == 0:
        print("[*] Nenhuma regra de deteção foi acionada.")

# --- Função Principal ---

def main():
    print(f"[*] A processar o ficheiro: {EVTX_FILE_PATH}")
    
    all_events = []
    with evtx.Evtx(EVTX_FILE_PATH) as log:
        for record in log.records():
            parsed_data = parse_record(record)
            if parsed_data:
                all_events.append(parsed_data)

    print(f"[*] Processamento concluído. Encontrados {len(all_events)} eventos relevantes (ID 1 e 13).")
    
    # Executa o motor de regras nos eventos que encontrámos
    run_rule_engine(all_events)


if __name__ == "__main__":
    main()
