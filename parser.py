# parser.py - UTIL
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

XML_NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def get_events(evtx_filepath ):
    all_events = []
    try:
        with evtx.Evtx(evtx_filepath) as log:
            for record in log.records():
                try:
                    xml_content = record.xml()
                    root = ET.fromstring(xml_content)
                    system = root.find(f"{XML_NAMESPACE}System")
                    event_id = system.find(f"{XML_NAMESPACE}EventID").text
                    if event_id not in ['1', '13']: continue
                    
                    common_data = {
                        "EventID": event_id,
                        "Computer": system.find(f"{XML_NAMESPACE}Computer").text,
                        "TimeCreated": system.find(f"{XML_NAMESPACE}TimeCreated").get("SystemTime")
                    }
                    
                    event_data_element = root.find(f"{XML_NAMESPACE}EventData")
                    if event_data_element is None: continue
                    
                    specific_data = {}
                    for data in event_data_element.findall(f"{XML_NAMESPACE}Data"):
                        specific_data[data.get("Name")] = data.text
                        
                    all_events.append({**common_data, **specific_data})
                except (ET.ParseError, AttributeError):
                    continue
    except FileNotFoundError:
        print(f"[ERRO] Ficheiro não encontrado: {evtx_filepath}")
        return []
    return all_events
