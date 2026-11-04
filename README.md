# SentinelAI

SentinelAI is a Windows-focused security log analysis project with two main flows:

- offline analysis of Windows event logs (`.evtx` and `.jsonl`)
- real-time forwarding from a Windows agent to a receiver with HMAC-authenticated JSONL events and a local console UI

## Current Scope

- Windows-only
- Rule-based detection for suspicious process execution and common attacker tradecraft
- Correlation of multi-step attack chains
- Risk scoring by host
- Text and PDF reporting
- Real-time receiver mode for agents on the same lab network
- Optional Discord notifications

## Repository Layout

```text
SentinelAI/
+-- src/
|   +-- menu.py
|   +-- receiver.py
|   +-- agent.py
|   +-- sentinel.py
|   +-- parser.py
|   +-- correlator.py
|   +-- report_writer.py
|   +-- train.py
|   +-- extract_training_data.py
|   +-- test_sentinel.py
|   +-- sentinelai_config.json   # local runtime config, ignored by git
+-- logs/                        # sample Windows EVTX corpus used for analysis
+-- models/                      # trained ML artefacts used by the anomaly layer
+-- output/                      # generated reports, ignored by git
+-- sentinelai_config.example.json
+-- requirements.txt
+-- agent.spec
```

## Requirements

- Windows
- Python 3.11+
- PowerShell
- Optional: administrator privileges on the monitored VM for richer event telemetry
- Optional: Ollama for local AI narrative output

## Installation

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configuration

The application reads `src/sentinelai_config.json` by default. That file is intentionally ignored by git so local webhooks, paths, and receiver settings do not leak into the repository.

Use the example file as the public baseline:

```powershell
Copy-Item .\sentinelai_config.example.json .\src\sentinelai_config.json
```

Available keys:

- `logs_folder`: directory used for input logs and collected network logs
- `output_folder`: directory used for generated reports
- `discord_webhook`: optional Discord webhook URL
- `receiver_server`: receiver address used by the Windows agent
- `receiver_host`: bind address used by `receiver.py` and the embedded receiver in the menu (defaults to `127.0.0.1`, set it explicitly to expose the listener on the network)
- `receiver_port`: TCP listener port
- `models_folder`: directory used for trained model artefacts
- `receiver_auth_token`: required shared secret used to sign every event with HMAC-SHA256; empty values and placeholders such as `CHANGE_ME` make the receiver refuse to start
- `receiver_tls_enabled`: enables TLS for the receiver/client transport (defaults to `true`; set it to `false` explicitly to opt out)
- `receiver_tls_certfile`: receiver certificate path when TLS is enabled
- `receiver_tls_keyfile`: receiver private key path when TLS is enabled
- `receiver_tls_ca_file`: CA bundle used by the agent to validate the receiver; on the receiver this enables client certificate verification
- `receiver_tls_server_name`: optional TLS server name override used by the agent
- `receiver_tls_client_certfile`: client certificate path used by the agent for mTLS
- `receiver_tls_client_keyfile`: client private key path used by the agent for mTLS

Optional environment overrides:

- `SENTINELAI_CONFIG_PATH`
- `SENTINELAI_LOGS_DIR`
- `SENTINELAI_OUTPUT_DIR`
- `SENTINELAI_MODELS_DIR`
- `SENTINELAI_DISCORD_WEBHOOK`
- `SENTINELAI_RECEIVER_SERVER`
- `SENTINELAI_RECEIVER_HOST`
- `SENTINELAI_RECEIVER_PORT`
- `SENTINELAI_RECEIVER_AUTH_TOKEN`
- `SENTINELAI_RECEIVER_TLS_ENABLED`
- `SENTINELAI_RECEIVER_TLS_CERTFILE`
- `SENTINELAI_RECEIVER_TLS_KEYFILE`
- `SENTINELAI_RECEIVER_TLS_CA_FILE`
- `SENTINELAI_RECEIVER_TLS_SERVER_NAME`
- `SENTINELAI_RECEIVER_TLS_CLIENT_CERTFILE`
- `SENTINELAI_RECEIVER_TLS_CLIENT_KEYFILE`
- `SENTINELAI_EVTX_DIR`

## Running

Interactive menu:

```powershell
.\venv\Scripts\python.exe .\src\menu.py
```

Standalone receiver:

```powershell
.\venv\Scripts\python.exe .\src\receiver.py
```

Windows agent from source:

```powershell
.\venv\Scripts\python.exe .\src\agent.py
```

Windows agent self-test:

```powershell
.\venv\Scripts\python.exe .\src\agent.py --receiver-server 192.168.56.1 --receiver-port 9000 --self-test
```

## Typical Lab Flow

1. Start the menu and open receiver mode with option `9`.
2. Start the receiver listener.
3. On the monitored Windows VM, run the agent pointing to the host IP.
4. Generate a test event or run the built-in self-test.
5. Confirm the event appears in the receiver panel.
6. Reuse the collected JSONL logs for offline analysis from the menu.

Example VM command:

```powershell
.\agent.exe --receiver-server 192.168.56.1 --receiver-port 9000
```

## Training and Data Utilities

Extract commands from EVTX samples:

```powershell
.\venv\Scripts\python.exe .\src\extract_training_data.py
```

Or point the extractor at another EVTX folder:

```powershell
.\venv\Scripts\python.exe .\src\extract_training_data.py "C:\Path\To\EVTX"
```

Refresh the training dataset:

```powershell
.\venv\Scripts\python.exe .\src\update_training.py
```

Train the anomaly model:

```powershell
.\venv\Scripts\python.exe .\src\train.py
```

## Tests

```powershell
.\venv\Scripts\python.exe -m pytest -q --cov=src --cov-report=term-missing .\src
```

## Building the Agent

```powershell
.\venv\Scripts\python.exe -m PyInstaller agent.spec --noconfirm
```

The resulting executable is created in `dist/`. That directory is ignored by git and should not be committed.

Made with love by Rodrigo Henriques
