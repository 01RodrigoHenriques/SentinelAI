# SentinelAI

SentinelAI is a Windows-focused security log analysis project with two main flows:

- offline analysis of Windows event logs (`.evtx` and `.jsonl`)
- real-time forwarding from a Windows agent to a TCP receiver with a local console UI

The repository is prepared for public upload. Local runtime artefacts, local config, builds, and generated network logs are excluded by `.gitignore`.

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
- `notifications`: enables local notification behavior in the menu flow
- `discord_webhook`: optional Discord webhook URL
- `receiver_server`: receiver address used by the Windows agent
- `receiver_host`: bind address used by `receiver.py` and the embedded receiver in the menu
- `receiver_port`: TCP listener port
- `receiver_auth_token`: optional shared token between agent and receiver

Optional environment overrides:

- `SENTINELAI_CONFIG_PATH`
- `SENTINELAI_LOGS_DIR`
- `SENTINELAI_OUTPUT_DIR`
- `SENTINELAI_DISCORD_WEBHOOK`
- `SENTINELAI_RECEIVER_SERVER`
- `SENTINELAI_RECEIVER_HOST`
- `SENTINELAI_RECEIVER_PORT`
- `SENTINELAI_RECEIVER_AUTH_TOKEN`
- `SENTINELAI_NOTIFICATIONS`
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
.\venv\Scripts\python.exe -m pytest -q .\src\test_sentinel.py
```

## Building the Agent

```powershell
.\venv\Scripts\python.exe -m PyInstaller agent.spec --noconfirm
```

The resulting executable is created in `dist/`. That directory is ignored by git and should not be committed.

## What Is Safe To Commit

Safe:

- source code under `src/`
- sample EVTX dataset under `logs/` except runtime network captures
- model files under `models/`
- `requirements.txt`
- `agent.spec`
- `sentinelai_config.example.json`

Ignored on purpose:

- `src/sentinelai_config.json`
- `logs/network/`
- `src/logs/`
- `output/`
- `build/`
- `dist/`
- `venv/`
- `.pytest_cache/`
- `Photos/`
- local runtime logs and agent state

Made with love by Rodrigo Henriques
