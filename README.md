# SentinelAI

[![tests](https://github.com/01RodrigoHenriques/SentinelAI/actions/workflows/tests.yml/badge.svg)](https://github.com/01RodrigoHenriques/SentinelAI/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20only-lightgrey)

Security log analytics for Windows environments. SentinelAI turns raw telemetry into actionable detections through two complementary flows:

- **Offline analysis** — ingest Windows event logs (`.evtx` / `.jsonl`), run detection engines, and produce risk-scored reports.
- **Real-time monitoring** — a lightweight Windows agent forwards HMAC-authenticated events over TLS to a receiver with a live console UI.

## Table of Contents

- [Key Features](#key-features)
- [Detection Engines](#detection-engines)
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Lab Architecture](#lab-architecture)
- [Training and Data Utilities](#training-and-data-utilities)
- [Tests and CI](#tests-and-ci)
- [Building the Agent](#building-the-agent)
- [Author](#author)

## Key Features

| Capability | Description |
| --- | --- |
| Rule-based detection | Signature rules covering persistence, LOLBins, suspicious PowerShell, credential access, and lateral movement |
| Attack chain correlation | Multi-step campaigns reconstructed from individual alerts, mapped to MITRE ATT&CK tactics |
| Anomaly detection | scikit-learn classifier over command-line features, plus entropy-based scoring |
| Host risk scoring | Aggregated, per-host risk ranking across a monitoring period |
| Reporting | JSON, plain-text, and PDF exports with analysis history |
| Real-time pipeline | TCP agent → receiver with HMAC-SHA256 event signing, optional TLS/mTLS, and replay protection |
| Notifications | Optional Discord webhook alerts |
| AI narrative | Optional local summarization of findings via Ollama |

## Detection Engines

**Rules (`src/sentinel.py`)**

| ID | Detection | Severity |
| --- | --- | --- |
| R001 | Persistence via registry Run key | High |
| R002 | Suspicious scheduled task creation | High |
| R003 | LOLBin execution (`certutil`, `mshta`, `rundll32`, …) | Medium |
| R004 | Suspicious/obfuscated PowerShell | High |
| R005 | Local account creation | Critical |
| R006 | Credential dumping (`mimikatz`, `procdump`, LSASS) | Critical |
| R007 | Lateral movement via PsExec / WMI | High |

**Attack chains (`src/correlator.py`)** — correlated sequences such as credential dump → lateral movement, or execution → persistence, each with a risk boost and ATT&CK tactic label.

**Anomaly layer (`src/train.py`)** — trained on a corpus of real Windows commands; artifacts are persisted to `models/` and reloaded at analysis time.

## Repository Layout

```text
SentinelAI/
├── src/
│   ├── menu.py                 # Interactive console UI (rich)
│   ├── sentinel.py             # Rule engine + anomaly engine
│   ├── correlator.py           # Attack-chain correlation
│   ├── host_scorer.py          # Per-host risk scoring
│   ├── report_writer.py        # JSON / text report generation
│   ├── parser.py               # EVTX and JSONL parsing
│   ├── receiver.py             # Standalone event receiver
│   ├── agent.py                # Windows agent (event forwarder)
│   ├── event_utils.py          # Shared helpers: HMAC auth, normalization
│   ├── app_config.py           # Configuration loading and env overrides
│   ├── runtime_paths.py
│   ├── train.py                # Anomaly model training
│   ├── extract_training_data.py
│   ├── update_training.py
│   ├── log_generator.py        # Synthetic log generator (lab use)
│   ├── training_data_real.json # Training corpus
│   └── test_*.py               # Pytest suite
├── .github/workflows/tests.yml # CI: pytest on windows-latest
├── sentinelai_config.example.json
├── requirements.txt
├── agent.spec                  # PyInstaller build spec
├── logo.ico
└── README.md
```

## Requirements

- Windows (10 / 11 or Windows Server)
- Python 3.11+
- PowerShell
- Optional: administrator privileges on the monitored host for richer telemetry
- Optional: [Ollama](https://ollama.com) for local AI-generated analysis narratives

## Installation

```powershell
git clone https://github.com/01RodrigoHenriques/SentinelAI.git
cd SentinelAI

python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configuration

Runtime configuration lives in `src/sentinelai_config.json`, which is **intentionally ignored by git** so local webhooks, paths, and secrets never leak into the repository. Start from the public baseline:

```powershell
Copy-Item .\sentinelai_config.example.json .\src\sentinelai_config.json
```

| Key | Purpose |
| --- | --- |
| `logs_folder` | Input logs and collected network logs |
| `output_folder` | Generated reports |
| `models_folder` | Trained model artifacts |
| `discord_webhook` | Optional Discord webhook URL |
| `receiver_server` | Receiver address used by the agent |
| `receiver_host` | Bind address for the receiver (defaults to `127.0.0.1`; set explicitly to expose on the network) |
| `receiver_port` | TCP listener port |
| `receiver_auth_token` | Shared secret used to sign every event with HMAC-SHA256. Empty values and placeholders such as `CHANGE_ME` make the receiver refuse to start |
| `receiver_tls_enabled` | Enables TLS for the receiver/client transport (defaults to `true`; set `false` explicitly to opt out) |
| `receiver_tls_certfile` / `receiver_tls_keyfile` | Receiver certificate and private key |
| `receiver_tls_ca_file` | CA bundle for agent validation; on the receiver it enables client certificate verification |
| `receiver_tls_server_name` | Optional TLS server name override for the agent |
| `receiver_tls_client_certfile` / `receiver_tls_client_keyfile` | Client certificate and key for agent mTLS |

Environment variable overrides are available for every key above:

| Variable | Maps to |
| --- | --- |
| `SENTINELAI_CONFIG_PATH` | Alternate config file location |
| `SENTINELAI_LOGS_DIR` | `logs_folder` |
| `SENTINELAI_OUTPUT_DIR` | `output_folder` |
| `SENTINELAI_MODELS_DIR` | `models_folder` |
| `SENTINELAI_DISCORD_WEBHOOK` | `discord_webhook` |
| `SENTINELAI_RECEIVER_SERVER` | `receiver_server` |
| `SENTINELAI_RECEIVER_HOST` | `receiver_host` |
| `SENTINELAI_RECEIVER_PORT` | `receiver_port` |
| `SENTINELAI_RECEIVER_AUTH_TOKEN` | `receiver_auth_token` |
| `SENTINELAI_RECEIVER_TLS_ENABLED` | `receiver_tls_enabled` |
| `SENTINELAI_RECEIVER_TLS_CERTFILE` | `receiver_tls_certfile` |
| `SENTINELAI_RECEIVER_TLS_KEYFILE` | `receiver_tls_keyfile` |
| `SENTINELAI_RECEIVER_TLS_CA_FILE` | `receiver_tls_ca_file` |
| `SENTINELAI_RECEIVER_TLS_SERVER_NAME` | `receiver_tls_server_name` |
| `SENTINELAI_RECEIVER_TLS_CLIENT_CERTFILE` | `receiver_tls_client_certfile` |
| `SENTINELAI_RECEIVER_TLS_CLIENT_KEYFILE` | `receiver_tls_client_keyfile` |
| `SENTINELAI_EVTX_DIR` | Alternate EVTX source directory |

## Usage

Interactive menu (analysis, reports, settings, receiver):

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

Agent self-test (verifies connectivity and event delivery without a real event log):

```powershell
.\venv\Scripts\python.exe .\src\agent.py --receiver-server 192.168.56.1 --receiver-port 9000 --self-test
```

### Menu options

| Option | Description |
| --- | --- |
| 1 | Run a full analysis |
| 2 | View the most recent report |
| 3 | List all reports |
| 4 | View a specific report |
| 5 | Host risk score chart |
| 6 | Analysis history |
| 7 | Export the report to PDF |
| 8 | Settings |
| 9 | Log receiver server (network mode) |

## Lab Architecture

```text
┌─────────────────┐   signed JSONL over TLS   ┌──────────────────┐
│  Windows host   │ ────────────────────────► │  SentinelAI      │
│  (agent.exe)    │   HMAC-SHA256 per event   │  receiver (UI)   │
└─────────────────┘                           └────────┬─────────┘
                                                       │ JSONL corpus
                                                       ▼
                                              ┌──────────────────┐
                                              │  Offline analysis│
                                              │  reports / PDF   │
                                              └──────────────────┘
```

Typical lab flow:

1. Start the menu and open receiver mode with option `9`.
2. Start the receiver listener.
3. On the monitored Windows VM, run the agent pointing at the host IP.
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

## Tests and CI

Local run:

```powershell
.\venv\Scripts\python.exe -m pytest -q --cov=src --cov-report=term-missing .\src
```

CI runs the same suite on every push and pull request via GitHub Actions (`windows-latest`, Python 3.11).

## Building the Agent

```powershell
.\venv\Scripts\python.exe -m PyInstaller agent.spec --noconfirm
```

The executable is written to `dist/`, which is ignored by git and must not be committed.

## Author

**Rodrigo Henriques**
