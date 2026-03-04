# 🛡️ SentinelAI 🛡️

> Motor de Análise Comportamental com IA para Logs de Segurança

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-yellow)
![License](https://img.shields.io/badge/License-MIT-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)

SentinelAI é um sistema de análise comportamental de logs de segurança focado na deteção de padrões suspeitos através de uma abordagem híbrida: **regras determinísticas**, **análise de anomalias**, **correlação de eventos** e **IA local** para explicação técnica estruturada.

O objetivo não é apenas detetar eventos isolados, mas identificar **cadeias comportamentais** associadas a atividade maliciosa — como persistência, execução suspeita de comandos ou movimento lateral.

---

## 📌 Índice

- [Objetivo](#-objetivo)
- [Arquitetura](#-arquitetura)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Instalação](#-instalação)
- [Utilização](#-utilização)
- [Modelo de Deteção](#-modelo-de-deteção)
- [Explicabilidade com IA](#-explicabilidade-com-ia-ollama)
- [Datasets](#-datasets)
- [Roadmap](#-roadmap)
- [Tecnologias](#-tecnologias)

---

## 🎯 Objetivo

Criar um sistema capaz de:

- Analisar logs de segurança (Windows/Linux)
- Construir um baseline de comportamento normal
- Identificar desvios comportamentais
- Correlacionar cadeias de eventos
- Produzir scoring de risco (0-100)
- Gerar relatórios técnicos estruturados com mapeamento MITRE ATT&CK
- Apoiar equipas SOC na investigação de incidentes

---

## 🧠 Arquitetura

```
Logs (.evtx / .csv / .json)
        │
        ▼
┌──────────────────┐
│   parser.py      │  ← Ingestão + Parsing (EVTX → JSON)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Normalização    │  ← Schema comum, deduplicação, ordenação temporal
└────────┬─────────┘
         │
         ▼
┌────────────────────────────────────┐
│         Motor de Deteção           │
│  ┌──────────┐  ┌───────────────┐   │
│  │  Regras  │  │   Anomalias   │   │
│  └──────────┘  └───────────────┘   │
│         ┌──────────────┐           │
│         │  Correlação  │           │
│         └──────────────┘           │
└────────────────┬───────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│         Risk Scoring             │  ← Score 0-100
└────────────────┬─────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│    Explicabilidade (Ollama)      │  ← Mistral local
│    Mapeamento MITRE ATT&CK       │
│    Relatório JSON estruturado    │
└──────────────────────────────────┘
```

---

## 📁 Estrutura do Projeto

```
SentinelAI/
│
├── src/
│   ├── parser.py          # Ingestão e parsing de ficheiros .evtx
│   ├── sentinel.py        # Motor principal (regras + anomalias)
│   └── train.py           # Treino do modelo de classificação
│
├── models/
│   ├── security_model.pkl # Modelo treinado (RandomForest)
│   └── vectorizer.pkl     # Vetorizador de texto
│
├── logs/
│   ├── normal/            # Logs de comportamento normal
│   └── attack/            # Logs de ataques (OTRF Security Datasets)
│       ├── persistence/
│       ├── execution/
│       ├── lateral_movement/
│       └── credential_access/
│
├── output/
│   └── reports/           # Relatórios JSON gerados
│
├── tests/
│   └── test_parser.py     # Testes unitários
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Instalação

```bash
# Clonar o repositório
git clone https://github.com/BolinaTec/SentinelAI.git
cd SentinelAI

# Criar ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Instalar dependências
pip install -r requirements.txt

# Instalar Ollama (IA local)
# https://ollama.com/download
ollama pull mistral
```

---

## 🚀 Utilização

```bash
# Analisar logs
python src/sentinel.py

# Treinar o modelo
python src/train.py

# Exemplo de output
{
  "risk_score": 82,
  "tactic": "Persistence",
  "technique": "T1053 - Scheduled Task",
  "summary": "Criação de tarefa agendada após execução suspeita de PowerShell",
  "confidence": 0.87,
  "next_steps": ["Isolar o host", "Verificar processos filhos", "Rever logs de rede"]
}
```

---

## 🧩 Modelo de Deteção

### 1) Motor de Regras
Deteções baseadas em padrões conhecidos:
- Execução suspeita de PowerShell (encoded commands, bypass flags)
- LOLBins: `rundll32`, `mshta`, `certutil`, `regsvr32`
- Criação de Scheduled Tasks
- Alterações a chaves de persistência (`Run`, `RunOnce`)
- Conexões externas suspeitas

### 2) Motor de Anomalias
Baseado em baseline comportamental com:
- **Isolation Forest** — deteção de outliers
- **Entropia de Shannon** — deteção de comandos ofuscados
- Análise de comprimento e complexidade de CommandLines

### 3) Motor de Correlação *(em desenvolvimento)*
Identificação de padrões multi-evento:
- `Processo suspeito → Conexão externa → Persistência`
- `Logon remoto → Execução administrativa → Dump de credenciais`

---

## 🤖 Explicabilidade com IA (Ollama)

Após deteção, o sistema envia o contexto para um modelo **Mistral** local via Ollama e gera:

- Resumo técnico do incidente
- Mapeamento MITRE ATT&CK (tática + técnica)
- Score de risco (0-100)
- Hipóteses de ataque
- Próximos passos de investigação

> ⚡ Totalmente local — sem APIs externas, sem custos, sem envio de dados.

---

## 📊 Datasets

Os logs de ataque utilizados para treino provêm do **[OTRF Security Datasets](https://github.com/OTRF/Security-Datasets)** — ficheiros `.evtx` de ataques simulados, organizados por técnica MITRE ATT&CK.

---

## 🗺️ Roadmap

Ver [GitHub Projects](../../projects) para o estado atual do desenvolvimento.

| Fase | Descrição | Estado |
|------|-----------|--------|
| 1 | Parser EVTX + Normalização | ✅ Concluído |
| 2 | Motor de Regras | ✅ Concluído |
| 3 | Motor de Anomalias (Isolation Forest) | ✅ Concluído |
| 4 | Treino do modelo de classificação | 🔄 Em progresso |
| 5 | Integração Ollama (Mistral local) | 🔄 Em progresso |
| 6 | Motor de Correlação | 📋 Planeado |
| 7 | Output JSON estruturado + Relatórios | 📋 Planeado |
| 8 | Interface CLI interativa | 📋 Planeado |

---

## 🛠️ Tecnologias

| Tecnologia | Uso |
|-----------|-----|
| Python 3.10+ | Linguagem principal |
| scikit-learn | Isolation Forest, RandomForest |
| pandas / numpy | Processamento de dados |
| python-evtx | Parsing de ficheiros .evtx |
| Ollama + Mistral | IA local para explicabilidade |
| MITRE ATT&CK | Framework de referência |
| OTRF Security Datasets | Dados de treino |

---

## 📄 Licença

MIT License — ver [LICENSE](LICENSE) para detalhes.

---

*Projeto académico desenvolvido no âmbito de estágio curricular.*
