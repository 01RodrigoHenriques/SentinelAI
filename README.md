# SentinelAI

> Motor de Analise Comportamental com IA para Logs de Seguranca Windows

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-yellow)
![License](https://img.shields.io/badge/License-MIT-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Tests](https://img.shields.io/badge/Testes-37%20passed-brightgreen)
![Model](https://img.shields.io/badge/Modelo-93%25%20accuracy-brightgreen)

SentinelAI e um sistema de analise comportamental de logs de seguranca focado na detecao de padroes suspeitos atraves de uma abordagem hibrida: **regras deterministicas**, **analise de anomalias com Machine Learning**, **correlacao temporal de eventos** e **IA local** para producao de relatorios tecnicos estruturados.

O objetivo nao e apenas detetar eventos isolados, mas identificar **cadeias comportamentais** associadas a atividade maliciosa — como movimentos laterais, dump de credenciais, execucao suspeita de codigo ou persistencia no sistema.

---

## Indice

- [Objetivo](#objetivo)
- [Arquitetura](#arquitetura)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Instalacao](#instalacao)
- [Utilizacao](#utilizacao)
- [Motores de Detecao](#motores-de-detecao)
- [Score de Risco por Host](#score-de-risco-por-host)
- [Correlacao de Eventos](#correlacao-de-eventos)
- [Explicabilidade com IA](#explicabilidade-com-ia)
- [Relatorios](#relatorios)
- [Testes](#testes)
- [Datasets](#datasets)
- [Roadmap](#roadmap)
- [Tecnologias](#tecnologias)

---

## Objetivo

Desenvolver um sistema capaz de:

- Analisar logs de seguranca em formato Windows (Sysmon/EVTX)
- Construir um baseline de comportamento normal e identificar desvios
- Correlacionar sequencias de eventos suspeitos em janelas temporais
- Calcular um score de risco individual por host (0-100)
- Gerar relatorios tecnicos com mapeamento MITRE ATT&CK
- Apoiar equipas SOC na investigacao e triagem de incidentes

---

## Arquitetura

```
Logs (EVTX / JSONL)
         |
         v
+------------------+
|   parser.py      |  <- Ingestao, parsing e normalizacao
+--------+---------+
         |
         v
+--------------------------------------------+
|            Motor de Detecao               |
|  +------------+  +----------------------+ |
|  |  Regras    |  |  Anomalias (ML)      | |
|  | (9 regras) |  |  Isolation Forest +  | |
|  |            |  |  RandomForest        | |
|  +------------+  +----------------------+ |
|         +-------------------+             |
|         |   Correlacao      |             |
|         |  (6 cadeias MITRE)|             |
|         +-------------------+             |
+--------------------+-----------------------+
                     |
                     v
+--------------------------------------------+
|         Score de Risco por Host            |
|         Ranking 0-100 por host             |
+--------------------+-----------------------+
                     |
                     v
+--------------------------------------------+
|         Analise Global com IA              |
|         Ollama + Mistral (local)           |
|         Fallback inteligente               |
+--------------------------------------------+
                     |
                     v
+--------------------------------------------+
|         Relatorios                         |
|         report_TIMESTAMP.json             |
|         report_TIMESTAMP.txt              |
|         report_TIMESTAMP.pdf              |
+--------------------------------------------+
```

---

## Estrutura do Projeto

```
SentinelAI/
|
+-- src/
|   +-- sentinel.py          # Motor principal
|   +-- parser.py            # Ingestao e parsing de logs
|   +-- train.py             # Treino do modelo ML (dados sinteticos)
|   +-- update_training.py   # Retreino com dados reais (EVTX)
|   +-- extract_training_data.py  # Extrator de CommandLines de EVTX
|   +-- correlator.py        # Motor de correlacao de eventos
|   +-- host_scorer.py       # Score de risco por host
|   +-- report_writer.py     # Gerador de relatorios TXT
|   +-- menu.py              # Interface interativa (terminal)
|   +-- test_sentinel.py     # Testes unitarios (pytest)
|
+-- models/
|   +-- security_model.pkl   # Modelo treinado (RandomForest)
|   +-- vectorizer.pkl       # Vetorizador char n-gram
|
+-- requirements.txt
+-- .gitignore
+-- README.md
```

---

## Instalacao

```bash
# Clonar o repositorio
git clone https://github.com/BolinaTec/SentinelAI.git
cd SentinelAI

# Criar ambiente virtual
python -m venv venv
venv\Scripts\activate      # Windows

# Instalar dependencias
pip install -r requirements.txt

# Instalar Ollama (IA local) - opcional
# https://ollama.com/download
ollama pull mistral
```

---

## Utilizacao

```bash
# Menu interativo (recomendado)
python src/menu.py

# Executar analise completa diretamente
python src/sentinel.py

# Retreinar modelo com dados reais
python src/extract_training_data.py
python src/update_training.py

# Correr testes unitarios
python -m pytest src/test_sentinel.py -v
```

Exemplo de output em consola:

```
[1] A analisar logs de ataque (Motor de Regras)...
    [CRITICAL] Dump de Credenciais (R006) - 18 ocorrencias em 5 hosts
    [HIGH]     PowerShell Suspeito (R004) - 12 ocorrencias em 3 hosts

[2] A analisar comportamento anomalo (Motor de Anomalias)...
    Anomaly Score: 0.19 | MALICIOSO (99%) [PowerShell EncodedCommand]

[3] A correlacionar eventos (Motor de Correlacao)...
    [CRITICAL] Comprometimento Total de Host Windows (C001) - 5 hosts
    Total de cadeias detetadas: 28

[4] A calcular score de risco por host...
    DESKTOP-ABC123    100/100   CRITICO   7 alertas   5 cadeias

[5] A gerar analise global com IA...
    Risk Score Global: 95/100 (CRITICO)
```

---

## Motores de Detecao

### Motor de Regras

Detecoes baseadas em padroes conhecidos (9 regras implementadas):

| Regra | Descricao | Severidade |
|-------|-----------|------------|
| R001 | Persistencia via Chave Run | HIGH |
| R002 | Criacao de Scheduled Task | HIGH |
| R003 | LOLBin Detetado (rundll32, certutil, mshta...) | MEDIUM |
| R004 | PowerShell Suspeito (encoded, bypass, hidden) | HIGH |
| R005 | Adicao de Utilizador ao Sistema | CRITICAL |
| R006 | Dump de Credenciais (mimikatz, lsass) | CRITICAL |
| R007 | Movimento Lateral via WMI ou PsExec | HIGH |
| R008 | Reverse Shell (/dev/tcp, nc -e) | CRITICAL |
| R009 | Leitura de Ficheiros de Credenciais | HIGH |

### Motor de Anomalias

Detecao de comportamento anomalo sem assinaturas previas:

- **Isolation Forest** — detecao de outliers por comprimento, entropia e numero de argumentos
- **RandomForest** — classificador treinado com dados reais (93% accuracy, F1: 0.862)
- **Entropia de Shannon** — identificacao de comandos ofuscados ou codificados em base64
- **Hard Rules** — 12 regras de alta certeza aplicadas antes do modelo ML

### Motor de Correlacao

Identificacao de cadeias de ataque multi-evento com base no framework MITRE ATT&CK:

| Cadeia | Descricao | Risk Score |
|--------|-----------|------------|
| C001 | Comprometimento Total Windows (PS + Mimikatz + Persistencia) | 95/100 |
| C002 | Movimento Lateral Apos Roubo de Credenciais | 90/100 |
| C003 | Persistencia Apos Execucao LOLBin | 80/100 |
| C004 | Persistencia Apos Execucao PowerShell | 82/100 |
| C005 | Backdoor Completo (Reverse Shell + Credential Read) | 95/100 |
| C006 | Criacao de Conta e Persistencia | 92/100 |

---

## Score de Risco por Host

Cada host recebe um score individual (0-100) calculado com base em:

- Peso dos alertas por severidade (CRITICAL: 30pts, HIGH: 15pts, MEDIUM: 5pts)
- Peso das cadeias de ataque detetadas (CRITICAL: 25pts, HIGH: 12pts)
- Nivel de risco: CRITICO (>=80), ALTO (>=55), MEDIO (>=30), BAIXO (<30)

---

## Explicabilidade com IA

Apos toda a analise, e feita uma unica chamada ao modelo **Mistral** via Ollama local que produz:

- Resumo executivo do incidente
- Hipotese de ataque narrativa
- Mapeamento MITRE ATT&CK (taticas e tecnicas)
- Hosts criticos ordenados por risco
- Acoes imediatas recomendadas

Em caso de timeout ou indisponibilidade do Ollama, o sistema usa um **fallback inteligente** que calcula todos os campos automaticamente a partir dos dados reais.

> Totalmente local — sem APIs externas, sem custos, sem envio de dados.

---

## Relatorios

Cada execucao gera automaticamente tres ficheiros em `output/reports/`:

**JSON** — estruturado para integracao com outras ferramentas:

```json
{
  "timestamp": "20260305_104650",
  "total_alerts": 10,
  "total_chains": 28,
  "total_hosts": 10,
  "ai_analysis": { ... },
  "host_scores": { ... },
  "alerts": [ ... ],
  "attack_chains": [ ... ]
}
```

**TXT** — legivel para analistas e orientadores, com sumario executivo, tabela de hosts, alertas ordenados por severidade e acoes recomendadas.

**PDF** — relatorio profissional exportavel diretamente pelo menu interativo.

---

## Testes

```bash
python -m pytest src/test_sentinel.py -v
# 37 passed in 4.00s
```

Cobertura de testes:

| Classe | Testes | Descricao |
|--------|--------|-----------|
| TestMotorDeRegras | 23 | Positivo + negativo por cada regra |
| TestMotorDeCorrelacao | 7 | Cadeia completa, incompleta, ordem diferente |
| TestHostScorer | 5 | Scoring, limites, multiplos hosts |
| TestReportWriter | 3 | Criacao de ficheiro, seccoes, dados reais |

---

## Datasets

O modelo ML foi treinado com dados reais extraidos do **[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)** — ficheiros Windows Event Log (.evtx) com ataques reais etiquetados por tecnica MITRE ATT&CK.

| Fonte | Tipo | Amostras |
|-------|------|----------|
| EVTX-ATTACK-SAMPLES | Maliciosos reais (EVTX) | 302 |
| Dados sinteticos | Normais + Maliciosos base | 117 |
| **Total** | | **419** |

Metricas do modelo (RandomForest, 300 estimadores):

| Metrica | Normal | Malicioso |
|---------|--------|-----------|
| Precision | 0.82 | 0.97 |
| Recall | 0.90 | 0.94 |
| F1-Score | 0.86 | 0.95 |
| **Accuracy** | | **93%** |

---

## Roadmap

| Fase | Descricao | Estado |
|------|-----------|--------|
| 1 | Parser + Normalizacao de logs | Concluido |
| 2 | Motor de Regras (9 regras) | Concluido |
| 3 | Motor de Anomalias (Isolation Forest + ML) | Concluido |
| 4 | Treino do modelo com dados sinteticos | Concluido |
| 5 | Motor de Correlacao (6 cadeias MITRE) | Concluido |
| 6 | Score de Risco por Host | Concluido |
| 7 | Integracao Ollama + Fallback inteligente | Concluido |
| 8 | Relatorios JSON + TXT + PDF | Concluido |
| 9 | Testes Unitarios (37 testes) | Concluido |
| 10 | Menu interativo com splash screen | Concluido |
| 11 | Retreino com dados reais (EVTX-ATTACK-SAMPLES) | Concluido |
| 12 | Compilacao para executavel (.exe) | Concluido |
| 13 | Validacao com logs de ambiente real | Em progresso |

---

## Tecnologias

| Tecnologia | Uso |
|-----------|-----|
| Python 3.10+ | Linguagem principal |
| scikit-learn | Isolation Forest, RandomForest |
| pandas / numpy | Processamento de dados |
| Ollama + Mistral | IA local para explicabilidade |
| python-evtx | Parsing de Windows Event Logs |
| reportlab | Exportacao de relatorios PDF |
| rich | Interface terminal interativa |
| pytest | Testes unitarios |
| MITRE ATT&CK | Framework de referencia |
| EVTX-ATTACK-SAMPLES | Dados de treino reais |

---

## Licenca

MIT License — ver [LICENSE](LICENSE) para detalhes.

---

*Projeto academico desenvolvido no ambito de estagio curricular.*
