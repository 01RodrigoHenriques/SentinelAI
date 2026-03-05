# SentinelAI

> Motor de Analise Comportamental com IA para Logs de Seguranca

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-yellow)
![License](https://img.shields.io/badge/License-MIT-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Tests](https://img.shields.io/badge/Testes-37%20passed-brightgreen)

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

- Analisar logs de seguranca em formato Windows (Sysmon/EVTX) e Linux (auditd)
- Construir um baseline de comportamento normal e identificar desvios
- Correlacionar sequencias de eventos suspeitos em janelas temporais
- Calcular um score de risco individual por host (0-100)
- Gerar relatorios tecnicos com mapeamento MITRE ATT&CK
- Apoiar equipas SOC na investigacao e triagem de incidentes

---

## Arquitetura

```
Logs (JSONL / EVTX / CSV)
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
+--------------------------------------------+
```

---

## Estrutura do Projeto

```
SentinelAI/
|
+-- sentinel.py          # Motor principal
+-- parser.py            # Ingestao e parsing de logs
+-- train.py             # Treino do modelo ML
+-- correlator.py        # Motor de correlacao de eventos
+-- host_scorer.py       # Score de risco por host
+-- report_writer.py     # Gerador de relatorios TXT
+-- test_sentinel.py     # Testes unitarios (pytest)
|
+-- models/
|   +-- security_model.pkl   # Modelo treinado (RandomForest)
|   +-- vectorizer.pkl        # Vetorizador TF-IDF
|
+-- logs/
|   +-- normal/              # Logs de comportamento normal
|   |   +-- windows/
|   |   +-- linux/
|   +-- attack/              # Logs de ataques simulados
|       +-- persistence/
|       +-- execution/
|       +-- lateral_movement/
|       +-- credential_access/
|
+-- output/
|   +-- reports/             # Relatorios JSON + TXT gerados
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
source venv/bin/activate   # Linux/Mac
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
# Executar analise completa
python sentinel.py

# Treinar o modelo ML
python train.py

# Correr testes unitarios
python -m pytest test_sentinel.py -v
```

Exemplo de output em consola:

```
[1] A analisar logs de ataque (Motor de Regras)...
    [CRITICAL] Dump de Credenciais (R006) - 18 ocorrencias em 5 hosts
    [CRITICAL] Reverse Shell Linux (R008) - 29 ocorrencias em 5 hosts

[2] A analisar comportamento anomalo (Motor de Anomalias)...
    Anomaly Score: 0.19 | MALICIOSO (99%) [PowerShell EncodedCommand]

[3] A correlacionar eventos (Motor de Correlacao)...
    [CRITICAL] Comprometimento Total de Host Windows (C001) - 5 hosts
    [CRITICAL] Backdoor Linux Completo (C005) - 5 hosts
    Total de cadeias detetadas: 28

[4] A calcular score de risco por host...
    DESKTOP-ABC123    100/100   CRITICO   7 alertas   5 cadeias
    db-server          84/100   CRITICO   2 alertas   1 cadeia

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
| R008 | Reverse Shell Linux (/dev/tcp, nc -e) | CRITICAL |
| R009 | Leitura de Ficheiros de Credenciais Linux | HIGH |

### Motor de Anomalias

Detecao de comportamento anomalo sem assinaturas previas:

- **Isolation Forest** — detecao de outliers por comprimento, entropia e numero de argumentos
- **RandomForest** — classificador treinado com 440 amostras (normal vs malicioso)
- **Entropia de Shannon** — identificacao de comandos ofuscados ou codificados em base64
- Deduplicacao automatica para evitar analises redundantes

### Motor de Correlacao

Identificacao de cadeias de ataque multi-evento com base no framework MITRE ATT&CK:

| Cadeia | Descricao | Risk Score |
|--------|-----------|------------|
| C001 | Comprometimento Total Windows (PS + Mimikatz + Persistencia) | 95/100 |
| C002 | Movimento Lateral Apos Roubo de Credenciais | 90/100 |
| C003 | Persistencia Apos Execucao LOLBin | 80/100 |
| C004 | Persistencia Apos Execucao PowerShell | 82/100 |
| C005 | Backdoor Linux Completo (Reverse Shell + Credential Read) | 95/100 |
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

Cada execucao gera automaticamente dois ficheiros em `output/reports/`:

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

**TXT** — legivel para analistas e orientadores, com sumario executivo, tabela de hosts, alertas ordenados por severidade, cadeias agrupadas por tipo e acoes recomendadas.

---

## Testes

```bash
python -m pytest test_sentinel.py -v
# 37 passed in 2.83s
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

Os logs de ataque utilizados para treino e validacao provem do **[OTRF Security Datasets](https://github.com/OTRF/Security-Datasets)** — ficheiros de ataques simulados organizados por tecnica MITRE ATT&CK, convertidos para formato JSONL.

Dataset sintetico gerado para desenvolvimento:

- 280 eventos de ataque (credential access, execution, lateral movement, persistence)
- 160 eventos normais (Windows + Linux)
- 440 eventos no total

---

## Roadmap

| Fase | Descricao | Estado |
|------|-----------|--------|
| 1 | Parser + Normalizacao de logs | Concluido |
| 2 | Motor de Regras (9 regras) | Concluido |
| 3 | Motor de Anomalias (Isolation Forest + ML) | Concluido |
| 4 | Treino do modelo de classificacao | Concluido |
| 5 | Motor de Correlacao (6 cadeias MITRE) | Concluido |
| 6 | Score de Risco por Host | Concluido |
| 7 | Integracao Ollama + Fallback inteligente | Concluido |
| 8 | Relatorios JSON + TXT | Concluido |
| 9 | Testes Unitarios (37 testes) | Concluido |
| 10 | Validacao com logs reais | Em progresso |
| 11 | Compilacao para executavel (.exe) | Pendente |

---

## Tecnologias

| Tecnologia | Uso |
|-----------|-----|
| Python 3.10+ | Linguagem principal |
| scikit-learn | Isolation Forest, RandomForest, TF-IDF |
| pandas / numpy | Processamento de dados |
| Ollama + Mistral | IA local para explicabilidade |
| pytest | Testes unitarios |
| MITRE ATT&CK | Framework de referencia |
| OTRF Security Datasets | Dados de treino |

---

## Licenca

MIT License — ver [LICENSE](LICENSE) para detalhes.

---

*Projeto academico desenvolvido no ambito de estagio curricular.*
