# 🛡️ SentinelAI 🛡️
### Motor de Análise Comportamental com IA para Logs de Segurança

SentinelAI é um sistema de análise comportamental de logs de segurança focado na deteção de padrões suspeitos através de uma abordagem híbrida:

- Regras determinísticas  
- Análise de anomalias  
- Correlação de eventos  
- Inteligência Artificial para explicação técnica estruturada  

O objetivo não é apenas detetar eventos isolados, mas identificar cadeias comportamentais associadas a atividade maliciosa, como persistência, execução suspeita de comandos ou movimento lateral.

---

## 📌 Índice

- [Objetivo](#-objetivo)
- [Arquitetura](#-arquitetura)
- [Pipeline de Processamento](#-pipeline-de-processamento)
- [Fontes de Logs](#-fontes-de-logs)
- [Modelo de Deteção](#-modelo-de-deteção)
- [Explicabilidade com IA](#-explicabilidade-com-ia)
- [Estrutura do Projeto](#-estrutura-inicial-do-projeto)
- [Roadmap](#-roadmap)
- [Tecnologias](#-tecnologias-previstas)
- [Estado Atual](#-estado)

---

## 🎯 Objetivo

Criar um sistema capaz de:

- Analisar logs de segurança (Windows/Linux)
- Construir um baseline de comportamento normal
- Identificar desvios comportamentais
- Correlacionar cadeias de eventos
- Produzir scoring de risco
- Gerar relatórios técnicos estruturados
- Apoiar equipas SOC na investigação

---

## 🧠 Arquitetura

### Visão Geral (descrição textual)

1. **Fontes de Logs**
   - Sysmon
   - Windows Security Log
   - PowerShell Operational
   - Linux Auditd
   - Exportações de SIEM / EDR

2. **Ingestão**
   - Collector (File / Agent / API)
   - Parser / Decoder (EVTX → JSON, CSV → JSON)

3. **Normalização**
   - Conversão para schema comum
   - Deduplicação
   - Ordenação temporal
   - Armazenamento raw imutável

4. **Enriquecimento**
   - Construção de contexto (host, utilizador, sessão)
   - Extração de features (processo, rede, ficheiros, registo)
   - Agregação temporal por janelas

5. **Deteção Híbrida**
   - Motor de Regras
   - Motor de Anomalias
   - Motor de Correlação

6. **Priorização**
   - Risk scoring
   - Seleção de evidências

7. **Explicabilidade**
   - Interpretação técnica via LLM
   - Mapeamento MITRE ATT&CK
   - Geração de relatório

---

## 🔄 Pipeline de Processamento

1. Ingestão de logs
2. Parsing e normalização
3. Armazenamento raw (imutável)
4. Extração de features
5. Construção de contexto
6. Agregação temporal
7. Deteção (regras + anomalias + correlação)
8. Cálculo de score de risco
9. Geração de explicação técnica
10. Produção de alerta e relatório

---

## 🔎 Fontes de Logs

### Windows
- Sysmon
- Security Log
- PowerShell Operational

### Linux
- Auditd
- Syslog

### Outras
- Exportações de SIEM
- Dados EDR
- JSON estruturado

---

## 🧩 Modelo de Deteção

### 1) Motor de Regras

Deteções baseadas em padrões conhecidos:

- Execução suspeita de PowerShell
- LOLBins (rundll32, mshta, certutil)
- Criação de scheduled tasks
- Alterações a chaves de persistência
- Conexões externas suspeitas

### 2) Motor de Anomalias

Baseado em baseline comportamental:

- Isolation Forest
- LOF
- One-Class SVM
- Estatística simples (Z-score, percentis)

Baseline pode ser definido por:

- Host
- Utilizador
- Perfil
- Janela temporal

### 3) Motor de Correlação

Identificação de padrões multi-evento, por exemplo:

- Processo suspeito → Conexão externa → Persistência
- Logon remoto → Execução administrativa → Dump de credenciais
- Execução rara → Movimento lateral

---

## 🤖 Explicabilidade com IA

Após deteção:

1. O sistema seleciona as evidências mais relevantes
2. Organiza o contexto técnico
3. Envia dados estruturados para o modelo
4. Gera:
   - Resumo técnico
   - Mapeamento MITRE ATT&CK
   - Avaliação de risco
   - Hipóteses de ataque
   - Próximos passos de investigação

### Exemplo de saída JSON

```json
{
  "risk_score": 82,
  "tactic": "Persistence",
  "technique": "T1053 - Scheduled Task",
  "summary": "Criação de tarefa agendada após execução suspeita de PowerShell",
  "confidence": 0.87
}
