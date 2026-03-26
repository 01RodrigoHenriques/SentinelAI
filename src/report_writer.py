# report_writer.py
# SentinelAI - Gerador de Relatorio Legivel em .txt

from datetime import datetime

def generate_txt_report(
    all_alerts:   list,
    correlations: list,
    host_scores:  dict,
    ai_analysis:  dict,
    output_path:  str
):
    lines = []

    def ln(text=""):
        lines.append(text)

    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # --------------------------------------------------------
    # CABECALHO
    # --------------------------------------------------------
    ln("=" * 64)
    ln("   SENTINELAI - RELATORIO DE SEGURANCA")
    ln(f"   Gerado em: {now}")
    ln("=" * 64)

    # --------------------------------------------------------
    # SUMARIO EXECUTIVO
    # --------------------------------------------------------
    ln()
    ln("SUMARIO EXECUTIVO")
    ln("-" * 64)
    risk   = ai_analysis.get("risk_score_global", 0)
    nivel  = ai_analysis.get("nivel_ameaca", "N/A")
    criticos_hosts = sum(1 for d in host_scores.values() if d["nivel"] == "CRITICO")

    ln(f"  Nivel de Ameaca    : {nivel}")
    ln(f"  Risk Score Global  : {risk}/100")
    ln(f"  Alertas Detetados  : {len(all_alerts)}")
    ln(f"  Cadeias de Ataque  : {len(correlations)}")
    ln(f"  Hosts Analisados   : {len(host_scores)}")
    ln(f"  Hosts Criticos     : {criticos_hosts}")
    ln()
    ln(f"  {ai_analysis.get('resumo_executivo', 'N/A')}")
    ln()
    ln(f"  Hipotese de Ataque:")
    ln(f"  {ai_analysis.get('hipotese_ataque', 'N/A')}")

    # --------------------------------------------------------
    # SCORE DE RISCO POR HOST
    # --------------------------------------------------------
    ln()
    ln()
    ln("SCORE DE RISCO POR HOST")
    ln("-" * 64)
    ln(f"  {'HOST':<25} {'SCORE':<10} {'NIVEL':<10} {'ALERTAS':<10} {'CADEIAS'}")
    ln(f"  {'-'*25} {'-'*9} {'-'*9} {'-'*9} {'-'*7}")

    sorted_hosts = sorted(host_scores.items(), key=lambda x: -x[1]["score"])
    for host, data in sorted_hosts:
        ln(f"  {host:<25} {data['score']:<3}/100    {data['nivel']:<10} {data['total_alertas']:<10} {data['total_cadeias']}")

    # --------------------------------------------------------
    # ALERTAS DETETADOS
    # --------------------------------------------------------
    ln()
    ln()
    ln("ALERTAS DETETADOS")
    ln("-" * 64)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_alerts = sorted(all_alerts, key=lambda a: severity_order.get(a.get("severity", "LOW"), 99))

    for alert in sorted_alerts:
        sev   = alert.get("severity", "N/A")
        name  = alert.get("rule_name", "Anomalia ML")
        rule  = alert.get("rule", "")
        occ   = alert.get("occurrences", 1)
        hosts = alert.get("hosts", [])

        sample  = alert.get("sample_event", {})
        exemplo = sample.get("CommandLine", sample.get("TargetObject", alert.get("command", "N/A")))

        ln()
        ln(f"  [{sev}] {name} ({rule})")
        ln(f"  Ocorrencias : {occ}")
        ln(f"  Hosts       : {', '.join(hosts[:5])}")
        ln(f"  Exemplo     : {str(exemplo)[:80]}")

    # --------------------------------------------------------
    # CADEIAS DE ATAQUE
    # --------------------------------------------------------
    ln()
    ln()
    ln("CADEIAS DE ATAQUE DETETADAS")
    ln("-" * 64)

    if not correlations:
        ln("  Nenhuma cadeia de ataque detetada.")
    else:
        # Agrupar por cadeia para nao repetir descricao
        chains_by_id = {}
        for c in correlations:
            cid = c.get("chain_id", "?")
            chains_by_id.setdefault(cid, []).append(c)

        for chain_id, instances in sorted(chains_by_id.items()):
            first   = instances[0]
            name    = first.get("chain_name", "N/A")
            sev     = first.get("severity", "N/A")
            tactic  = first.get("mitre_tactic", "N/A")
            risk_c  = first.get("risk_score", 0)
            hosts_c = [i.get("host") for i in instances]
            sequence = first.get("steps") or first.get("sequence", [])
            sequence_str = " -> ".join(
                f"{step.get('rule_name', '?')} [{step.get('timestamp', 'N/A')[:19] if step.get('timestamp') else 'N/A'}]"
                for step in sequence
            )

            ln()
            ln(f"  [{sev}] {name} ({chain_id})")
            ln(f"  Tatica      : {tactic}")
            ln(f"  Risk Score  : {risk_c}/100")
            ln(f"  Hosts       : {', '.join(hosts_c)}")
            ln(f"  Sequencia   : {sequence_str or 'N/A'}")

    # --------------------------------------------------------
    # TECNICAS MITRE ATT&CK
    # --------------------------------------------------------
    ln()
    ln()
    ln("TECNICAS MITRE ATT&CK IDENTIFICADAS")
    ln("-" * 64)
    for t in ai_analysis.get("tecnicas_mitre", []):
        ln(f"  - {t}")

    # --------------------------------------------------------
    # ACOES RECOMENDADAS
    # --------------------------------------------------------
    ln()
    ln()
    ln("ACOES IMEDIATAS RECOMENDADAS")
    ln("-" * 64)
    for i, acao in enumerate(ai_analysis.get("acoes_imediatas", []), 1):
        ln(f"  {i}. {acao}")

    # --------------------------------------------------------
    # RODAPE
    # --------------------------------------------------------
    ln()
    ln()
    ln("=" * 64)
    ln("   SentinelAI - Motor de Analise Comportamental")
    ln("   Relatorio gerado automaticamente. Uso interno.")
    ln("=" * 64)

    # Escrever ficheiro
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"  [+] Relatorio TXT guardado em: {output_path}")
