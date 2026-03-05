# menu.py
# SentinelAI - Menu Interativo
# pip install rich reportlab

import os
import sys
import json
import glob
import time
import threading

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich import box
from rich.rule import Rule
from rich.align import Align

console = Console()

VERSION = "v1.1.0"

# ============================================================
# BASE DIR - Funciona tanto como .py como .exe compilado
# ============================================================

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH  = os.path.join(BASE_DIR, "sentinelai.config.json")
OUTPUT_DIR   = os.path.join(BASE_DIR, "output", "reports")
HISTORY_PATH = os.path.join(BASE_DIR, "output", "history.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

# ============================================================
# CONFIG FILE
# ============================================================

DEFAULT_CONFIG = {
    "logs_folder":   os.path.join(BASE_DIR, "logs"),
    "output_folder": OUTPUT_DIR,
    "notifications": True,
}

def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                cfg.setdefault(k, v)
            return cfg
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(cfg: dict):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

config = load_config()

# ============================================================
# HISTORICO DE ANALISES
# ============================================================

def load_history() -> list:
    if os.path.exists(HISTORY_PATH):
        try:
            with open(HISTORY_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def append_history(report: dict, path: str):
    history = load_history()
    entry = {
        "timestamp":    report.get("timestamp", ""),
        "path":         path,
        "total_alerts": report.get("total_alerts", 0),
        "total_chains": report.get("total_chains", 0),
        "total_hosts":  report.get("total_hosts",  0),
        "risk_score":   report.get("ai_analysis", {}).get("risk_score_global", 0),
        "nivel":        report.get("ai_analysis", {}).get("nivel_ameaca", "N/A"),
    }
    if not any(h["path"] == path for h in history):
        history.append(entry)
        os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
        with open(HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)

# ============================================================
# NOTIFICACAO WINDOWS
# ============================================================

def notify_windows(title: str, message: str):
    if not config.get("notifications", True):
        return
    try:
        from ctypes import windll
        def _show():
            windll.user32.MessageBoxW(0, message, title, 0x40)
        threading.Thread(target=_show, daemon=True).start()
    except Exception:
        pass

# ============================================================
# CORES / UTILITARIOS
# ============================================================

SEV_COLOR = {
    "CRITICAL": "bold red",
    "ALTO":     "bold red",
    "HIGH":     "orange1",
    "CRITICO":  "bold red",
    "MEDIO":    "yellow",
    "MEDIUM":   "yellow",
    "BAIXO":    "green",
    "LOW":      "green",
}

def risk_color(score: int) -> str:
    if score >= 80: return "bold red"
    if score >= 60: return "orange1"
    if score >= 40: return "yellow"
    return "green"

def cls():
    os.system("cls" if os.name == "nt" else "clear")

def wait_key():
    console.print()
    Prompt.ask("  [dim]Prima ENTER para continuar[/dim]", default="")

# ============================================================
# SPLASH SCREEN
# ============================================================

def show_splash():
    cls()
    lines = [
        "",
        "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗",
        "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║",
        "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║",
        "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║",
        "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║",
        "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝",
        "",
    ]
    for line in lines:
        console.print(line, style="bold blue")
    console.print(f"  {'Motor de Analise Comportamental com IA':^80}", style="dim cyan")
    console.print(f"  {VERSION:^80}", style="dim white")
    console.print()
    time.sleep(1.5)

# ============================================================
# CABECALHO + MENU
# ============================================================

def print_header():
    cls()
    title = Text()
    title.append("  SentinelAI  ", style="bold white on dark_blue")
    title.append(f"  {VERSION}", style="dim white")
    subtitle = Text("Motor de Analise Comportamental com IA", style="dim cyan")
    console.print()
    console.print(Align.center(Panel(
        Align.center(title),
        subtitle=str(subtitle),
        border_style="blue",
        width=60,
        padding=(0, 2),
    )))
    console.print()

def print_menu():
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Opcao", style="bold cyan", width=6)
    table.add_column("Descricao", style="white")
    table.add_row("[1]", "Executar analise completa")
    table.add_row("[2]", "Ver ultimo relatorio")
    table.add_row("[3]", "Listar todos os relatorios")
    table.add_row("[4]", "Ver relatorio especifico")
    table.add_row("[5]", "Grafico de risk scores")
    table.add_row("[6]", "Historico de analises")
    table.add_row("[7]", "Exportar relatorio em PDF")
    table.add_row("[8]", "Configuracoes")
    table.add_row("", "")
    table.add_row("[0]", "Sair")
    console.print(Align.center(table))
    console.print()

# ============================================================
# OPCAO 1 - EXECUTAR ANALISE
# ============================================================

def run_analysis():
    cls()
    console.print(Rule("[bold cyan]Analise Completa[/bold cyan]"))
    console.print()

    os.environ["SENTINELAI_LOGS_DIR"]   = config.get("logs_folder", "logs")
    os.environ["SENTINELAI_OUTPUT_DIR"] = config.get("output_folder", OUTPUT_DIR)

    try:
        from sentinel import main as sentinel_main
        sentinel_main()
    except Exception as e:
        console.print(f"\n  [bold red]Erro:[/bold red] {e}")
        wait_key()
        return

    # Registar no historico e notificar
    reports = sorted(glob.glob(os.path.join(config.get("output_folder", OUTPUT_DIR), "*.json")))
    if reports:
        try:
            with open(reports[-1], encoding="utf-8") as f:
                report = json.load(f)
            append_history(report, reports[-1])
            risk  = report.get("ai_analysis", {}).get("risk_score_global", 0)
            nivel = report.get("ai_analysis", {}).get("nivel_ameaca", "N/A")
            notify_windows(
                "SentinelAI - Analise Concluida",
                f"Risk Score: {risk}/100 ({nivel})\n"
                f"Alertas: {report.get('total_alerts', 0)} | "
                f"Cadeias: {report.get('total_chains', 0)}"
            )
        except Exception:
            pass

    wait_key()

# ============================================================
# OPCAO 2 - ULTIMO RELATORIO
# ============================================================

def show_last_report():
    out_dir = config.get("output_folder", OUTPUT_DIR)
    reports = sorted(glob.glob(os.path.join(out_dir, "*.json")))
    if not reports:
        cls()
        console.print(f"  [yellow]Nenhum relatorio encontrado em {out_dir}[/yellow]")
        wait_key()
        return
    cls()
    try:
        with open(reports[-1], encoding="utf-8") as f:
            report = json.load(f)
        _render_report(report, reports[-1])
    except Exception as e:
        console.print(f"  [red]Erro:[/red] {e}")
    wait_key()

# ============================================================
# OPCAO 3 - LISTAR RELATORIOS
# ============================================================

def list_reports():
    cls()
    console.print(Rule("[bold cyan]Relatorios Gerados[/bold cyan]"))
    console.print()
    out_dir = config.get("output_folder", OUTPUT_DIR)
    reports = sorted(glob.glob(os.path.join(out_dir, "*.json")), reverse=True)
    if not reports:
        console.print("  [yellow]Nenhum relatorio encontrado.[/yellow]")
        wait_key()
        return

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    table.add_column("#",          width=4,  justify="right")
    table.add_column("Ficheiro",   width=35)
    table.add_column("Alertas",    width=8,  justify="center")
    table.add_column("Cadeias",    width=8,  justify="center")
    table.add_column("Hosts",      width=8,  justify="center")
    table.add_column("Risk Score", width=14, justify="center")

    for i, path in enumerate(reports[:20], 1):
        fname = os.path.basename(path)
        try:
            with open(path, encoding="utf-8") as f:
                r = json.load(f)
            risk  = r.get("ai_analysis", {}).get("risk_score_global", 0)
            nivel = r.get("ai_analysis", {}).get("nivel_ameaca", "")
            risk_str = Text(f"{risk}/100 {nivel}", style=SEV_COLOR.get(nivel.upper(), "white"))
            table.add_row(str(i), fname,
                          str(r.get("total_alerts", "?")),
                          str(r.get("total_chains", "?")),
                          str(r.get("total_hosts",  "?")),
                          risk_str)
        except Exception:
            table.add_row(str(i), fname, "?", "?", "?", "?")

    console.print(table)
    wait_key()

# ============================================================
# OPCAO 4 - VER RELATORIO ESPECIFICO
# ============================================================

def view_specific_report():
    cls()
    console.print(Rule("[bold cyan]Ver Relatorio Especifico[/bold cyan]"))
    console.print()
    out_dir = config.get("output_folder", OUTPUT_DIR)
    reports = sorted(glob.glob(os.path.join(out_dir, "*.json")), reverse=True)
    if not reports:
        console.print("  [yellow]Nenhum relatorio encontrado.[/yellow]")
        wait_key()
        return

    for i, path in enumerate(reports[:10], 1):
        console.print(f"  [cyan]{i}[/cyan]  {os.path.basename(path)}")

    console.print()
    choice = Prompt.ask("  Numero do relatorio", default="1")
    try:
        idx  = int(choice) - 1
        path = reports[idx]
        cls()
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
        _render_report(report, path)
    except (ValueError, IndexError):
        console.print("  [red]Opcao invalida.[/red]")
    wait_key()

# ============================================================
# OPCAO 5 - GRAFICO DE RISK SCORES
# ============================================================

def show_risk_chart():
    cls()
    console.print(Rule("[bold cyan]Grafico de Risk Scores[/bold cyan]"))
    console.print()
    out_dir = config.get("output_folder", OUTPUT_DIR)
    reports = sorted(glob.glob(os.path.join(out_dir, "*.json")), reverse=True)[:15]

    if not reports:
        console.print("  [yellow]Nenhum relatorio encontrado.[/yellow]")
        wait_key()
        return

    data = []
    for path in reports:
        try:
            with open(path, encoding="utf-8") as f:
                r = json.load(f)
            ts    = r.get("timestamp", os.path.basename(path))
            score = int(r.get("ai_analysis", {}).get("risk_score_global", 0))
            nivel = r.get("ai_analysis", {}).get("nivel_ameaca", "N/A")
            data.append((ts, score, nivel))
        except Exception:
            pass

    if not data:
        console.print("  [yellow]Dados invalidos.[/yellow]")
        wait_key()
        return

    data.reverse()  # ordem cronologica

    BAR_WIDTH = 40
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 1))
    table.add_column("Data/Hora",  width=18)
    table.add_column("Score",      width=6,  justify="right")
    table.add_column("Nivel",      width=8)
    table.add_column("Barra",      width=BAR_WIDTH + 2)

    for ts, score, nivel in data:
        label  = ts[:16].replace("_", " ") if len(ts) >= 8 else ts
        color  = risk_color(score)
        filled = int(score / 100 * BAR_WIDTH)
        bar    = "█" * filled + "░" * (BAR_WIDTH - filled)
        table.add_row(
            label,
            Text(str(score), style=color),
            Text(nivel, style=SEV_COLOR.get(nivel.upper(), "white")),
            Text(bar, style=color),
        )

    console.print(table)

    scores = [s for _, s, _ in data]
    console.print()
    stats = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    stats.add_column("", style="dim cyan", width=12)
    stats.add_column("", style="white", width=10)
    stats.add_row("Media :",    f"{sum(scores)/len(scores):.1f}/100")
    stats.add_row("Maximo:",    f"{max(scores)}/100")
    stats.add_row("Minimo:",    f"{min(scores)}/100")
    stats.add_row("Analises:", str(len(scores)))
    console.print(Align.center(stats))
    wait_key()

# ============================================================
# OPCAO 6 - HISTORICO DE ANALISES
# ============================================================

def show_history():
    cls()
    console.print(Rule("[bold cyan]Historico de Analises[/bold cyan]"))
    console.print()

    history = load_history()
    if not history:
        console.print("  [yellow]Sem historico. Execute uma analise primeiro.[/yellow]")
        wait_key()
        return

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    table.add_column("#",         width=4,  justify="right")
    table.add_column("Data/Hora", width=18)
    table.add_column("Alertas",   width=8,  justify="center")
    table.add_column("Cadeias",   width=8,  justify="center")
    table.add_column("Hosts",     width=7,  justify="center")
    table.add_column("Score",     width=8,  justify="center")
    table.add_column("Nivel",     width=10, justify="center")
    table.add_column("Tendencia", width=12, justify="center")

    entries = list(reversed(history[-20:]))
    for i, entry in enumerate(entries, 1):
        score = entry.get("risk_score", 0)
        nivel = entry.get("nivel", "N/A")
        ts    = entry.get("timestamp", "")[:16].replace("_", " ")

        # Tendencia vs entrada seguinte (mais antiga)
        if i < len(entries):
            prev_score = entries[i].get("risk_score", 0)
            diff = score - prev_score
            if diff > 0:
                trend = Text(f"▲ +{diff}", style="bold red")
            elif diff < 0:
                trend = Text(f"▼ {diff}", style="bold green")
            else:
                trend = Text("= igual", style="dim yellow")
        else:
            trend = Text("--", style="dim")

        table.add_row(
            str(i), ts,
            str(entry.get("total_alerts", 0)),
            str(entry.get("total_chains", 0)),
            str(entry.get("total_hosts",  0)),
            Text(str(score), style=risk_color(score)),
            Text(nivel, style=SEV_COLOR.get(nivel.upper(), "white")),
            trend,
        )

    console.print(table)

    scores = [e.get("risk_score", 0) for e in history]
    if len(scores) >= 2:
        diff = scores[-1] - scores[-2]
        console.print()
        if diff > 0:
            console.print(f"  [bold red]Tendencia: risco a AUMENTAR (+{diff} vs analise anterior)[/bold red]")
        elif diff < 0:
            console.print(f"  [bold green]Tendencia: risco a DIMINUIR ({diff} vs analise anterior)[/bold green]")
        else:
            console.print("  [dim]Tendencia: sem alteracao vs analise anterior[/dim]")

    wait_key()

# ============================================================
# OPCAO 7 - EXPORTAR PDF
# ============================================================

def export_pdf():
    cls()
    console.print(Rule("[bold cyan]Exportar Relatorio em PDF[/bold cyan]"))
    console.print()
    out_dir = config.get("output_folder", OUTPUT_DIR)
    reports = sorted(glob.glob(os.path.join(out_dir, "*.json")), reverse=True)
    if not reports:
        console.print("  [yellow]Nenhum relatorio encontrado.[/yellow]")
        wait_key()
        return

    for i, path in enumerate(reports[:10], 1):
        console.print(f"  [cyan]{i}[/cyan]  {os.path.basename(path)}")

    console.print()
    choice = Prompt.ask("  Numero do relatorio para exportar", default="1")

    try:
        idx  = int(choice) - 1
        path = reports[idx]
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        console.print(f"  [red]Erro:[/red] {e}")
        wait_key()
        return

    pdf_path = path.replace(".json", ".pdf")
    console.print(f"\n  A gerar PDF...", end=" ")

    try:
        _generate_pdf(report, pdf_path)
        console.print("[bold green]OK[/bold green]")
        console.print(f"\n  [green]PDF guardado em:[/green] {pdf_path}")
    except ImportError:
        console.print("[red]ERRO[/red]")
        console.print("\n  [yellow]Biblioteca 'reportlab' nao instalada.[/yellow]")
        console.print("  Execute:  [bold cyan]pip install reportlab[/bold cyan]")
    except Exception as e:
        console.print(f"[red]ERRO: {e}[/red]")

    wait_key()

def _generate_pdf(report: dict, pdf_path: str):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table as RLTable, TableStyle, HRFlowable)

    doc    = SimpleDocTemplate(pdf_path, pagesize=A4,
                               rightMargin=2*cm, leftMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    title_style = ParagraphStyle("title", parent=styles["Title"],
                                 textColor=colors.HexColor("#1a3a6b"), fontSize=22, spaceAfter=4)
    sub_style   = ParagraphStyle("sub", parent=styles["Normal"],
                                 textColor=colors.grey, fontSize=10, spaceAfter=12)
    h2_style    = ParagraphStyle("h2", parent=styles["Heading2"],
                                 textColor=colors.HexColor("#1a3a6b"), fontSize=13, spaceBefore=14)
    body_style  = ParagraphStyle("body", parent=styles["Normal"], fontSize=10, leading=14)
    red_style   = ParagraphStyle("red", parent=body_style, textColor=colors.red)

    ai    = report.get("ai_analysis", {})
    hosts = report.get("host_scores", {})
    alerts= report.get("alerts", [])
    risk  = ai.get("risk_score_global", 0)
    nivel = ai.get("nivel_ameaca", "N/A")
    ts    = report.get("timestamp", "")[:16].replace("_", " ")

    # Titulo
    story.append(Paragraph("SentinelAI", title_style))
    story.append(Paragraph(f"Relatorio de Analise de Seguranca  |  {ts}", sub_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a3a6b")))
    story.append(Spacer(1, 0.3*cm))

    # Sumario
    score_color = "#c0392b" if risk >= 80 else "#e67e22" if risk >= 60 else "#f39c12" if risk >= 40 else "#27ae60"
    story.append(Paragraph("Sumario Executivo", h2_style))
    story.append(Paragraph(
        f"<b>Risk Score Global:</b> <font color='{score_color}'><b>{risk}/100 ({nivel})</b></font>",
        body_style))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f"<b>Alertas:</b> {report.get('total_alerts',0)}  |  "
        f"<b>Cadeias de Ataque:</b> {report.get('total_chains',0)}  |  "
        f"<b>Hosts Analisados:</b> {report.get('total_hosts',0)}", body_style))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(ai.get("resumo_executivo", "N/A"), body_style))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(f"<b>Hipotese de Ataque:</b> {ai.get('hipotese_ataque','N/A')}", body_style))

    # Hosts
    if hosts:
        story.append(Paragraph("Score de Risco por Host", h2_style))
        h_data = [["Host", "Score", "Nivel", "Alertas", "Cadeias"]]
        for host, data in sorted(hosts.items(), key=lambda x: -x[1].get("score", 0)):
            h_data.append([host, f"{data.get('score',0)}/100", data.get("nivel","N/A"),
                           str(data.get("total_alertas",0)), str(data.get("total_cadeias",0))])
        ht = RLTable(h_data, colWidths=[5*cm, 2.5*cm, 2.5*cm, 2*cm, 2*cm])
        ht.setStyle(TableStyle([
            ("BACKGROUND",     (0,0), (-1,0), colors.HexColor("#1a3a6b")),
            ("TEXTCOLOR",      (0,0), (-1,0), colors.white),
            ("FONTNAME",       (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f0f4f8")]),
            ("GRID",           (0,0), (-1,-1), 0.5, colors.grey),
            ("ALIGN",          (1,0), (-1,-1), "CENTER"),
        ]))
        story.append(ht)

    # Alertas
    if alerts:
        story.append(Paragraph("Alertas Detetados", h2_style))
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        a_data = [["Severidade", "Regra", "Nome", "Ocorr."]]
        for a in sorted(alerts, key=lambda x: sev_order.get(x.get("severity","LOW"), 99)):
            a_data.append([a.get("severity","N/A"), a.get("rule","ML"),
                           a.get("rule_name","Anomalia"), str(a.get("occurrences",1))])
        at = RLTable(a_data, colWidths=[2.5*cm, 2*cm, 8*cm, 1.5*cm])
        at.setStyle(TableStyle([
            ("BACKGROUND",     (0,0), (-1,0), colors.HexColor("#1a3a6b")),
            ("TEXTCOLOR",      (0,0), (-1,0), colors.white),
            ("FONTNAME",       (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f0f4f8")]),
            ("GRID",           (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        story.append(at)

    # MITRE + Acoes
    tecnicas = ai.get("tecnicas_mitre", [])
    acoes    = ai.get("acoes_imediatas", [])
    if tecnicas:
        story.append(Paragraph("Tecnicas MITRE ATT&CK", h2_style))
        for t in tecnicas:
            story.append(Paragraph(f"• {t}", body_style))
    if acoes:
        story.append(Paragraph("Acoes Imediatas", h2_style))
        for a in acoes:
            story.append(Paragraph(f"• {a}", red_style))

    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Paragraph(f"Gerado por SentinelAI {VERSION}  |  {ts}", sub_style))

    doc.build(story)

# ============================================================
# OPCAO 8 - CONFIGURACOES
# ============================================================

def show_settings():
    global config
    while True:
        cls()
        console.print(Rule("[bold cyan]Configuracoes[/bold cyan]"))
        console.print()

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Opcao", style="bold cyan", width=6)
        table.add_column("Chave", style="dim white", width=24)
        table.add_column("Valor atual", style="white")
        table.add_row("[1]", "Pasta de logs",
                     config.get("logs_folder", ""))
        table.add_row("[2]", "Pasta de reports",
                     config.get("output_folder", ""))
        table.add_row("[3]", "Notificacoes Windows",
                     "[green]Activas[/green]" if config.get("notifications") else "[red]Inactivas[/red]")
        table.add_row("", "", "")
        table.add_row("[0]", "Voltar", "")
        console.print(Align.center(table))
        console.print()

        choice = Prompt.ask("  Opcao", default="0")

        if choice == "1":
            new_val = Prompt.ask("  Nova pasta de logs", default=config.get("logs_folder", ""))
            if os.path.isdir(new_val):
                config["logs_folder"] = new_val
                save_config(config)
                console.print("  [green]Guardado.[/green]")
            else:
                console.print("  [red]Pasta nao existe. Crie-a primeiro.[/red]")
            time.sleep(1.2)

        elif choice == "2":
            new_val = Prompt.ask("  Nova pasta de reports", default=config.get("output_folder", ""))
            os.makedirs(new_val, exist_ok=True)
            config["output_folder"] = new_val
            save_config(config)
            console.print("  [green]Guardado.[/green]")
            time.sleep(1.2)

        elif choice == "3":
            config["notifications"] = not config.get("notifications", True)
            save_config(config)
            state = "activas" if config["notifications"] else "inactivas"
            console.print(f"  [green]Notificacoes {state}.[/green]")
            time.sleep(1.2)

        elif choice == "0":
            break

# ============================================================
# RENDER DE RELATORIO
# ============================================================

def _render_report(report: dict, path: str):
    ai    = report.get("ai_analysis", {})
    hosts = report.get("host_scores", {})
    alerts= report.get("alerts", [])
    risk  = ai.get("risk_score_global", 0)
    nivel = ai.get("nivel_ameaca", "N/A")

    risk_col = SEV_COLOR.get(nivel.upper(), "white")
    summary = Text()
    summary.append(f"  Risk Score Global : ", style="white")
    summary.append(f"{risk}/100 ({nivel})\n", style=risk_col)
    summary.append(f"  Alertas           : {report.get('total_alerts', 0)}\n", style="white")
    summary.append(f"  Cadeias de Ataque : {report.get('total_chains', 0)}\n", style="white")
    summary.append(f"  Hosts Analisados  : {report.get('total_hosts', 0)}\n", style="white")
    summary.append(f"\n  {ai.get('resumo_executivo', '')}", style="dim white")

    console.print(Panel(summary, title="[bold]Sumario Executivo[/bold]",
                        border_style="blue", padding=(0, 1)))
    console.print()

    if hosts:
        ht = Table(title="Score de Risco por Host", box=box.SIMPLE_HEAVY,
                   header_style="bold cyan", show_header=True)
        ht.add_column("Host",    width=25)
        ht.add_column("Score",   width=10, justify="center")
        ht.add_column("Nivel",   width=10, justify="center")
        ht.add_column("Alertas", width=8,  justify="center")
        ht.add_column("Cadeias", width=8,  justify="center")
        for host, data in sorted(hosts.items(), key=lambda x: -x[1].get("score", 0)):
            n = data.get("nivel", "N/A")
            ht.add_row(host, f"{data.get('score', 0)}/100",
                       Text(n, style=SEV_COLOR.get(n.upper(), "white")),
                       str(data.get("total_alertas", 0)),
                       str(data.get("total_cadeias", 0)))
        console.print(ht)
        console.print()

    if alerts:
        at = Table(title="Alertas Detetados", box=box.SIMPLE_HEAVY,
                   header_style="bold cyan", show_header=True)
        at.add_column("Severidade", width=10, justify="center")
        at.add_column("Regra",      width=8,  justify="center")
        at.add_column("Nome",       width=35)
        at.add_column("Ocorr.",     width=7,  justify="center")
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for a in sorted(alerts, key=lambda x: sev_order.get(x.get("severity", "LOW"), 99)):
            s = a.get("severity", "N/A")
            at.add_row(Text(s, style=SEV_COLOR.get(s, "white")),
                       a.get("rule", "ML"),
                       a.get("rule_name", "Anomalia"),
                       str(a.get("occurrences", 1)))
        console.print(at)
        console.print()

    tecnicas = ai.get("tecnicas_mitre", [])
    acoes    = ai.get("acoes_imediatas", [])
    if tecnicas or acoes:
        info = ""
        if tecnicas:
            info += "[bold cyan]Tecnicas MITRE ATT&CK:[/bold cyan]\n"
            for t in tecnicas:
                info += f"  [yellow]•[/yellow] {t}\n"
        if acoes:
            info += "\n[bold cyan]Acoes Imediatas:[/bold cyan]\n"
            for a in acoes:
                info += f"  [red]•[/red] {a}\n"
        console.print(Panel(info.strip(), border_style="dim blue", padding=(0, 1)))
        console.print()

    console.print(f"  [dim]Ficheiro: {path}[/dim]")

# ============================================================
# MAIN
# ============================================================

def main():
    show_splash()
    while True:
        print_header()
        print_menu()
        choice = Prompt.ask("  Opcao", default="0")

        if   choice == "1": run_analysis()
        elif choice == "2": show_last_report()
        elif choice == "3": list_reports()
        elif choice == "4": view_specific_report()
        elif choice == "5": show_risk_chart()
        elif choice == "6": show_history()
        elif choice == "7": export_pdf()
        elif choice == "8": show_settings()
        elif choice == "0":
            cls()
            console.print("  [dim]A sair...[/dim]\n")
            sys.exit(0)
        else:
            console.print("  [yellow]Opcao invalida.[/yellow]")
            time.sleep(1)

if __name__ == "__main__":
    main()