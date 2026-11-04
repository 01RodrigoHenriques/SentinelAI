# SentinelAI - Menu interativo
# Dependencias: rich, reportlab

import os
import sys
import json
import glob
import time
import threading
import socket
import subprocess
from collections import defaultdict, deque

from app_config import get_config_path, load_app_config, mask_secret, save_app_config, secret_fingerprint
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich import box
from rich.rule import Rule
from rich.align import Align

from event_utils import (
    get_event_id_int,
    has_valid_auth_token,
    normalize_event,
    strip_auth_token,
)
from runtime_paths import get_app_root

console = Console()

VERSION = "v1.2"

# ============================================================
# BASE DIR - Funciona tanto como .py como .exe compilado
# ============================================================

BASE_DIR = str(get_app_root(__file__))
CONFIG_PATH  = str(get_config_path(__file__))
OUTPUT_DIR   = os.path.join(BASE_DIR, "output", "reports")
HISTORY_PATH = os.path.join(BASE_DIR, "output", "history.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

# ============================================================
# CONFIG FILE
# ============================================================

def load_config() -> dict:
    return load_app_config(__file__, create_if_missing=True)

def save_config(cfg: dict):
    save_app_config(__file__, cfg)
    cfg.clear()
    cfg.update(load_app_config(__file__, create_if_missing=True))

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
        "  ================================================================",
        "                           SentinelAI                            ",
        "  ================================================================",
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
    table.add_row("[9]", "Servidor de recepcao de logs (rede)")
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

    data.reverse()  # ordem temporal

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
            story.append(Paragraph(f"- {t}", body_style))
    if acoes:
        story.append(Paragraph("Acoes Imediatas", h2_style))
        for a in acoes:
            story.append(Paragraph(f"- {a}", red_style))

    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Paragraph(f"Gerado por SentinelAI {VERSION}  |  {ts}", sub_style))

    doc.build(story)

# ============================================================
# DISCORD WEBHOOK
# ============================================================

def send_discord_alert(title: str, description: str, color: int = 0xe74c3c):
    """Envia alerta para o canal Discord via webhook."""
    webhook_url = config.get("discord_webhook", "")
    if not webhook_url:
        return
    try:
        import urllib.request
        payload = json.dumps({
            "embeds": [{
                "title":       title,
                "description": description,
                "color":       color,
                "footer":      {"text": f"SentinelAI {VERSION}"},
                "timestamp":   __import__('datetime').datetime.utcnow().isoformat() + "Z",
            }]
        }).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        return

# ============================================================
# OPCAO 9 - SERVIDOR DE RECEPCAO DE LOGS EM REDE
# ============================================================

_recv_running = False
_recv_stats   = {"agents": {}, "total": 0}
_recv_stats_lock = threading.Lock()
_recv_client_slots = threading.BoundedSemaphore(64)
_recv_rate = defaultdict(deque)
_recv_nonces = defaultdict(deque)
_RECV_MAX_BUFFER_BYTES = 128 * 1024
_RECV_MAX_LINE_BYTES = 64 * 1024
_RECV_RATE_WINDOW_SECONDS = 10
_RECV_RATE_LIMIT_EVENTS = 200
_RECV_NONCE_WINDOW_SECONDS = 300

def _score_local_ip(ip: str):
    if ip.startswith("192.168."):
        if ip.startswith("192.168.56."):
            return (2, ip)
        return (0, ip)
    if ip.startswith("10."):
        return (1, ip)
    if ip.startswith("172."):
        return (3, ip)
    return (4, ip)


def _get_local_ip_candidates():
    candidates = []

    if os.name == "nt":
        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=0x08000000,
            )
            for line in result.stdout.splitlines():
                if "IPv4" not in line or ":" not in line:
                    continue
                ip = line.split(":", 1)[1].strip()
                if (
                    ip
                    and ip != "127.0.0.1"
                    and not ip.startswith("169.254.")
                    and ip not in candidates
                ):
                    candidates.append(ip)
        except Exception:
            pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip not in candidates and ip != "127.0.0.1":
            candidates.append(ip)
    except Exception:
        pass

    if not candidates:
        return ["127.0.0.1"]

    return sorted(candidates, key=_score_local_ip)


def _get_local_ip():
    return _get_local_ip_candidates()[0]

def _handle_agent(conn, addr):
    global _recv_stats
    ip  = addr[0]
    buf = ""
    buf_bytes = 0
    from datetime import datetime
    today    = datetime.now().strftime("%Y%m%d")
    net_dir  = os.path.join(config.get("logs_folder", os.path.join(BASE_DIR, "logs")), "network")
    expected_token = config.get("receiver_auth_token", "").strip()
    os.makedirs(net_dir, exist_ok=True)
    log_file = os.path.join(net_dir, f"agent_{ip}_{today}.jsonl")
    with _recv_stats_lock:
        agent_info = _recv_stats["agents"].setdefault(
            ip,
            {"ip": ip, "events": 0, "hostname": "?", "connections": 0},
        )
        agent_info["connections"] += 1
    console.print(f"\n  [bold green]Agente ligado:[/bold green] [cyan]{ip}[/cyan]")
    try:
        conn.settimeout(30)
        with open(log_file, "a", encoding="utf-8") as f:
            while _recv_running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    buf_bytes += len(data)
                    if buf_bytes > _RECV_MAX_BUFFER_BYTES:
                        console.print(f"\n  [bold red]Ligacao terminada:[/bold red] buffer excedido de {ip}")
                        break
                    buf += data.decode("utf-8", errors="ignore")
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        buf_bytes = len(buf.encode("utf-8", errors="ignore"))
                        line = line.strip()
                        if not line:
                            continue
                        if len(line.encode("utf-8")) > _RECV_MAX_LINE_BYTES:
                            console.print(f"\n  [yellow]Evento descartado:[/yellow] linha demasiado grande de {ip}")
                            continue
                        if not _allow_receiver_event(ip):
                            console.print(f"\n  [bold red]Ligacao terminada:[/bold red] rate limit excedido de {ip}")
                            return
                        try:
                            ev = json.loads(line)
                            if not ev.get("AuthSignature"):
                                console.print(f"\n  [bold red]Ligacao rejeitada:[/bold red] assinatura HMAC ausente de {ip}")
                                console.print("  [yellow]Confirme que a VM usa o agent.exe novo e a config ao lado do executavel.[/yellow]")
                                return
                            if not has_valid_auth_token(ev, expected_token):
                                console.print(f"\n  [bold red]Ligacao rejeitada:[/bold red] token invalido de {ip}")
                                console.print(f"  [yellow]Token ID esperado:[/yellow] {secret_fingerprint(expected_token)}")
                                console.print(f"  [yellow]Token ID recebido:[/yellow] {ev.get('AuthTokenId', 'N/A')}")
                                return
                            if not _accept_receiver_nonce(ip, str(ev.get("AuthNonce", ""))):
                                console.print(f"\n  [bold red]Ligacao rejeitada:[/bold red] replay detetado de {ip}")
                                return
                            ev = normalize_event(strip_auth_token(ev))

                            # O heartbeat atualiza o ultimo host conhecido sem gerar alerta.
                            if ev.get("type") == "heartbeat":
                                with _recv_stats_lock:
                                    if ip in _recv_stats["agents"]:
                                        _recv_stats["agents"][ip]["hostname"] = ev.get("host", "?")
                                continue

                            hostname  = ev.get("Computer", ip)
                            rule_name = ev.get("rule_name", "")
                            severity  = ev.get("severity", "")
                            cmd       = ev.get("CommandLine", "")
                            eid       = ev.get("EventID", "?")

                            with _recv_stats_lock:
                                if ip in _recv_stats["agents"]:
                                    _recv_stats["agents"][ip]["hostname"] = hostname
                                    _recv_stats["agents"][ip]["events"]  += 1
                                _recv_stats["total"] += 1
                            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                            f.flush()

                            # O terminal apresenta apenas eventos que ja trazem classificacao.
                            if rule_name and severity:
                                style = SEV_COLOR.get(severity, "white")
                                console.print(f"\n  [{style}]{'-' * 50}[/{style}]")
                                console.print(f"  [{style}][{severity}] {rule_name}[/{style}]")
                                console.print(f"  [cyan]Host   :[/cyan] {hostname} ({ip})")
                                console.print(f"  [cyan]EventID:[/cyan] {eid}")
                                if cmd:
                                    display = cmd[:80] + "..." if len(cmd) > 80 else cmd
                                    console.print(f"  [cyan]Comando:[/cyan] {display}")
                                console.print(f"  [{style}]{'-' * 50}[/{style}]")

                            # O alerta imediato e enviado quando a configuracao o permite.
                            _check_realtime_alert(ev, ip)

                        except json.JSONDecodeError:
                            console.print(f"\n  [yellow]Evento descartado:[/yellow] JSON invalido de {ip}")
                            continue
                        except Exception as e:
                            console.print(f"\n  [yellow]Evento descartado:[/yellow] erro ao processar evento de {ip}: {e}")
                            continue
                except Exception:
                    break
    finally:
        conn.close()
        _recv_client_slots.release()
        with _recv_stats_lock:
            agent_info = _recv_stats["agents"].get(ip)
            if agent_info:
                agent_info["connections"] = max(0, agent_info.get("connections", 1) - 1)
                if agent_info["connections"] == 0:
                    _recv_stats["agents"].pop(ip, None)
        console.print(f"\n  [bold red]Agente desligado:[/bold red] {ip}")


# Event IDs criticos com alerta imediato.
_CRITICAL_EVENTS = {
    4625: "Login falhado",
    4648: "Login com credenciais explicitas",
    4672: "Privilegios especiais atribuidos",
    4697: "Servico instalado",
    4698: "Tarefa agendada criada",
    4720: "Conta de utilizador criada",
    4726: "Conta de utilizador eliminada",
    7045: "Novo servico instalado no sistema",
    4103: "PowerShell - Execucao de modulo",
    4104: "PowerShell - Script executado",
}
_alert_cooldown = {}  # ip -> {event_id -> timestamp}

def _allow_receiver_event(ip: str) -> bool:
    now = time.time()
    events = _recv_rate[ip]
    while events and now - events[0] > _RECV_RATE_WINDOW_SECONDS:
        events.popleft()
    if len(events) >= _RECV_RATE_LIMIT_EVENTS:
        return False
    events.append(now)
    return True


def _accept_receiver_nonce(ip: str, nonce: str) -> bool:
    if not nonce:
        return False
    now = time.time()
    entries = _recv_nonces[ip]
    while entries and now - entries[0][1] > _RECV_NONCE_WINDOW_SECONDS:
        entries.popleft()
    if any(seen_nonce == nonce for seen_nonce, _ in entries):
        return False
    entries.append((nonce, now))
    return True

def _check_realtime_alert(ev: dict, ip: str):
    """Verifica se o evento e critico e envia alerta Discord."""
    eid      = get_event_id_int(ev)
    hostname = ev.get("Computer", ip)
    channel  = ev.get("Channel", "")

    if eid is None or eid not in _CRITICAL_EVENTS:
        return

    # O cooldown reduz repeticao de alertas para a mesma origem.
    now = time.time()
    key = f"{ip}_{eid}"
    if _alert_cooldown.get(key, 0) + 60 > now:
        return
    _alert_cooldown[key] = now

    descricao = _CRITICAL_EVENTS[eid]
    cmd_line  = ev.get("CommandLine", "")
    msg = ev.get("Message", "")[:300]

    description = (
        f"**Host:** `{hostname}` (`{ip}`)\n"
        f"**Canal:** `{channel}`\n"
        f"**Event ID:** `{eid}` - {descricao}\n"
    )
    if cmd_line:
        description += f"**CommandLine:** `{cmd_line[:200]}`\n"
    if msg:
        description += f"**Detalhes:**\n```{msg}```"

    threading.Thread(
        target=send_discord_alert,
        args=(f"Alerta SentinelAI - {descricao}", description, 0xe74c3c),
        daemon=True
    ).start()

def _server_loop(port):
    global _recv_running
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(1.0)
    bind_host = config.get("receiver_host", "127.0.0.1")
    try:
        srv.bind((bind_host, port))
        srv.listen(50)
        while _recv_running:
            try:
                conn, addr = srv.accept()
                if not _recv_client_slots.acquire(blocking=False):
                    conn.close()
                    continue
                t = threading.Thread(target=_handle_agent, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
    except Exception as e:
        console.print(f"  [red]Erro no servidor: {e}[/red]")
    finally:
        srv.close()

def show_receiver():
    global _recv_running, _recv_stats

    while True:
        port = config.get("receiver_port", 9000)
        bind_host = config.get("receiver_host", "127.0.0.1")
        auth_token = config.get("receiver_auth_token", "").strip()
        cls()
        console.print(Rule("[bold cyan]Servidor de Recepcao de Logs[/bold cyan]"))
        console.print()

        local_ips = _get_local_ip_candidates()
        local_ip = local_ips[0]
        alt_ips = ", ".join(local_ips[1:3]) if len(local_ips) > 1 else ""
        status   = "[bold green]ACTIVO[/bold green]" if _recv_running else "[bold red]INACTIVO[/bold red]"
        with _recv_stats_lock:
            agents_snapshot = dict(_recv_stats.get("agents", {}))
            n_agents = len(agents_snapshot)
            total = _recv_stats.get("total", 0)

        console.print(Panel(
            f"  Estado   : {status}\n"
            f"  Config   : [cyan]{CONFIG_PATH}[/cyan]\n"
            f"  Bind     : [cyan]{bind_host}[/cyan]\n"
            f"  IP rec.  : [cyan]{local_ip}[/cyan]\n"
            f"  Porta    : [cyan]{port}[/cyan]\n"
            f"  Token    : [cyan]{mask_secret(auth_token)}[/cyan]\n"
            f"  Token ID : [cyan]{secret_fingerprint(auth_token)}[/cyan]\n"
            f"  Agentes  : [cyan]{n_agents}[/cyan] ligados\n"
            f"  Eventos  : [cyan]{total}[/cyan] recebidos\n\n"
            f"  [dim]Configuracao recomendada no agente:[/dim]\n"
            f"  [yellow]receiver_server = {local_ip}[/yellow]\n"
            f"  [yellow]receiver_port = {port}[/yellow]\n"
            f"  [yellow]receiver_auth_token = {mask_secret(auth_token)}[/yellow]\n"
            f"  [yellow]receiver_token_id = {secret_fingerprint(auth_token)}[/yellow]\n"
            f"  [dim]Auth HMAC obrigatoria[/dim]"
            + (f"\n\n  [dim]IPs alternativos:[/dim] [cyan]{alt_ips}[/cyan]" if alt_ips else ""),
            title="[bold]Estado do Servidor[/bold]",
            border_style="blue", padding=(0, 2)
        ))
        console.print()

        agents = agents_snapshot
        if agents:
            at = Table(title="Agentes Ligados", box=box.SIMPLE_HEAVY,
                       header_style="bold cyan", show_header=True)
            at.add_column("IP",       width=18)
            at.add_column("Hostname", width=22)
            at.add_column("Eventos",  width=10, justify="center")
            for ip, info in agents.items():
                at.add_row(ip, info.get("hostname", "?"), str(info.get("events", 0)))
            console.print(at)
            console.print()

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Opcao", style="bold cyan", width=6)
        table.add_column("Descricao", style="white")
        if _recv_running:
            table.add_row("[1]", "Parar servidor")
        else:
            table.add_row("[1]", "Iniciar servidor")
        table.add_row("[0]", "Voltar")
        console.print(Align.center(table))
        console.print()

        choice = Prompt.ask("  Opcao", default="0")

        if choice == "1":
            if _recv_running:
                _recv_running = False
                console.print("  [yellow]Servidor parado.[/yellow]")
            else:
                if not auth_token:
                    console.print("  [bold red]Defina Receiver Token antes de iniciar o servidor.[/bold red]")
                    time.sleep(1.5)
                    continue
                _recv_running = True
                with _recv_stats_lock:
                    _recv_stats = {"agents": {}, "total": 0}
                _recv_rate.clear()
                _recv_nonces.clear()
                t = threading.Thread(target=_server_loop, args=(port,), daemon=True)
                t.start()
                console.print(f"  [green]Servidor iniciado em {local_ip}:{port}[/green]")
            time.sleep(1.2)

        elif choice == "0":
            break

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
        wh = config.get("discord_webhook", "")
        wh_status = "[green]Configurado[/green]" if wh else "[red]Nao configurado[/red]"
        table.add_row("[3]", "Discord Webhook",        wh_status)
        table.add_row("[4]", "Receiver Host", config.get("receiver_host", "127.0.0.1"))
        table.add_row("[5]", "Receiver Porta", str(config.get("receiver_port", 9000)))
        table.add_row("[6]", "Receiver Token", mask_secret(config.get("receiver_auth_token", "")))
        table.add_row("", "", "")
        table.add_row("[0]", "Voltar", "")
        console.print(Align.center(table))
        console.print()

        choice = Prompt.ask("  Opcao", default="0")

        if choice == "1":
            new_val = Prompt.ask("  Nova pasta de logs", default=config.get("logs_folder", ""))
            os.makedirs(new_val, exist_ok=True)
            config["logs_folder"] = new_val
            save_config(config)
            console.print("  [green]Guardado.[/green]")
            time.sleep(1.2)

        elif choice == "2":
            new_val = Prompt.ask("  Nova pasta de reports", default=config.get("output_folder", ""))
            os.makedirs(new_val, exist_ok=True)
            config["output_folder"] = new_val
            save_config(config)
            console.print("  [green]Guardado.[/green]")
            time.sleep(1.2)

        elif choice == "3":
            new_val = Prompt.ask("  Discord Webhook URL", default=config.get("discord_webhook", ""))
            config["discord_webhook"] = new_val.strip()
            save_config(config)
            if new_val.strip():
                threading.Thread(target=send_discord_alert, args=(
                    "SentinelAI configurado",
                    "Webhook configurado. Os alertas de seguranca serao enviados para este canal.",
                    0x2ecc71
                ), daemon=True).start()
                console.print("  [green]Webhook guardado! Mensagem de teste enviada.[/green]")
            else:
                console.print("  [yellow]Webhook removido.[/yellow]")
            time.sleep(1.5)

        elif choice == "4":
            new_val = Prompt.ask("  Endereco de bind do receiver", default=config.get("receiver_host", "127.0.0.1"))
            config["receiver_host"] = new_val.strip() or "127.0.0.1"
            save_config(config)
            console.print("  [green]Guardado.[/green]")
            time.sleep(1.2)

        elif choice == "5":
            new_val = Prompt.ask("  Porta do receiver", default=str(config.get("receiver_port", 9000)))
            config["receiver_port"] = new_val.strip()
            save_config(config)
            config = load_config()
            console.print(f"  [green]Porta guardada:[/green] {config['receiver_port']}")
            time.sleep(1.2)

        elif choice == "6":
            new_val = Prompt.ask("  Token de autenticacao do receiver", default=config.get("receiver_auth_token", ""))
            config["receiver_auth_token"] = new_val.strip()
            save_config(config)
            if new_val.strip():
                console.print("  [green]Token guardado.[/green]")
            else:
                console.print("  [yellow]Token removido. O receiver nao inicia sem autenticacao.[/yellow]")
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
                info += f"  [yellow]-[/yellow] {t}\n"
        if acoes:
            info += "\n[bold cyan]Acoes Imediatas:[/bold cyan]\n"
            for a in acoes:
                info += f"  [red]-[/red] {a}\n"
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
        elif choice == "9": show_receiver()
        elif choice == "0":
            cls()
            console.print("  [dim]A sair...[/dim]\n")
            sys.exit(0)
        else:
            console.print("  [yellow]Opcao invalida.[/yellow]")
            time.sleep(1)

if __name__ == "__main__":
    main()
