# test_sentinel.py
# SentinelAI - Testes Unitarios
# Executar com: python -m pytest test_sentinel.py -v

import pytest
import sys
import os
import json
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ============================================================
# TESTES - MOTOR DE REGRAS
# ============================================================

from sentinel import RULES

def get_rule(rule_id):
    return next(r for r in RULES if r["id"] == rule_id)

class TestMotorDeRegras:

    # R001 - Persistencia via Chave Run
    def test_r001_deteta_chave_run(self):
        rule = get_rule("R001")
        evento = {"EventID": "13", "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"}
        assert rule["check"](evento) is True

    def test_r001_ignora_chave_nao_run(self):
        rule = get_rule("R001")
        evento = {"EventID": "13", "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\app"}
        assert rule["check"](evento) is False

    # R002 - Scheduled Task
    def test_r002_deteta_schtasks_create(self):
        rule = get_rule("R002")
        evento = {"EventID": "1", "CommandLine": "schtasks /create /tn winupdate /tr payload.exe /sc onlogon"}
        assert rule["check"](evento) is True

    def test_r002_ignora_schtasks_query(self):
        rule = get_rule("R002")
        evento = {"EventID": "1", "CommandLine": "schtasks /query /fo LIST"}
        assert rule["check"](evento) is False

    # R003 - LOLBin
    def test_r003_deteta_rundll32(self):
        rule = get_rule("R003")
        evento = {"EventID": "1", "CommandLine": "rundll32.exe comsvcs.dll MiniDump 624 lsass.dmp full"}
        assert rule["check"](evento) is True

    def test_r003_deteta_certutil(self):
        rule = get_rule("R003")
        evento = {"EventID": "1", "CommandLine": "certutil -decode encoded.b64 output.exe"}
        assert rule["check"](evento) is True

    def test_r003_ignora_processo_normal(self):
        rule = get_rule("R003")
        evento = {"EventID": "1", "CommandLine": "notepad.exe C:\\Users\\user\\document.txt"}
        assert rule["check"](evento) is False

    # R004 - PowerShell Suspeito
    def test_r004_deteta_powershell_encoded(self):
        rule = get_rule("R004")
        evento = {"EventID": "1", "CommandLine": "powershell -nop -w hidden -enc UwB0AGEAcgB0"}
        assert rule["check"](evento) is True

    def test_r004_deteta_powershell_bypass(self):
        rule = get_rule("R004")
        evento = {"EventID": "1", "CommandLine": "powershell -ExecutionPolicy Bypass -WindowStyle Hidden"}
        assert rule["check"](evento) is True

    def test_r004_ignora_powershell_normal(self):
        rule = get_rule("R004")
        evento = {"EventID": "1", "CommandLine": "powershell Get-Process"}
        assert rule["check"](evento) is False

    # R005 - Adicao de Utilizador
    def test_r005_deteta_net_user_add(self):
        rule = get_rule("R005")
        evento = {"EventID": "1", "CommandLine": "net user hacker Password123! /add"}
        assert rule["check"](evento) is True

    def test_r005_ignora_net_user_list(self):
        rule = get_rule("R005")
        evento = {"EventID": "1", "CommandLine": "net user"}
        assert rule["check"](evento) is False

    # R006 - Dump de Credenciais
    def test_r006_deteta_mimikatz(self):
        rule = get_rule("R006")
        evento = {"EventID": "1", "CommandLine": "mimikatz.exe lsadump::sam"}
        assert rule["check"](evento) is True

    def test_r006_deteta_lsass(self):
        rule = get_rule("R006")
        evento = {"EventID": "1", "CommandLine": "procdump -ma lsass.exe lsass.dmp"}
        assert rule["check"](evento) is True

    def test_r006_ignora_processo_normal(self):
        rule = get_rule("R006")
        evento = {"EventID": "1", "CommandLine": "explorer.exe"}
        assert rule["check"](evento) is False

    # R007 - Movimento Lateral
    def test_r007_deteta_psexec(self):
        rule = get_rule("R007")
        evento = {"EventID": "1", "CommandLine": "psexec.exe \\\\192.168.1.20 -u admin -p pass cmd.exe"}
        assert rule["check"](evento) is True

    def test_r007_ignora_processo_normal(self):
        rule = get_rule("R007")
        evento = {"EventID": "1", "CommandLine": "ping 192.168.1.20"}
        assert rule["check"](evento) is False

# ============================================================
# TESTES - MOTOR DE CORRELACAO
# ============================================================

from correlator import check_chain, build_host_timeline

CHAIN_C001 = {
    "id":          "C001",
    "name":        "Comprometimento Total Windows",
    "rules":       ["R004", "R006", "R001"],
    "severity":    "CRITICAL",
    "risk_score":  95,
    "mitre_tactic": "Execution -> Credential Access -> Persistence"
}

class TestMotorDeCorrelacao:

    def _make_events(self, rule_ids):
        return [{"rule_id": r, "timestamp": None, "severity": "CRITICAL"} for r in rule_ids]

    def test_deteta_cadeia_c001_completa(self):
        events = self._make_events(["R004", "R006", "R001"])
        matches = check_chain(events, CHAIN_C001, 60)
        assert len(matches) == 1

    def test_nao_deteta_cadeia_c001_fora_de_ordem(self):
        # Regras presentes mas fora de ordem nao devem formar cadeia.
        events = self._make_events(["R006", "R001", "R004"])
        matches = check_chain(events, CHAIN_C001, 60)
        assert len(matches) == 0

    def test_nao_deteta_cadeia_incompleta(self):
        # Falta R001
        events = self._make_events(["R004", "R006"])
        matches = check_chain(events, CHAIN_C001, 60)
        assert len(matches) == 0

    def test_nao_deteta_cadeia_fora_janela_temporal(self):
        events = [
            {"rule_id": "R004", "timestamp": datetime(2026, 2, 1, 10, 0), "severity": "HIGH"},
            {"rule_id": "R006", "timestamp": datetime(2026, 2, 1, 12, 0), "severity": "CRITICAL"},
            {"rule_id": "R001", "timestamp": datetime(2026, 2, 1, 12, 10), "severity": "HIGH"},
        ]
        matches = check_chain(events, CHAIN_C001, 60)
        assert len(matches) == 0

    def test_nao_deteta_cadeia_vazia(self):
        matches = check_chain([], CHAIN_C001, 60)
        assert len(matches) == 0

    def test_build_timeline_agrupa_por_host(self):
        alerts = [
            {"rule": "R006", "severity": "CRITICAL",
             "hosts": ["HOST-A", "HOST-B"],
             "sample_event": {"TimeCreated": "2026-02-01T10:00:00Z"}},
            {"rule": "R001", "severity": "HIGH",
             "hosts": ["HOST-A"],
             "sample_event": {"TimeCreated": "2026-02-02T10:00:00Z"}},
        ]
        timeline = build_host_timeline(alerts)
        assert "HOST-A" in timeline
        assert "HOST-B" in timeline
        assert len(timeline["HOST-A"]) == 2
        assert len(timeline["HOST-B"]) == 1

    def test_build_timeline_prefere_eventos_expandidos(self):
        alerts = [{
            "rule": "R006", "rule_name": "Dump de Credenciais", "severity": "CRITICAL",
            "events": [
                {"Computer": "HOST-A", "TimeCreated": "2026-02-01T10:00:00Z"},
                {"Computer": "HOST-B", "TimeCreated": "2026-02-01T10:05:00Z"},
            ],
            "sample_event": {"TimeCreated": "2026-02-01T09:00:00Z"},
        }]
        timeline = build_host_timeline(alerts)
        assert len(timeline["HOST-A"]) == 1
        assert len(timeline["HOST-B"]) == 1
        assert timeline["HOST-B"][0]["timestamp"].isoformat() == "2026-02-01T10:05:00"


# ============================================================
# TESTES - SCORE DE RISCO POR HOST
# ============================================================

from host_scorer import calculate_host_scores

class TestHostScorer:

    def _make_alert(self, severity, hosts):
        return {"rule": "R001", "rule_name": "Teste", "severity": severity, "hosts": hosts, "sample_event": {}}

    def _make_chain(self, host, severity, risk_score):
        return {"chain_id": "C001", "chain_name": "Teste", "host": host,
                "severity": severity, "risk_score": risk_score, "sequence": []}

    def test_host_critico_com_alertas_criticos(self):
        alerts = [self._make_alert("CRITICAL", ["HOST-A"])] * 3
        scores = calculate_host_scores(alerts, [])
        assert scores["HOST-A"]["nivel"] == "CRITICO"
        assert scores["HOST-A"]["score"] >= 80

    def test_host_com_cadeia_aumenta_score(self):
        alerts  = [self._make_alert("HIGH", ["HOST-A"])]
        chains  = [self._make_chain("HOST-A", "CRITICAL", 95)]
        scores  = calculate_host_scores(alerts, chains)
        assert scores["HOST-A"]["total_cadeias"] == 1
        assert scores["HOST-A"]["score"] > 0

    def test_host_regista_tecnica_mitre_por_regra(self):
        alerts = [self._make_alert("CRITICAL", ["HOST-A"])]
        alerts[0]["rule"] = "R001"
        scores = calculate_host_scores(alerts, [])
        assert "T1547 - Boot or Logon Autostart Execution" in scores["HOST-A"]["tecnicas"]

    def test_host_sem_alertas_nao_aparece(self):
        alerts = [self._make_alert("HIGH", ["HOST-A"])]
        scores = calculate_host_scores(alerts, [])
        assert "HOST-B" not in scores

    def test_multiplos_hosts_independentes(self):
        alerts = [
            self._make_alert("CRITICAL", ["HOST-A"]),
            self._make_alert("LOW",      ["HOST-B"]),
        ]
        scores = calculate_host_scores(alerts, [])
        assert scores["HOST-A"]["score"] > scores["HOST-B"]["score"]

    def test_score_nao_excede_100(self):
        alerts = [self._make_alert("CRITICAL", ["HOST-A"])] * 20
        chains = [self._make_chain("HOST-A", "CRITICAL", 95)] * 10
        scores = calculate_host_scores(alerts, chains)
        assert scores["HOST-A"]["score"] <= 100


# ============================================================
# TESTES - RELATORIO TXT
# ============================================================

from report_writer import generate_txt_report
from parser import get_events, parse_jsonl
from app_config import load_app_config
from event_utils import attach_auth_token, has_valid_auth_token, strip_auth_token

class TestReportWriter:

    def _sample_data(self):
        alerts = [{
            "rule": "R006", "rule_name": "Dump de Credenciais",
            "severity": "CRITICAL", "occurrences": 5,
            "hosts": ["HOST-A"], "sample_event": {"CommandLine": "mimikatz.exe"}
        }]
        correlations = [{
            "chain_id": "C001", "chain_name": "Comprometimento Total",
            "severity": "CRITICAL", "risk_score": 95,
            "host": "HOST-A", "mitre_tactic": "Execution -> Persistence",
            "steps": [
                {"rule_name": "PowerShell", "timestamp": "2026-02-01T10:00:00"},
                {"rule_name": "Mimikatz", "timestamp": "2026-02-01T10:05:00"},
            ]
        }]
        host_scores = {
            "HOST-A": {"score": 95, "nivel": "CRITICO",
                       "total_alertas": 1, "total_cadeias": 1,
                       "alertas": [], "cadeias": []}
        }
        ai_analysis = {
            "risk_score_global": 95, "nivel_ameaca": "CRITICO",
            "resumo_executivo": "Teste de relatorio.",
            "hipotese_ataque": "Ataque simulado.",
            "principais_ameacas": ["Mimikatz"],
            "hosts_criticos": ["HOST-A"],
            "tecnicas_mitre": ["T1003 - OS Credential Dumping"],
            "acoes_imediatas": ["Isolar HOST-A"]
        }
        return alerts, correlations, host_scores, ai_analysis

    def test_relatorio_cria_ficheiro(self):
        alerts, correlations, host_scores, ai_analysis = self._sample_data()
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        generate_txt_report(alerts, correlations, host_scores, ai_analysis, path)
        assert os.path.exists(path)
        os.unlink(path)

    def test_relatorio_contem_secoes_principais(self):
        alerts, correlations, host_scores, ai_analysis = self._sample_data()
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            path = f.name
        generate_txt_report(alerts, correlations, host_scores, ai_analysis, path)
        content = open(path, encoding="utf-8").read()
        assert "SUMARIO EXECUTIVO"              in content
        assert "SCORE DE RISCO POR HOST"        in content
        assert "ALERTAS DETETADOS"              in content
        assert "CADEIAS DE ATAQUE"              in content
        assert "TECNICAS MITRE ATT&CK"          in content
        assert "ACOES IMEDIATAS RECOMENDADAS"   in content
        os.unlink(path)

    def test_relatorio_contem_dados_reais(self):
        alerts, correlations, host_scores, ai_analysis = self._sample_data()
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            path = f.name
        generate_txt_report(alerts, correlations, host_scores, ai_analysis, path)
        content = open(path, encoding="utf-8").read()
        assert "HOST-A"               in content
        assert "Dump de Credenciais"  in content
        assert "95/100"               in content
        assert "PowerShell [2026-02-01T10:00:00]" in content
        os.unlink(path)


class TestParserJsonl:

    def test_parse_jsonl_normaliza_eventid(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w", encoding="utf-8") as f:
            f.write('{"EventId": 7045, "Computer": "HOST-A"}\n')
            path = f.name

        events = parse_jsonl(path)
        assert len(events) == 1
        assert events[0]["EventID"] == "7045"
        os.unlink(path)

    def test_parser_ignora_formato_nao_windows(self):
        with tempfile.NamedTemporaryFile(suffix=".audit", delete=False, mode="w", encoding="utf-8") as f:
            f.write("unsupported content\n")
            path = f.name

        events = get_events(path)
        assert events == []
        os.unlink(path)


class TestTransportAuth:

    def test_attach_auth_token_adiciona_campo(self):
        payload = attach_auth_token({"type": "heartbeat"}, "segredo")
        assert payload["AuthToken"] == "segredo"

    def test_has_valid_auth_token_valida_token_certo(self):
        payload = {"AuthToken": "segredo"}
        assert has_valid_auth_token(payload, "segredo") is True
        assert has_valid_auth_token(payload, "errado") is False

    def test_strip_auth_token_remove_campo(self):
        payload = strip_auth_token({"AuthToken": "segredo", "EventID": "4688"})
        assert "AuthToken" not in payload
        assert payload["EventID"] == "4688"


class TestAppConfig:

    def test_load_app_config_resolve_paths_e_overrides(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "sentinelai_config.json")
            script_path = os.path.join(tmpdir, "src", "dummy.py")
            os.makedirs(os.path.dirname(script_path), exist_ok=True)

            with open(config_path, "w", encoding="utf-8") as config_file:
                json.dump({
                    "logs_folder": "logs",
                    "output_folder": "output/reports",
                    "receiver_port": "9100",
                }, config_file)

            monkeypatch.setenv("SENTINELAI_CONFIG_PATH", config_path)
            monkeypatch.setenv("SENTINELAI_RECEIVER_AUTH_TOKEN", "env-token")

            config = load_app_config(script_path)

            assert config["receiver_port"] == 9100
            assert config["receiver_auth_token"] == "env-token"
            assert os.path.isabs(config["logs_folder"])
            assert os.path.isabs(config["output_folder"])
