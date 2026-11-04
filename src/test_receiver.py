# test_receiver.py
# SentinelAI - Testes do receiver e da validacao HMAC
# Executar com: python -m pytest test_receiver.py -v

import json
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from event_utils import (
    AUTH_WINDOW_SECONDS,
    attach_auth_token,
    has_valid_auth_token,
    strip_auth_token,
)
from receiver import (
    PLACEHOLDER_TOKENS,
    accept_nonce,
    allow_event_from_ip,
    build_tls_context,
    rate_counters,
    run_server,
    seen_nonces,
    validate_auth_token,
)

TOKEN = "sentinelai-token-de-teste-123456"


def make_event(**extra):
    event = {
        "Computer": "HOST-TESTE",
        "EventID": "4688",
        "CommandLine": "whoami",
        "rule_name": "Teste",
        "severity": "LOW",
    }
    event.update(extra)
    return event


# ============================================================
# VALIDACAO HMAC
# ============================================================

class TestValidacaoHMAC:

    def test_assinatura_valida_e_aceite(self):
        signed = attach_auth_token(make_event(), TOKEN)
        assert has_valid_auth_token(signed, TOKEN) is True

    def test_token_incorreto_e_rejeitado(self):
        signed = attach_auth_token(make_event(), TOKEN)
        assert has_valid_auth_token(signed, "outro-token") is False

    def test_payload_alterado_e_rejeitado(self):
        signed = attach_auth_token(make_event(), TOKEN)
        signed["CommandLine"] = "powershell -enc JABzAD0ATg=="
        assert has_valid_auth_token(signed, TOKEN) is False

    def test_timestamp_fora_da_janela_e_rejeitado(self):
        signed = attach_auth_token(make_event(), TOKEN)
        signed["AuthTimestamp"] = str(int(time.time()) - AUTH_WINDOW_SECONDS - 1)
        assert has_valid_auth_token(signed, TOKEN) is False

    @pytest.mark.parametrize("campo", ["AuthSignature", "AuthTimestamp", "AuthNonce"])
    def test_campo_de_auth_em_falta_e_rejeitado(self, campo):
        signed = attach_auth_token(make_event(), TOKEN)
        signed.pop(campo)
        assert has_valid_auth_token(signed, TOKEN) is False

    def test_token_vazio_e_rejeitado(self):
        signed = attach_auth_token(make_event(), TOKEN)
        assert has_valid_auth_token(signed, "") is False

    def test_assinar_sem_token_levanta_erro(self):
        with pytest.raises(ValueError):
            attach_auth_token(make_event(), "")

    def test_strip_auth_token_remove_os_campos(self):
        signed = attach_auth_token(make_event(), TOKEN)
        clean = strip_auth_token(signed)
        for campo in ("AuthSignature", "AuthTimestamp", "AuthNonce", "AuthTokenId"):
            assert campo not in clean
        assert clean["CommandLine"] == "whoami"


# ============================================================
# TOKEN DO RECEIVER
# ============================================================

class TestTokenDoReceiver:

    def test_token_forte_e_aceite(self):
        assert validate_auth_token(TOKEN) == TOKEN

    @pytest.mark.parametrize("placeholder", sorted(PLACEHOLDER_TOKENS))
    def test_placeholders_sao_recusados(self, placeholder):
        with pytest.raises(RuntimeError) as exc:
            validate_auth_token(placeholder)
        assert "valor por omissao" in str(exc.value)

    def test_mensagem_de_erro_menciona_change_me(self):
        with pytest.raises(RuntimeError) as exc:
            validate_auth_token("CHANGE_ME")
        assert "CHANGE_ME" in str(exc.value)

    def test_token_vazio_e_recusado(self):
        with pytest.raises(RuntimeError) as exc:
            validate_auth_token("")
        assert "receiver_auth_token" in str(exc.value)

    def test_run_server_recusa_change_me(self):
        with pytest.raises(RuntimeError, match="CHANGE_ME"):
            run_server("127.0.0.1", 0, "CHANGE_ME", {"receiver_tls_enabled": False})

    def test_run_server_recusa_token_vazio(self):
        with pytest.raises(RuntimeError, match="receiver_auth_token"):
            run_server("127.0.0.1", 0, "", {"receiver_tls_enabled": False})


# ============================================================
# TLS
# ============================================================

class TestTLS:

    def test_tls_desativado_devolve_none(self):
        assert build_tls_context({"receiver_tls_enabled": False}) is None

    def test_tls_sem_certificados_falha_com_mensagem_clara(self):
        with pytest.raises(RuntimeError) as exc:
            build_tls_context({"receiver_tls_enabled": True})
        mensagem = str(exc.value)
        assert "receiver_tls_certfile" in mensagem
        assert "receiver_tls_enabled: false" in mensagem


# ============================================================
# LIMITES DO RECEIVER
# ============================================================

class TestLimitesDoReceiver:

    def test_rate_limit_por_ip(self):
        rate_counters.clear()
        for _ in range(200):
            assert allow_event_from_ip("10.0.0.99") is True
        assert allow_event_from_ip("10.0.0.99") is False

    def test_nonce_repetido_e_rejeitado(self):
        seen_nonces.clear()
        assert accept_nonce("10.0.0.98", "nonce-1") is True
        assert accept_nonce("10.0.0.98", "nonce-1") is False

    def test_nonce_vazio_e_rejeitado(self):
        seen_nonces.clear()
        assert accept_nonce("10.0.0.98", "") is False


# ============================================================
# SERVIDOR (integracao minima em 127.0.0.1)
# ============================================================

def _porta_livre():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _arrancar_receiver(token):
    for _ in range(3):
        port = _porta_livre()
        threading.Thread(
            target=run_server,
            args=("127.0.0.1", port, token, {"receiver_tls_enabled": False}),
            daemon=True,
        ).start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return port
            except OSError:
                time.sleep(0.1)
    pytest.fail("receiver nao arrancou em 127.0.0.1")


def _enviar(port, payload):
    linha = payload if isinstance(payload, str) else json.dumps(payload) + "\n"
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.sendall(linha.encode("utf-8"))
        sock.settimeout(2)
        try:
            return sock.recv(4096)
        except socket.timeout:
            return None  # ligacao mantida aberta


@pytest.fixture(scope="module")
def receiver_port():
    rate_counters.clear()
    seen_nonces.clear()
    return _arrancar_receiver(TOKEN)


class TestServidorReceiver:

    def test_evento_sem_assinatura_termina_a_ligacao(self, receiver_port):
        assert _enviar(receiver_port, {"Computer": "HOST-A"}) == b""

    def test_evento_com_token_incorreto_termina_a_ligacao(self, receiver_port):
        assinado = attach_auth_token(make_event(), "token-errado")
        assert _enviar(receiver_port, assinado) == b""

    def test_evento_assinado_e_aceite(self, receiver_port):
        assinado = attach_auth_token(make_event(), TOKEN)
        assert _enviar(receiver_port, assinado) is None

    def test_replay_do_mesmo_evento_e_rejeitado(self, receiver_port):
        assinado = attach_auth_token(make_event(CommandLine="hostname"), TOKEN)
        assert _enviar(receiver_port, assinado) is None
        assert _enviar(receiver_port, assinado) == b""
