from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid

AUTH_TOKEN_KEYS = (
    "AuthToken",
    "auth_token",
    "AuthSignature",
    "AuthTimestamp",
    "AuthNonce",
    "AuthTokenId",
)
AUTH_WINDOW_SECONDS = 300


def normalize_event(event: dict) -> dict:
    normalized = dict(event)

    raw_event_id = normalized.get("EventID", normalized.get("EventId"))
    if raw_event_id not in (None, ""):
        normalized["EventID"] = str(raw_event_id)
        normalized.setdefault("EventId", normalized["EventID"])

    raw_record_id = normalized.get("RecordId", normalized.get("RecordID"))
    if raw_record_id not in (None, ""):
        try:
            normalized["RecordId"] = int(raw_record_id)
        except (TypeError, ValueError):
            normalized["RecordId"] = raw_record_id

    return normalized


def get_event_id_int(event: dict):
    raw_event_id = event.get("EventID", event.get("EventId"))
    if raw_event_id in (None, ""):
        return None
    try:
        return int(raw_event_id)
    except (TypeError, ValueError):
        return None


def _canonical_payload(event: dict) -> bytes:
    payload = {
        key: value
        for key, value in event.items()
        if key not in AUTH_TOKEN_KEYS
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _signature_base(event: dict, timestamp: str, nonce: str) -> bytes:
    return b"\n".join([
        timestamp.encode("utf-8"),
        nonce.encode("utf-8"),
        _canonical_payload(event),
    ])


def attach_auth_token(event: dict, auth_token: str) -> dict:
    payload = dict(event)
    if not auth_token:
        raise ValueError("receiver_auth_token e obrigatorio para assinar eventos")

    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    signature = hmac.new(
        auth_token.encode("utf-8"),
        _signature_base(payload, timestamp, nonce),
        hashlib.sha256,
    ).hexdigest()

    payload["AuthTimestamp"] = timestamp
    payload["AuthNonce"] = nonce
    payload["AuthSignature"] = signature
    payload["AuthTokenId"] = hashlib.sha256(auth_token.encode("utf-8")).hexdigest()[:10]
    return payload


def has_valid_auth_token(event: dict, expected_token: str) -> bool:
    if not expected_token:
        return False

    signature = str(event.get("AuthSignature", ""))
    timestamp = str(event.get("AuthTimestamp", ""))
    nonce = str(event.get("AuthNonce", ""))
    if not signature or not timestamp or not nonce:
        return False

    try:
        event_time = int(timestamp)
    except (TypeError, ValueError):
        return False

    if abs(int(time.time()) - event_time) > AUTH_WINDOW_SECONDS:
        return False

    expected_signature = hmac.new(
        expected_token.encode("utf-8"),
        _signature_base(event, timestamp, nonce),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)


def strip_auth_token(event: dict) -> dict:
    sanitized = dict(event)
    for key in AUTH_TOKEN_KEYS:
        sanitized.pop(key, None)
    return sanitized
