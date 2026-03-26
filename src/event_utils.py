from __future__ import annotations


AUTH_TOKEN_KEYS = ("AuthToken", "auth_token")


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


def attach_auth_token(event: dict, auth_token: str) -> dict:
    payload = dict(event)
    if auth_token:
        payload["AuthToken"] = auth_token
    return payload


def has_valid_auth_token(event: dict, expected_token: str) -> bool:
    if not expected_token:
        return True

    for key in AUTH_TOKEN_KEYS:
        if event.get(key) == expected_token:
            return True
    return False


def strip_auth_token(event: dict) -> dict:
    sanitized = dict(event)
    for key in AUTH_TOKEN_KEYS:
        sanitized.pop(key, None)
    return sanitized
