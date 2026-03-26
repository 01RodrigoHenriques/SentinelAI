from __future__ import annotations

import json
import os
from pathlib import Path

from runtime_paths import get_app_root, resolve_config_path


def _default_paths(file_path: str) -> tuple[Path, Path]:
    app_root = get_app_root(file_path)
    return app_root / "logs", app_root / "output" / "reports"


def build_default_config(file_path: str) -> dict:
    logs_dir, output_dir = _default_paths(file_path)
    return {
        "logs_folder": str(logs_dir),
        "output_folder": str(output_dir),
        "notifications": True,
        "discord_webhook": "",
        "receiver_server": "",
        "receiver_host": "0.0.0.0",
        "receiver_port": 9000,
        "receiver_auth_token": "",
    }


def get_config_path(file_path: str) -> Path:
    return resolve_config_path(file_path)


def _parse_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def _normalize_port(value, default: int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    if 1 <= port <= 65535:
        return port
    return default


def _normalize_path(value, fallback: Path, app_root: Path) -> str:
    raw_value = str(value).strip() if value is not None else ""
    if not raw_value:
        return str(fallback)

    candidate = Path(raw_value).expanduser()
    if not candidate.is_absolute():
        candidate = (app_root / candidate).resolve()
    return str(candidate)


def mask_secret(value: str, prefix: int = 6, suffix: int = 4) -> str:
    raw_value = str(value or "").strip()
    if not raw_value:
        return "Nao configurado"
    if len(raw_value) <= prefix + suffix:
        return "*" * len(raw_value)
    return f"{raw_value[:prefix]}...{raw_value[-suffix:]}"


def _apply_env_overrides(config: dict) -> dict:
    overridden = dict(config)
    env_map = {
        "logs_folder": "SENTINELAI_LOGS_DIR",
        "output_folder": "SENTINELAI_OUTPUT_DIR",
        "discord_webhook": "SENTINELAI_DISCORD_WEBHOOK",
        "receiver_server": "SENTINELAI_RECEIVER_SERVER",
        "receiver_host": "SENTINELAI_RECEIVER_HOST",
        "receiver_port": "SENTINELAI_RECEIVER_PORT",
        "receiver_auth_token": "SENTINELAI_RECEIVER_AUTH_TOKEN",
        "notifications": "SENTINELAI_NOTIFICATIONS",
    }

    for key, env_var in env_map.items():
        raw_value = os.getenv(env_var)
        if raw_value is not None:
            overridden[key] = raw_value

    return overridden


def normalize_config(config: dict, file_path: str) -> dict:
    defaults = build_default_config(file_path)
    app_root = get_app_root(file_path)
    merged = dict(defaults)
    merged.update(config or {})
    merged = _apply_env_overrides(merged)

    merged["logs_folder"] = _normalize_path(
        merged.get("logs_folder"),
        Path(defaults["logs_folder"]),
        app_root,
    )
    merged["output_folder"] = _normalize_path(
        merged.get("output_folder"),
        Path(defaults["output_folder"]),
        app_root,
    )
    merged["notifications"] = _parse_bool(
        merged.get("notifications"),
        defaults["notifications"],
    )
    merged["discord_webhook"] = str(merged.get("discord_webhook", "")).strip()
    merged["receiver_server"] = str(merged.get("receiver_server", "")).strip()
    merged["receiver_host"] = str(merged.get("receiver_host", "0.0.0.0")).strip() or "0.0.0.0"
    merged["receiver_port"] = _normalize_port(
        merged.get("receiver_port"),
        defaults["receiver_port"],
    )
    merged["receiver_auth_token"] = str(merged.get("receiver_auth_token", "")).strip()
    return merged


def ensure_runtime_dirs(config: dict):
    os.makedirs(config["logs_folder"], exist_ok=True)
    os.makedirs(config["output_folder"], exist_ok=True)


def load_app_config(file_path: str, create_if_missing: bool = False) -> dict:
    config_path = get_config_path(file_path)
    defaults = build_default_config(file_path)
    raw_config = {}

    if config_path.exists():
        try:
            with open(config_path, encoding="utf-8") as config_file:
                loaded = json.load(config_file)
            if isinstance(loaded, dict):
                raw_config = loaded
        except (json.JSONDecodeError, OSError):
            raw_config = {}
    elif create_if_missing:
        save_app_config(file_path, defaults)
        raw_config = defaults

    config = normalize_config(raw_config, file_path)
    ensure_runtime_dirs(config)
    return config


def save_app_config(file_path: str, config: dict):
    config_path = get_config_path(file_path)
    normalized = normalize_config(config, file_path)
    ensure_runtime_dirs(normalized)
    os.makedirs(config_path.parent, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as config_file:
        json.dump(normalized, config_file, indent=2, ensure_ascii=False)
