from __future__ import annotations

import os
import sys
from pathlib import Path


def get_source_dir(file_path: str) -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(file_path).resolve().parent


def get_app_root(file_path: str) -> Path:
    source_dir = get_source_dir(file_path)
    if getattr(sys, "frozen", False):
        return source_dir

    if source_dir.name.lower() == "src":
        project_root = source_dir.parent
        markers = ("requirements.txt", "models", "logs", "output")
        if any((project_root / marker).exists() for marker in markers):
            return project_root

    return source_dir


def resolve_config_path(file_path: str) -> Path:
    env_override = os.getenv("SENTINELAI_CONFIG_PATH", "").strip()
    if env_override:
        return Path(env_override).expanduser()

    app_root = get_app_root(file_path)
    source_dir = get_source_dir(file_path)

    if getattr(sys, "frozen", False):
        parent_dir = app_root.parent
        candidates = [
            app_root / "sentinelai_config.json",
            parent_dir / "sentinelai_config.json",
            parent_dir / "src" / "sentinelai_config.json",
            app_root / "sentinelai.config.json",
            parent_dir / "sentinelai.config.json",
            parent_dir / "src" / "sentinelai.config.json",
        ]
    else:
        candidates = [
            app_root / "sentinelai_config.json",
            source_dir / "sentinelai_config.json",
            app_root / "sentinelai.config.json",
            source_dir / "sentinelai.config.json",
        ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    # In source mode keep config near the Python files for compatibility.
    if source_dir != app_root:
        return source_dir / "sentinelai_config.json"
    return app_root / "sentinelai_config.json"
