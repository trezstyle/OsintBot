"""Persistent alert storage — stores Suricata alerts and command history in JSON."""
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from config import settings

log = logging.getLogger("cyber_volt.alert_store")

ALERT_DB = settings.paths.base_dir / "alert_history.json"
MAX_ALERTS = 200
MAX_HISTORY = 100


def _load() -> dict[str, Any]:
    try:
        if ALERT_DB.exists():
            data = json.loads(ALERT_DB.read_text())
            if isinstance(data.get("alerts"), list) and isinstance(data.get("history"), list):
                return data
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Corrupt alert DB, resetting: %s", e)
    return {"alerts": [], "history": []}


def _save(data: dict[str, Any]) -> None:
    tmp = ALERT_DB.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, default=str, ensure_ascii=False))
        tmp.replace(ALERT_DB)
    except OSError as e:
        log.error("Failed to write alert DB: %s", e)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def push_alert(alert: dict[str, Any]) -> None:
    data = _load()
    data["alerts"].append(alert)
    if len(data["alerts"]) > MAX_ALERTS:
        data["alerts"] = data["alerts"][-MAX_ALERTS:]
    _save(data)


def push_history(entry: dict[str, Any]) -> None:
    data = _load()
    data["history"].append(entry)
    if len(data["history"]) > MAX_HISTORY:
        data["history"] = data["history"][-MAX_HISTORY:]
    _save(data)


def get_alerts(limit: int = 20) -> list[dict[str, Any]]:
    data = _load()
    return list(reversed(data["alerts"][-limit:]))


def get_history(limit: int = 20) -> list[dict[str, Any]]:
    data = _load()
    return list(reversed(data["history"][-limit:]))


def record_command(user_id: int, username: str, cmd: str, args: str) -> None:
    push_history({
        "time": datetime.now().isoformat(),
        "user_id": user_id,
        "username": username or "unknown",
        "cmd": cmd,
        "args": args,
    })
