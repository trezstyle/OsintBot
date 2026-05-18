"""Persistent alert storage — backed by SQLite."""
from datetime import datetime
from typing import Any

from services.database import get_alerts as _db_get_alerts
from services.database import get_history as _db_get_history
from services.database import push_alert as _db_push_alert
from services.database import record_command as _db_record_command


def push_alert(alert: dict[str, Any]) -> None:
    _db_push_alert(alert.get("time", datetime.now().isoformat()), alert.get("line", ""), alert.get("type", "suricata"))


def push_history(entry: dict[str, Any]) -> None:
    _db_record_command(
        entry.get("user_id"),
        entry.get("username", "unknown"),
        entry.get("cmd", ""),
        entry.get("args", ""),
    )


def get_alerts(limit: int = 20) -> list[dict[str, Any]]:
    return _db_get_alerts(limit)


def get_history(limit: int = 20) -> list[dict[str, Any]]:
    return _db_get_history(limit)


def record_command(user_id: int | None, username: str | None, cmd: str, args: str) -> None:
    _db_record_command(user_id, username, cmd, args)
