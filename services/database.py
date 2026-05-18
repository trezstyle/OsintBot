"""SQLite database for persistent storage (alerts, FIM, history)."""
import logging
import sqlite3
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from config import settings

log = logging.getLogger("cyber_volt.db")

_local = threading.local()
_DB_PATH: Path = settings.paths.base_dir / "bot.db"
_PRAGMAS = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;
"""


def get_db() -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.executescript(_PRAGMAS)
    return _local.conn


def init_db() -> None:
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS fim (
            path TEXT PRIMARY KEY,
            hash TEXT NOT NULL,
            added TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'file'
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'suricata',
            line TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            cmd TEXT NOT NULL,
            args TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            role TEXT NOT NULL DEFAULT 'admin',
            added TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            deadline TEXT,
            priority TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'pending',
            created TEXT NOT NULL,
            reminder_minutes INTEGER DEFAULT 1440,
            reminded INTEGER DEFAULT 0
        );
    """)
    db.commit()
    log.info("Database initialized at %s", _DB_PATH)


# ── FIM ──

def fim_load() -> dict[str, dict[str, Any]]:
    db = get_db()
    rows = db.execute("SELECT path, hash, added, type FROM fim").fetchall()
    return {r["path"]: {"hash": r["hash"], "added": r["added"], "type": r["type"]} for r in rows}


def fim_save_all(entries: dict[str, dict[str, Any]]) -> None:
    db = get_db()
    db.execute("DELETE FROM fim")
    db.executemany(
        "INSERT INTO fim (path, hash, added, type) VALUES (?, ?, ?, ?)",
        [(p, v["hash"], v.get("added", ""), v.get("type", "file")) for p, v in entries.items()],
    )
    db.commit()


def fim_upsert(path: str, hash_val: str, added: str, ftype: str = "file") -> None:
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO fim (path, hash, added, type) VALUES (?, ?, ?, ?)",
        (path, hash_val, added, ftype),
    )
    db.commit()


# ── Alerts ──

def push_alert(alert_time: str, line: str, alert_type: str = "suricata") -> None:
    db = get_db()
    db.execute("INSERT INTO alerts (time, type, line) VALUES (?, ?, ?)", (alert_time, alert_type, line))
    db.execute("DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 200)")
    db.commit()


def get_alerts(limit: int = 20) -> list[dict[str, Any]]:
    db = get_db()
    rows = db.execute("SELECT time, type, line FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# ── History ──

def record_command(user_id: int | None, username: str | None, cmd: str, args: str) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO history (time, user_id, username, cmd, args) VALUES (datetime('now'), ?, ?, ?, ?)",
        (user_id, username or "unknown", cmd, args),
    )
    db.execute("DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT 100)")
    db.commit()


def get_history(limit: int = 20) -> list[dict[str, Any]]:
    db = get_db()
    rows = db.execute(
        "SELECT time, user_id, username, cmd, args FROM history ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ── Users (role model) ──

def get_user(user_id: int) -> dict[str, Any] | None:
    row = get_db().execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def set_user(user_id: int, username: str, role: str = "admin") -> None:
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO users (user_id, username, role, added) VALUES (?, ?, ?, datetime('now'))",
        (user_id, username, role),
    )
    db.commit()


def delete_user(user_id: int) -> None:
    get_db().execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    get_db().commit()


def list_users() -> list[dict[str, Any]]:
    rows = get_db().execute("SELECT user_id, username, role, added FROM users ORDER BY added").fetchall()
    return [dict(r) for r in rows]


# ── Settings ──

def get_setting(key: str, default: str = "") -> str:
    row = get_db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    db.commit()
