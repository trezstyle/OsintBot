"""Standalone healthcheck for Cyber-Volt SOC Bot."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import psutil


def _pid_file() -> Path:
    return Path(os.getenv("PID_FILE", Path(__file__).resolve().parent / "bot.pid"))


def _format_uptime(seconds: float) -> str:
    total = max(0, int(seconds))
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h {minutes}m {seconds}s"
    return f"{hours}h {minutes}m {seconds}s"


def _check_process() -> tuple[bool, int | None, str | None, str]:
    path = _pid_file()
    if not path.exists():
        return False, None, "pid_file_missing", "0h 0m 0s"
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
        process = psutil.Process(pid)
        if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
            return False, pid, "process_not_running", "0h 0m 0s"
        return True, pid, None, _format_uptime(time.time() - process.create_time())
    except (ValueError, psutil.Error, OSError) as exc:
        return False, None, type(exc).__name__, "0h 0m 0s"


def _check_telegram() -> tuple[bool, str | None]:
    token = os.getenv("TELEGRAM_TOKEN", "").strip()
    if not token:
        return False, "telegram_token_missing"
    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        with urllib.request.urlopen(url, timeout=8) as response:
            if response.status != 200:
                return False, f"telegram_status_{response.status}"
            payload = json.loads(response.read().decode("utf-8"))
            if not payload.get("ok"):
                return False, "telegram_not_ok"
            return True, None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return False, type(exc).__name__


def check_health() -> tuple[dict[str, Any], int]:
    process_ok, pid, process_error, uptime = _check_process()
    telegram_ok, telegram_error = _check_telegram()
    ok = process_ok and telegram_ok
    payload: dict[str, Any] = {
        "status": "ok" if ok else "error",
        "uptime": uptime,
        "checks": {
            "process": {"ok": process_ok, "pid": pid, "error": process_error},
            "telegram_api": {"ok": telegram_ok, "error": telegram_error},
        },
    }
    return payload, 0 if ok else 1


def main() -> int:
    payload, code = check_health()
    print(json.dumps(payload, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
