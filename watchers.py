"""Background alert watchers."""
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import os
import re
import threading
import time

from config import settings
from services.notifier import send_message
from services.system import recent_failed_logins
from services.threat_intel import get_abuseipdb_report, get_geoip, get_vt_report

log = logging.getLogger("cyber_volt")

# ── Shared state for auth brute-force detection ──
failed_attempts: dict[str, list] = defaultdict(list)
_failed_attempts_lock = threading.Lock()

# ── Synchronisation primitives shared with ui.handlers ──
ALERT_CHAT_ID_SET = threading.Event()
ALERT_CHAT_ID_LOCK = threading.Lock()
_alert_chat_id: int | None = None


def _set_alert_chat_id(cid: int) -> None:
    global _alert_chat_id
    with ALERT_CHAT_ID_LOCK:
        _alert_chat_id = cid
    ALERT_CHAT_ID_SET.set()


def _get_alert_chat_id() -> int | None:
    with ALERT_CHAT_ID_LOCK:
        return _alert_chat_id


# ── Auth log brute-force watcher ──

def alert_watcher() -> None:
    """Monitor auth.log for brute force attacks."""
    last_size = 0
    seen_lines: set[str] = set()
    while True:
        time.sleep(30)
        if not ALERT_CHAT_ID_SET.is_set():
            continue
        cid = _get_alert_chat_id()
        if not cid:
            continue

        path = str(settings.paths.auth_log_file)
        if not os.path.exists(path):
            continue
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            log.debug("alert_watcher: cannot stat auth.log: %s", exc)
            continue

        if size == last_size and seen_lines:
            continue
        if size < last_size:
            seen_lines.clear()
        last_size = size

        try:
            out = recent_failed_logins(20)
        except Exception as exc:
            log.debug("alert_watcher: recent_failed_logins failed: %s", exc)
            continue

        now = datetime.now()
        for line in out.strip().split("\n"):
            if not line:
                continue
            lk = line[:80]
            if lk in seen_lines:
                continue
            seen_lines.add(lk)
            if len(seen_lines) > 500:
                seen_lines.clear()

            m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if not m:
                continue
            ip = m.group(1)

            t = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
            if t:
                try:
                    if (now - datetime.fromisoformat(t.group(1))) > timedelta(minutes=10):
                        continue
                except ValueError:
                    pass

            with _failed_attempts_lock:
                failed_attempts[ip].append(now)

        # Check thresholds
        with _failed_attempts_lock:
            ips_to_check = list(failed_attempts.items())
            triggered = []
            for ip, times in ips_to_check:
                times[:] = [t for t in times if now - t < timedelta(minutes=5)]
                if len(times) >= 5:
                    triggered.append((ip, len(times)))
                    failed_attempts[ip] = []

        for ip, count in triggered:
            send_message(
                cid,
                f"🚨 *Brute Force Alert!*\nIP: `{ip}`\nAttempts: {count} in 5min",
                parse_mode="Markdown",
            )


# ── Suricata alert buffer — last N alerts ──
suricata_alerts: list[dict] = []
suricata_lock = threading.Lock()


def suricata_watcher() -> None:
    """Monitor Suricata fast.log for IDS alerts."""
    path = str(settings.paths.suricata_fast_log_file)
    seen: set[str] = set()
    while True:
        time.sleep(15)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
        except OSError as exc:
            log.debug("suricata_watcher: cannot read %s: %s", path, exc)
            continue

        now = datetime.now()
        lines = content.strip().splitlines()[-20:] if content.strip() else []

        for line in lines:
            if not line:
                continue
            sig = line.strip()
            if sig in seen:
                continue
            seen.add(sig)
            if len(seen) > 1000:
                seen.clear()

            with suricata_lock:
                suricata_alerts.append({"time": now, "line": sig})
                if len(suricata_alerts) > 50:
                    suricata_alerts.pop(0)

            ips = re.findall(r"\d+\.\d+\.\d+\.\d+", sig)

            urgent_keywords = [
                "ET MALWARE", "ET TROJAN", "ET EXPLOIT", "ET CNC",
                "MALWARE", "TROJAN", "CVE-", "SHELLCODE",
                "ET CNC", "DNS TUNNEL", "MYSQL", "RCE",
            ]
            if not any(k.lower() in sig.lower() for k in urgent_keywords):
                continue

            cid = _get_alert_chat_id() if ALERT_CHAT_ID_SET.is_set() else None
            if not cid:
                continue

            try:
                msg = f"🚨 *Suricata IDS Alert!*\n```\n{sig[:200]}\n```"
                if ips:
                    msg += f"\nSource IP: `{ips[0]}`"
                if len(ips) > 1:
                    msg += f" → Target: `{ips[1]}`"
                send_message(cid, msg, parse_mode="Markdown")
            except Exception:
                log.exception("Failed to send Suricata urgent alert")

            if ips:
                try:
                    vt = get_vt_report(ips[0])
                    abuse = get_abuseipdb_report(ips[0])
                    geo = get_geoip(ips[0])
                    report = f"🎯 *Auto Threat Hunt: `{ips[0]}`*\n\n{vt}\n\n{abuse}\n\n{geo}"
                    send_message(cid, report, parse_mode="Markdown")
                except Exception:
                    log.exception("Failed to send auto threat hunt")
