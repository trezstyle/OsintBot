"""Cyber-Volt SOC Bot entry point."""
import atexit
import logging
import os
from pathlib import Path
import sys
import threading
import time

from telebot.types import BotCommand

from config import settings
from logging_config import configure_logging
from runtime import polling_loop

log = configure_logging(log_file=settings.paths.bot_log_file)

from services.fim import fim_check
from services.notifier import send_message
from services.system import format_status
from ui.handlers import bot  # noqa: E402
from watchers import alert_watcher, suricata_watcher  # noqa: E402


def _atomic_write(path: Path, content: str) -> None:
    """Write content atomically using a temporary file."""
    tmp = path.with_suffix(".pid.tmp")
    try:
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def acquire_pid_guard():
    p = settings.paths.pid_file
    try:
        with open(p, "x") as f:
            f.write(str(os.getpid()))
    except FileExistsError:
        try:
            old = int(p.read_text(encoding="utf-8").strip())
            try:
                os.kill(old, 0)
                log.warning("Bot already running (PID %s), exiting", old)
                sys.exit(0)
            except OSError:
                pass
        except (ValueError, OSError):
            old = None
        _atomic_write(p, str(os.getpid()))


def cleanup_pid():
    try:
        settings.paths.pid_file.unlink(missing_ok=True)
    except OSError:
        pass


def cleanup_webhook():
    log.info("Cleaning up stale sessions...")
    for attempt in range(5):
        try:
            bot.remove_webhook()
            log.info(f"Webhook removed (attempt {attempt + 1})")
            return
        except Exception as e:
            log.warning(f"remove_webhook error: {e}")
            time.sleep(3)


def set_commands():
    data = [
        ("start", "🤖 Start the bot / greeting"),
        ("status", "🖥 System dashboard (CPU/RAM/Disk)"),
        ("logs", "📜 Log analysis (failed/sudo/ssh/attack)"),
        ("scan", "🕸 Network scan (fast / full)"), ("whois", "🏢 WHOIS lookup by domain"),
        ("recon", "🌐 Domain / IP reconnaissance"), ("fim", "📋 File Integrity Monitor (add/check)"),
        ("cve", "🧠 CVE vulnerability check for package"), ("hibp", "🔐 Breach search (email/domain)"),
        ("ssl", "🔒 SSL certificate check"), ("httpcheck", "🛡 HTTP security headers check"),
        ("bl", "⚫ DNSBL blacklist check"), ("bandwidth", "🌐 Network bandwidth by interface"),
        ("email", "📧 Email OSINT report"),
        ("tor", "🔍 Tor exit node check"), ("proxy", "🌐 Proxy/VPN and hosting check"),
        ("ctlogs", "📜 Certificate Transparency log summary"), ("phone", "📞 Phone number OSINT"),
        ("fw", "🛡 UFW firewall status and confirmed changes"), ("compliance", "✅ CIS compliance check"),
        ("mitre", "🧬 MITRE ATT&CK technique search"), ("report", "📄 Generate PDF report"),
        ("alerts", "🚨 View Suricata IDS alerts"),
        ("job", "🔍 Check status of a running job (e.g. /job abc123)"),
        ("history", "📋 Show command history or /history alerts"),
    ]
    bot.set_my_commands([BotCommand(cmd, desc) for cmd, desc in data])
    log.info(f"Set {len(data)} BotFather commands")


def _scheduler():
    """Run periodic tasks every 24 hours."""
    INTERVAL = 86400  # 24h
    while True:
        time.sleep(INTERVAL)
        try:
            log.info("Scheduler: running scheduled FIM check")
            fim_check()
        except Exception as e:
            log.error("Scheduler FIM failed: %s", e)


if __name__ == "__main__":
    threading.Thread(target=alert_watcher, daemon=True).start()
    threading.Thread(target=suricata_watcher, daemon=True).start()
    threading.Thread(target=_scheduler, daemon=True).start()
    acquire_pid_guard()
    atexit.register(cleanup_pid)
    cleanup_webhook()
    try:
        set_commands()
    except Exception as e:
        log.warning(f"Failed to set BotFather commands: {e}")
    time.sleep(5)
    log.info("Starting custom polling loop")
    polling_loop(bot)
