"""Cyber-Volt SOC Bot entry point."""
import atexit
import logging
import os
import sys
import threading
import time

from telebot.types import BotCommand

from config import settings
from runtime import polling_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(settings.paths.bot_log_file), logging.StreamHandler()],
)
log = logging.getLogger("cyber_volt")

from ui.handlers import bot  # noqa: E402
from watchers import alert_watcher, suricata_watcher  # noqa: E402


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
                log.warning(f"Bot already running (PID {old}), exiting")
                sys.exit(0)
            except OSError:
                pass
            p.unlink(missing_ok=True)
            p.write_text(str(os.getpid()), encoding="utf-8")
        except (ValueError, OSError):
            pass


def cleanup_pid():
    try:
        settings.paths.pid_file.unlink(missing_ok=True)
    except Exception:
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
        ("start", "🤖 Start the bot / greeting"), ("help", "📖 Open menu with all functions"),
        ("status", "🖥 System dashboard (CPU/RAM/Disk)"), ("top", "📊 Top processes by CPU/RAM"),
        ("logs", "📜 Log analysis (failed/sudo/ssh/attack)"), ("audit", "🛡 BSI Compliance Audit"),
        ("scan", "🕸 Network scan (fast / full)"), ("whois", "🏢 WHOIS lookup by domain"),
        ("recon", "🌐 Domain / IP reconnaissance"), ("fim", "📋 File Integrity Monitor (add/check)"),
        ("cve", "🧠 CVE vulnerability check for package"), ("hibp", "🔐 Breach search (email/domain)"),
        ("mitre", "🧬 MITRE ATT&CK technique search"), ("report", "📄 Generate PDF report"),
        ("alerts", "🚨 View Suricata IDS alerts"),
    ]
    bot.set_my_commands([BotCommand(cmd, desc) for cmd, desc in data])
    log.info(f"Set {len(data)} BotFather commands")


if __name__ == "__main__":
    threading.Thread(target=alert_watcher, daemon=True).start()
    threading.Thread(target=suricata_watcher, daemon=True).start()
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
