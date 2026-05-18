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

log = configure_logging(log_file=settings.paths.bot_log_file)

# ── Sentry ──
if settings.api.sentry_dsn:
    try:
        import sentry_sdk

        sentry_sdk.init(
            dsn=settings.api.sentry_dsn,
            traces_sample_rate=0.1,
            environment=os.getenv("ENVIRONMENT", "production"),
        )
        log.info("Sentry SDK initialized")
    except Exception as e:
        log.warning("Sentry init failed: %s", e)

# ── i18n ──
from services.i18n import set_locale  # noqa: E402

set_locale(settings.api.locale)

# ── Metrics ──
from services.metrics import (  # noqa: E402
    alerts_total,
    callback_total,
    cmd_duration,
    commands_total,
    errors_total,
    start_metrics_server,
    uptime_gauge,
)

# ── Core imports ──
from runtime import polling_loop  # noqa: E402

from services.fim import fim_check  # noqa: E402
from ui.handlers import bot  # noqa: E402
from watchers import alert_watcher, suricata_watcher  # noqa: E402


def _atomic_write(path: Path, content: str) -> None:
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
    INTERVAL = 86400
    while True:
        time.sleep(INTERVAL)
        try:
            log.info("Scheduler: running scheduled FIM check")
            fim_check()
        except Exception as e:
            log.error("Scheduler FIM failed: %s", e)


def _start_webhook():
    """Start Flask webhook server in background thread."""
    import flask
    from telebot.types import Update

    app = flask.Flask(__name__)
    secret = os.getenv("WEBHOOK_SECRET", "")

    @app.route(f"/webhook/{settings.api.telegram_token}", methods=["POST"])
    def webhook():
        if flask.request.headers.get("X-Telegram-Bot-Api-Secret-Token", "") != secret:
            return "Unauthorized", 403
        update = Update.de_json(flask.request.get_json(force=True))
        if update.message:
            from runtime import dispatch_message

            dispatch_message(bot, update.message)
        elif update.callback_query:
            from runtime import dispatch_callback

            dispatch_callback(bot, update.callback_query)
        return "OK", 200

    app.run(host="0.0.0.0", port=settings.api.webhook_port, debug=False)


def _uptime_tracker():
    while True:
        uptime_gauge.set(time.monotonic())
        time.sleep(15)


if __name__ == "__main__":
    threading.Thread(target=alert_watcher, daemon=True).start()
    threading.Thread(target=suricata_watcher, daemon=True).start()
    threading.Thread(target=_scheduler, daemon=True).start()
    threading.Thread(target=_uptime_tracker, daemon=True).start()

    try:
        start_metrics_server(settings.api.metrics_port)
        log.info("Metrics server on port %d", settings.api.metrics_port)
    except Exception as e:
        log.warning("Metrics server failed: %s", e)

    acquire_pid_guard()
    atexit.register(cleanup_pid)

    # Webhook or polling mode
    if settings.api.webhook_url:
        cleanup_webhook()
        bot.set_webhook(
            url=f"{settings.api.webhook_url}/webhook/{settings.api.telegram_token}",
            secret_token=os.getenv("WEBHOOK_SECRET", ""),
        )
        log.info("Webhook set to %s", settings.api.webhook_url)
        try:
            set_commands()
        except Exception as e:
            log.warning("Failed to set BotFather commands: %s", e)
        _start_webhook()
    else:
        cleanup_webhook()
        try:
            set_commands()
        except Exception as e:
            log.warning("Failed to set BotFather commands: %s", e)
        time.sleep(5)
        log.info("Starting custom polling loop")
        polling_loop(bot)
