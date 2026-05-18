"""Cyber-Volt SOC Bot entry point (aiogram 3.x)."""
import asyncio
import atexit
import logging
import os
from pathlib import Path
import sys
import threading
import time

from aiogram import Bot
from aiogram.types import BotCommand
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

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
from services.i18n import set_locale

set_locale(settings.api.locale)

# ── Metrics ──
from services.metrics import (
    alerts_total,
    callback_total,
    cmd_duration,
    commands_total,
    errors_total,
    start_metrics_server,
    uptime_gauge,
)

# ── Core imports ──
from services.fim import fim_check
from services.notifier import init_bot
from watchers import alert_watcher, suricata_watcher

# ── Web dashboard ──
from services.web_api import start_dashboard


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


async def set_commands(bot: Bot):
    data = [
        BotCommand(command="start", description="🤖 Start the bot / greeting"),
        BotCommand(command="status", description="🖥 System dashboard (CPU/RAM/Disk)"),
        BotCommand(command="logs", description="📜 Log analysis (failed/sudo/ssh/attack)"),
        BotCommand(command="scan", description="🕸 Network scan (fast / full)"),
        BotCommand(command="whois", description="🏢 WHOIS lookup by domain"),
        BotCommand(command="recon", description="🌐 Domain / IP reconnaissance"),
        BotCommand(command="fim", description="📋 File Integrity Monitor (add/check)"),
        BotCommand(command="cve", description="🧠 CVE vulnerability check for package"),
        BotCommand(command="hibp", description="🔐 Breach search (email/domain)"),
        BotCommand(command="ssl", description="🔒 SSL certificate check"),
        BotCommand(command="httpcheck", description="🛡 HTTP security headers check"),
        BotCommand(command="bl", description="⚫ DNSBL blacklist check"),
        BotCommand(command="bandwidth", description="🌐 Network bandwidth by interface"),
        BotCommand(command="email", description="📧 Email OSINT report"),
        BotCommand(command="tor", description="🔍 Tor exit node check"),
        BotCommand(command="proxy", description="🌐 Proxy/VPN and hosting check"),
        BotCommand(command="ctlogs", description="📜 Certificate Transparency log summary"),
        BotCommand(command="phone", description="📞 Phone number OSINT"),
        BotCommand(command="fw", description="🛡 UFW firewall status and confirmed changes"),
        BotCommand(command="compliance", description="✅ CIS compliance check"),
        BotCommand(command="mitre", description="🧬 MITRE ATT&CK technique search"),
        BotCommand(command="report", description="📄 Generate PDF report"),
        BotCommand(command="alerts", description="🚨 View Suricata IDS alerts"),
        BotCommand(command="job", description="🔍 Check status of a running job"),
        BotCommand(command="history", description="📋 Show command history or /history alerts"),
    ]
    await bot.set_my_commands(data)
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


def _uptime_tracker():
    while True:
        uptime_gauge.set(time.monotonic())
        time.sleep(15)


async def cleanup_webhook(bot: Bot):
    log.info("Cleaning up stale webhook...")
    for attempt in range(5):
        try:
            await bot.delete_webhook()
            log.info(f"Webhook removed (attempt {attempt + 1})")
            return
        except Exception as e:
            log.warning(f"delete_webhook error: {e}")
            await asyncio.sleep(3)


async def main():
    # Build aiogram Bot
    bot = Bot(token=settings.api.telegram_token, parse_mode="Markdown")
    init_bot(bot)

    # Patch ui.handlers.bot reference (set by import, but needs actual Bot instance)
    import ui.handlers as handlers_mod
    handlers_mod.bot = bot

    # Start background threads
    threading.Thread(target=alert_watcher, daemon=True).start()
    threading.Thread(target=suricata_watcher, daemon=True).start()
    threading.Thread(target=_scheduler, daemon=True).start()
    threading.Thread(target=_uptime_tracker, daemon=True).start()

    try:
        start_metrics_server(settings.api.metrics_port)
        log.info("Metrics server on port %d", settings.api.metrics_port)
    except Exception as e:
        log.warning("Metrics server failed: %s", e)

    # Start web dashboard (Flask in background thread)
    try:
        if os.getenv("WEB_DASHBOARD_ENABLED", "").lower() in ("1", "true", "yes"):
            t = threading.Thread(target=start_dashboard, daemon=True)
            t.start()
            log.info("Web dashboard started")
    except Exception as e:
        log.warning("Web dashboard failed: %s", e)

    acquire_pid_guard()
    atexit.register(cleanup_pid)

    from runtime import create_dispatcher
    dp = create_dispatcher(bot)

    # Webhook or polling mode
    if settings.api.webhook_url:
        await cleanup_webhook(bot)
        await bot.set_webhook(
            url=f"{settings.api.webhook_url}/webhook/{settings.api.telegram_token}",
            secret_token=os.getenv("WEBHOOK_SECRET", ""),
        )
        log.info("Webhook set to %s", settings.api.webhook_url)
        await set_commands(bot)

        app = web.Application()
        SimpleRequestHandler(dispatcher=dp, bot=bot).register(app, path=f"/webhook/{settings.api.telegram_token}")
        setup_application(app, dp, bot=bot)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host="0.0.0.0", port=settings.api.webhook_port)
        await site.start()
        log.info("Webhook server on port %d", settings.api.webhook_port)
        await asyncio.Event().wait()
    else:
        await cleanup_webhook(bot)
        await set_commands(bot)
        log.info("Starting aiogram polling")
        await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("Bot shutting down")
