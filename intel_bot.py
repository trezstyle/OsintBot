"""Cyber-Volt SOC Bot entry point (aiogram 3.x)."""
import asyncio
import atexit
import logging
import os
from pathlib import Path
import signal
import sys
import threading
import time

from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.types import BotCommand
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

from config import settings
from logging_config import configure_logging

log = configure_logging(log_file=settings.paths.bot_log_file)

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

from services.i18n import set_locale
set_locale(settings.api.locale)

from services.metrics import (
    alerts_total,
    callback_total,
    cmd_duration,
    commands_total,
    errors_total,
    start_metrics_server,
    uptime_gauge,
)

from services.database import init_db
from services.fim import fim_check
from services.notifier import init_bot
from services.tasks import start_scheduler
from watchers import alert_watcher, suricata_watcher
from services.web_api import start_dashboard


SHUTDOWN_SIGNAL = threading.Event()


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
        BotCommand(command="users", description="👥 Manage users (admin only)"),
        BotCommand(command="task", description="📅 Task planner: /task, /task add ..., /task today"),
        BotCommand(command="tasks", description="📋 List tasks by status: /tasks pending"),
    ]
    await bot.set_my_commands(data)


def _scheduler():
    INTERVAL = 86400
    while not SHUTDOWN_SIGNAL.is_set():
        shutdown_waited = SHUTDOWN_SIGNAL.wait(INTERVAL)
        if shutdown_waited:
            break
        try:
            fim_check()
        except Exception as e:
            log.error("Scheduler FIM failed: %s", e)


def _uptime_tracker():
    while not SHUTDOWN_SIGNAL.is_set():
        uptime_gauge.set(time.monotonic())
        SHUTDOWN_SIGNAL.wait(15)


def _run_watcher(watcher_fn, name: str):
    try:
        watcher_fn()
    except Exception:
        log.exception("Watcher %s crashed", name)


async def cleanup_webhook(bot: Bot):
    log.info("Cleaning up stale webhook...")
    for attempt in range(5):
        try:
            await bot.delete_webhook()
            return
        except Exception as e:
            log.warning("delete_webhook error: %s", e)
            await asyncio.sleep(3)


def _handle_signal():
    log.info("Shutdown signal received, stopping...")
    SHUTDOWN_SIGNAL.set()


async def main():
    bot = Bot(token=settings.api.telegram_token, default=DefaultBotProperties(parse_mode="Markdown"))
    init_bot(bot)

    import ui.handlers as handlers_mod
    handlers_mod.bot = bot

    threads = [
        threading.Thread(target=_run_watcher, args=(alert_watcher, "alert_watcher"), daemon=True),
        threading.Thread(target=_run_watcher, args=(suricata_watcher, "suricata_watcher"), daemon=True),
        threading.Thread(target=_scheduler, daemon=True),
        threading.Thread(target=_uptime_tracker, daemon=True),
    ]
    for t in threads:
        t.start()

    try:
        start_metrics_server(settings.api.metrics_port)
    except Exception as e:
        log.warning("Metrics server failed: %s", e)

    if os.getenv("WEB_DASHBOARD_ENABLED", "").lower() in ("1", "true", "yes"):
        try:
            t = threading.Thread(target=start_dashboard, daemon=True)
            t.start()
        except Exception as e:
            log.warning("Web dashboard failed: %s", e)

    acquire_pid_guard()
    atexit.register(cleanup_pid)

    init_db()
    start_scheduler()

    from runtime import create_dispatcher
    dp = create_dispatcher(bot)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            pass

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
