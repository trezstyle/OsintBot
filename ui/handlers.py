"""Telegram UI handlers for Cyber-Volt SOC Bot (aiogram 3.x)."""
import logging
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from aiogram import Bot, F, Router
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

import security
from config import settings
from services.bot_states import BotStates
from services.fim import fim_add, fim_check
from services.notifier import init_bot
from services.alert_store import get_alerts, get_history, record_command
from services.i18n import t
from services.metrics import callback_total, cmd_duration, commands_total, errors_total
from services.rate_limit import _get_user_id, _heavy
from services.reporting import generate_report
from services.scanner import scan_network
from services.system import analyze_logs, check_cve, format_bandwidth, format_compliance, format_firewall, format_status, format_top
from services.threat_intel import (attack_simulation, check_blacklist, check_ctlogs, check_email,
                                    check_hash, check_hibp, check_http_headers, check_phone, check_proxy,
                                    check_ssl, check_tor, check_urlscan, get_whois, mitre_lookup,
                                    threat_hunt_domain, threat_hunt_ip)
from ui.keyboards import fim_keyboard, help_keyboard, logs_keyboard, menu_text, scan_keyboard, top_keyboard
from watchers import suricata_alerts, suricata_lock, _set_alert_chat_id

log = logging.getLogger("cyber_volt")
security.load_authorization()

UNAUTHORIZED_TEXT = settings.unauthorized_text
MAX_MSG_LEN = 4096

router = Router()
bot: Bot = None  # set in intel_bot.py via init_bot

_CMD_TABLE = {
    "ssl": {
        "fn": check_ssl,
        "prompt": "🔒 *Enter domain for SSL check:*",
        "validate": security.validate_domain,
        "success_msg": "🔒 *Checking SSL for `{arg}`...*",
    },
    "httpcheck": {
        "fn": check_http_headers,
        "prompt": "🛡 *Enter domain or URL for HTTP header check:*",
        "validate": security.validate_domain,
        "validate_transform": lambda a: a.replace("https://", "").replace("http://", "").split("/")[0] if a else a,
        "success_msg": "🛡 *Checking HTTP headers for `{arg}`...*",
    },
    "bl": {
        "fn": check_blacklist,
        "prompt": "⚫ *Enter IP address for blacklist check:*",
        "validate": security.validate_ip,
        "success_msg": "⚫ *Checking DNSBLs for `{arg}`...*",
    },
    "email": {
        "fn": check_email,
        "prompt": "📧 *Enter email address for OSINT:*",
        "validate": None,
        "success_msg": "📧 *Running Email OSINT for `{arg}`...*",
    },
    "tor": {
        "fn": check_tor,
        "prompt": "🔍 *Enter IP address for Tor check:*",
        "validate": security.validate_ip,
        "success_msg": "🔍 *Checking Tor exit status for `{arg}`...*",
    },
    "proxy": {
        "fn": check_proxy,
        "prompt": "🌐 *Enter IP address for Proxy/VPN check:*",
        "validate": security.validate_ip,
        "success_msg": "🌐 *Checking Proxy/VPN status for `{arg}`...*",
    },
    "ctlogs": {
        "fn": check_ctlogs,
        "prompt": "📜 *Enter domain for CT logs:*",
        "validate": security.validate_domain,
        "success_msg": "📜 *Checking CT logs for `{arg}`...*",
    },
    "phone": {
        "fn": check_phone,
        "prompt": "📞 *Enter phone number:*\nExample: `+491234567`",
        "validate": None,
        "success_msg": None,
    },
    "whois": {
        "fn": get_whois,
        "prompt": "🕵️ *Enter a domain for WHOIS:*",
        "validate": security.validate_domain,
        "success_msg": None,
    },
    "hash": {
        "fn": check_hash,
        "prompt": "🔑 *Enter hash (MD5/SHA1/SHA256):*",
        "validate": None,
        "validate_transform": lambda a: a.lower().strip(),
        "success_msg": "🔑 *Checking hash `{arg}` on VirusTotal...*",
    },
    "urlscan": {
        "fn": check_urlscan,
        "prompt": "🔗 *Enter URL to scan:*\nExample: `https://example.com`",
        "validate": None,
        "success_msg": "🔗 *Scanning `{arg}` on VirusTotal...*",
    },
    "attack": {
        "fn": attack_simulation,
        "prompt": "🧬 *Enter MITRE technique ID:*\nExample: `T1059`",
        "validate": None,
        "success_msg": "🧬 *Simulating attack technique `{arg}`...*",
    },
}


def escape_md(text: str) -> str:
    for ch in ("_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"):
        text = text.replace(ch, "\\" + ch)
    return text


def _close_code_blocks(text):
    return text + "\n```" if text.count("```") % 2 else text


async def send_long_message(chat_id, text, parse_mode=None, reply_markup=None):
    if len(text) <= MAX_MSG_LEN:
        return await bot.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup)
    parts = []
    while text:
        if len(text) <= MAX_MSG_LEN:
            parts.append(text)
            break
        split_at = text.rfind("\n", 0, MAX_MSG_LEN)
        if split_at == -1:
            split_at = MAX_MSG_LEN
        chunk = text[:split_at]
        if chunk.count("```") % 2:
            chunk += "\n```"
            split_at = text.rfind("\n", 0, split_at + 4)
            if split_at == -1:
                split_at = text.find("\n", split_at + 4)
                if split_at == -1:
                    split_at = MAX_MSG_LEN
            chunk = text[:split_at]
            if chunk.count("```") % 2:
                chunk += "\n```"
        parts.append(chunk)
        text = text[split_at:]
    msg = None
    for i, part in enumerate(parts):
        markup = reply_markup if i == len(parts) - 1 else None
        part = _close_code_blocks(part)
        msg = await bot.send_message(chat_id, part, parse_mode=parse_mode, reply_markup=markup)
    return msg


# ── Authorization ──

async def is_message_authorized(message: Message) -> bool:
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    chat_id = getattr(getattr(message, "chat", None), "id", None)
    if security.is_authorized(user_id, chat_id):
        return True
    await message.answer(UNAUTHORIZED_TEXT)
    return False


async def is_callback_authorized(call: CallbackQuery) -> bool:
    user_id = getattr(getattr(call, "from_user", None), "id", None)
    if security.is_authorized(user_id, None):
        return True
    try:
        await call.answer("❌ Unauthorized")
    except Exception:
        pass
    return False


def authorized_message(func):
    @wraps(func)
    async def wrapper(message: Message, **kwargs):
        if not await is_message_authorized(message):
            return
        return await func(message, **kwargs)
    return wrapper


def authorized_callback(func):
    @wraps(func)
    async def wrapper(call: CallbackQuery, **kwargs):
        if not await is_callback_authorized(call):
            return
        return await func(call, **kwargs)
    return wrapper


def admin_required(func):
    """Decorator: authorized + must be admin for dangerous commands."""
    @wraps(func)
    async def wrapper(message: Message, **kwargs):
        if not await is_message_authorized(message):
            return
        uid = getattr(getattr(message, "from_user", None), "id", None)
        if uid and not security.is_admin(uid):
            await message.answer("❌ This command requires admin privileges.")
            return
        return await func(message, **kwargs)
    return wrapper


# ── Handlers ──

LOGO = """```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗
██║     ██║   ██║██████╔╝█████╗  ██████╔╝
██║     ╚██╗ ██╔╝██╔══██╗██╔══╝  ██╔══██╗
╚██████╗ ╚████╔╝ ██████╔╝███████╗██║  ██║
 ╚═════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
```"""


@router.message(Command("users"))
@authorized_message
async def cmd_users(message: Message):
    """Manage authorized users: /users, /users add <id> <role>, /users del <id>"""
    from services.database import delete_user, list_users, set_user
    uid = getattr(getattr(message, "from_user", None), "id", None)
    if uid and not security.is_admin(uid):
        await message.answer("❌ Admin privileges required.")
        return
    args = message.text.split()[1:]
    if not args:
        users = list_users()
        if not users:
            await message.answer("📋 *Users*\nNo users in database. Auth via ALLOWED_USERS in .env", parse_mode="Markdown")
        else:
            lines = [f"📋 *Users ({len(users)})*"]
            for u in users:
                lines.append(f"`{u['user_id']}` — *{u['role']}* — @{u['username'] or '?'} — _{u['added'][:10]}_")
            await send_long_message(message.chat.id, "\n".join(lines), parse_mode="Markdown")
        return

    action = args[0]
    if action == "add" and len(args) >= 3:
        try:
            target_id = int(args[1])
            role = args[2].lower()
            if role not in ("admin", "readonly", "observer"):
                await message.answer("❌ Role must be: `admin`, `readonly`, or `observer`")
                return
            username = args[3] if len(args) > 3 else "cli"
            set_user(target_id, username, role)
            await message.answer(f"✅ User `{target_id}` added as *{role}*", parse_mode="Markdown")
        except ValueError:
            await message.answer("❌ Invalid user ID. Usage: `/users add <id> <role> [username]`")
    elif action == "del" and len(args) >= 2:
        try:
            target_id = int(args[1])
            delete_user(target_id)
            await message.answer(f"✅ User `{target_id}` removed", parse_mode="Markdown")
        except ValueError:
            await message.answer("❌ Invalid user ID. Usage: `/users del <id>`")
    else:
        await message.answer("Usage:\n`/users` — list\n`/users add <id> <role>` — add user\n`/users del <id>` — remove", parse_mode="Markdown")


@router.message(Command("start"))
@authorized_message
async def cmd_start(message: Message):
    _set_alert_chat_id(message.chat.id)
    await message.answer(
        f"{LOGO}\n🤖 *Cyber-Volt SOC Master v3.0*\n\nFull-featured SOC platform in Telegram.\n\nUse /start to open the menu.",
        parse_mode="Markdown",
        reply_markup=help_keyboard(),
    )


COMMAND_LIST = [
    "status", "top", "logs", "whois", "recon", "scan", "fim", "cve", "hibp",
    "mitre", "report", "alerts", "ssl", "httpcheck", "bl", "bandwidth",
    "email", "tor", "proxy", "ctlogs", "phone", "fw", "compliance",
    "hash", "urlscan", "attack", "job", "history", "users",
    "task", "tasks",
]


@router.message(Command(*COMMAND_LIST))
@authorized_message
async def cmd_handler(message: Message, command: CommandObject, state: FSMContext):
    _set_alert_chat_id(message.chat.id)
    cmd = command.command
    args = command.args.split() if command.args else []

    commands_total.labels(command=cmd).inc()
    _t0 = time.monotonic()

    record_command(
        getattr(getattr(message, "from_user", None), "id", None),
        getattr(getattr(message, "from_user", None), "username", None),
        cmd,
        " ".join(args),
    )

    uid = _get_user_id(message)
    if cmd in ("scan", "report", "fw", "compliance") and uid is not None:
        if not _heavy.is_allowed(uid):
            await message.answer(t("rate_limit"), parse_mode="Markdown")
            return

    # Admin-only commands
    if cmd in ("fw", "scan", "report", "users"):
        uid = getattr(getattr(message, "from_user", None), "id", None)
        if uid and not security.is_admin(uid):
            await message.answer("❌ This command requires admin privileges.")
            return

    try:
        if cmd == "status":
            await send_long_message(message.chat.id, format_status(), parse_mode="Markdown")
        elif cmd == "top":
            sort = args[0] if args and args[0] in ("cpu", "ram", "pid", "name") else "cpu"
            await send_long_message(message.chat.id, format_top(sort), parse_mode="Markdown", reply_markup=top_keyboard(sort))
        elif cmd == "bandwidth":
            await send_long_message(message.chat.id, format_bandwidth(), parse_mode="Markdown")
        elif cmd == "logs":
            if args:
                await send_long_message(message.chat.id, analyze_logs(args[0]), parse_mode="Markdown")
            else:
                await message.answer("📊 *Choose log filter:*", parse_mode="Markdown", reply_markup=logs_keyboard())
        elif cmd == "recon":
            if args:
                await process_domain_hunt_inner(message)
            else:
                await message.answer("🌐 *Enter a domain or IP:*", parse_mode="Markdown")
                await state.set_state(BotStates.waiting_for_domain)
        elif cmd == "scan":
            if args:
                fast = "fast" in args
                target = [a for a in args if a != "fast"][0] if fast else args[0]
                if fast:
                    await message.answer(f"⚡ *Fast scan `{target}`...*", parse_mode="Markdown")
                    await send_long_message(message.chat.id, scan_network(target, all_ports=False), parse_mode="Markdown")
                else:
                    await message.answer(f"🔍 *Full scan `{target}`...* ~5-10 min ⏳", parse_mode="Markdown")
                    await send_long_message(message.chat.id, scan_network(target, all_ports=True), parse_mode="Markdown")
            else:
                await message.answer("🕸 *Choose scan mode:*", parse_mode="Markdown", reply_markup=scan_keyboard())
        elif cmd == "fim":
            if len(args) >= 2 and args[0] == "add":
                await send_long_message(message.chat.id, fim_add(" ".join(args[1:])), parse_mode="Markdown")
            elif args and args[0] == "check":
                await send_long_message(message.chat.id, fim_check(), parse_mode="Markdown")
            else:
                await message.answer("📋 *File Integrity Monitor*", parse_mode="Markdown", reply_markup=fim_keyboard())
        elif cmd == "cve":
            if args:
                await send_long_message(message.chat.id, check_cve(args[0]), parse_mode="Markdown")
            else:
                await message.answer("🧠 *Enter package name:*\nExample: `openssl`", parse_mode="Markdown")
                await state.set_state(BotStates.waiting_for_package)
        elif cmd == "hibp":
            if args:
                await send_long_message(message.chat.id, check_hibp(args[0]), parse_mode="Markdown")
            else:
                await message.answer("🔐 *Enter email or domain:*", parse_mode="Markdown")
                await state.set_state(BotStates.waiting_for_hibp_input)
        elif cmd == "fw":
            action = args[0] if args else "status"
            fw_args = " ".join(args[1:]) if len(args) > 1 else ""
            if action in ("allow", "deny", "delete") and fw_args:
                from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
                confirm_data = f"fw_confirm_{action}_{fw_args}"
                kb = InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="✅ Confirm", callback_data=confirm_data),
                     InlineKeyboardButton(text="❌ Cancel", callback_data="h_menu")],
                ])
                await message.answer(
                    f"⚠️ *Confirm firewall change:*\n`ufw {action} {fw_args}`",
                    parse_mode="Markdown",
                    reply_markup=kb,
                )
            else:
                await send_long_message(message.chat.id, format_firewall(action, fw_args), parse_mode="Markdown")
        elif cmd == "compliance":
            await send_long_message(message.chat.id, format_compliance(), parse_mode="Markdown")
        elif cmd == "mitre":
            if args:
                await send_long_message(message.chat.id, mitre_lookup(args[0]), parse_mode="Markdown")
            else:
                await message.answer("🧬 *Enter technique ID:*\nExample: `T1059`", parse_mode="Markdown")
                await state.set_state(BotStates.waiting_for_mitre_technique)
        elif cmd == "report":
            await message.answer("📄 *Generating PDF report...*")
            result = generate_report()
            if isinstance(result, str) and Path(result).exists():
                with open(result, "rb") as f:
                    await bot.send_document(message.chat.id, f, caption="📄 Cyber-Volt SOC Report")
            else:
                await message.answer(f"❌ {result}")
        elif cmd == "alerts":
            with suricata_lock:
                if not suricata_alerts:
                    await message.answer(
                        f"📋 *Suricata Alerts*\nNo alerts recorded yet.\n"
                        f"Make sure Suricata is installed and logging to `{settings.paths.suricata_fast_log_file}`",
                        parse_mode="Markdown",
                    )
                else:
                    lines = ["📋 *Recent Suricata Alerts*", f"Total: {len(suricata_alerts)} alerts\n"]
                    for a in reversed(suricata_alerts[-10:]):
                        stamp = a["time"].strftime("%H:%M:%S")
                        lines.append(f"`{stamp}` {escape_md(a['line'][:80])}")
                    await send_long_message(message.chat.id, "\n".join(lines), parse_mode="Markdown")
        elif cmd == "history":
            sub = args[0] if args else "commands"
            if sub == "alerts":
                alerts = get_alerts(15)
                if not alerts:
                    await message.answer(t("no_alerts"), parse_mode="Markdown")
                else:
                    lines = ["📋 *Recent Alerts*", f"Total: {len(alerts)}\n"]
                    for a in alerts:
                        stamp = a.get("time", "?")[11:19]
                        s = escape_md(a.get("line", "?")[:80])
                        lines.append(f"`{stamp}` {s}")
                    await send_long_message(message.chat.id, "\n".join(lines), parse_mode="Markdown")
            else:
                entries = get_history(15)
                if not entries:
                    await message.answer(t("no_history"), parse_mode="Markdown")
                else:
                    lines = ["📋 *Recent Commands*", f"Total: {len(entries)}\n"]
                    for e in entries:
                        stamp = e.get("time", "?")[11:19]
                        u = escape_md(e.get("username", "?")[:15])
                        c = escape_md(e.get("cmd", "?"))
                        a = escape_md(e.get("args", "")[:30])
                        lines.append(f"`{stamp}` *{c}* {a} — {u}")
                    await send_long_message(message.chat.id, "\n".join(lines), parse_mode="Markdown")
        elif cmd == "job":
            from services.job_queue import format_job_status
            job_id = args[0] if args else ""
            if not job_id:
                await message.answer(t("job_usage"), parse_mode="Markdown")
            else:
                await send_long_message(message.chat.id, format_job_status(job_id), parse_mode="Markdown")
        elif cmd in ("task", "tasks"):
            from ui.task_handlers import cmd_task
            await cmd_task(message, command=command)
        elif cmd in _CMD_TABLE:
            config = _CMD_TABLE[cmd]
            if args:
                arg = args[0]
                validate_fn = config.get("validate")
                if validate_fn:
                    transform = config.get("validate_transform")
                    check_arg = transform(arg) if transform else arg
                    if not validate_fn(check_arg):
                        await message.answer(f"❌ Invalid input: `{arg}`")
                        return
                await send_long_message(message.chat.id, config["fn"](arg), parse_mode="Markdown")
            else:
                await message.answer(config["prompt"], parse_mode="Markdown")
                await state.update_data(table_cmd=cmd)
                await state.set_state(BotStates.waiting_for_from_table)
        cmd_duration.labels(command=cmd).observe(time.monotonic() - _t0)
    except Exception as e:
        log.error(f"cmd_handler({cmd}): {e}")
        errors_total.labels(type=type(e).__name__).inc()
        await message.answer(f"❌ Error: {e}")
        cmd_duration.labels(command=cmd).observe(time.monotonic() - _t0)


# ── Auto threat hunt (text not starting with /) ──

@router.message(lambda msg: msg.text and not msg.text.startswith("/"))
@authorized_message
async def fsm_task_title_handler(message: Message, state: FSMContext):
    from ui.task_handlers import TaskStates, fsm_task_title
    cur = await state.get_state()
    if cur != TaskStates.waiting_for_title.state:
        return
    await fsm_task_title(message, state)


@router.message(F.text)
@authorized_message
async def auto_threat_hunt(message: Message):
    _set_alert_chat_id(message.chat.id)
    text = message.text.strip()
    if text.startswith("/"):
        return

    ip = security.validate_ip(text)
    if ip:
        await message.answer(f"🎯 *IP detected:* `{ip}`\nRunning threat hunt...", parse_mode="Markdown")
        await send_long_message(message.chat.id, threat_hunt_ip(ip), parse_mode="Markdown")
        return

    domain = security.validate_domain(text)
    if domain:
        await message.answer(f"🌐 *Domain detected:* `{domain}`\nRunning recon...", parse_mode="Markdown")
        await send_long_message(message.chat.id, threat_hunt_domain(domain), parse_mode="Markdown")
        return


# ── Callbacks ──

@router.callback_query(lambda c: c.data and c.data.startswith("fw_confirm_"))
@authorized_callback
async def handle_fw_confirm(call: CallbackQuery):
    """Execute firewall confirmation inline."""
    payload = call.data[len("fw_confirm_"):]
    parts = payload.split("_", 1)
    if len(parts) != 2:
        await call.answer("❌ Invalid confirmation data", show_alert=True)
        return
    action, arg = parts[0], parts[1]
    result = format_firewall("confirm", f"{action} {arg}")
    try:
        await call.message.edit_text(result, parse_mode="Markdown")
    except Exception:
        await bot.send_message(call.message.chat.id, result, parse_mode="Markdown")
    await call.answer("✅ Done")


@router.callback_query(lambda c: c.data and c.data.startswith("h_"))
@authorized_callback
async def handle_callback(call: CallbackQuery, state: FSMContext):
    cmd = call.data[2:]
    cid = call.message.chat.id
    callback_total.labels(action=cmd).inc()
    log.info(f"Callback: data={call.data!r}, cmd={cmd!r}")
    try:
        await call.answer()
    except Exception as e:
        log.warning(f"answer_callback_query failed: {e}")

    try:
        if cmd == "ip":
            await bot.send_message(cid, "🎯 *Enter an IP address:*", parse_mode="Markdown")
            await state.set_state(BotStates.waiting_for_ip)
        elif cmd == "domain":
            await bot.send_message(cid, "🌐 *Enter a domain:*", parse_mode="Markdown")
            await state.set_state(BotStates.waiting_for_domain)
        elif cmd == "scan_common":
            await bot.send_message(cid, "⚡ *Enter target:* (Fast — 23 ports)", parse_mode="Markdown")
            await state.set_state(BotStates.waiting_for_scan_fast)
        elif cmd == "scan_all":
            await bot.send_message(cid, "🔍 *Enter target:* (Full — all ports, ~5-10 min)", parse_mode="Markdown")
            await state.set_state(BotStates.waiting_for_scan_full)
        elif cmd == "logs_menu":
            await bot.send_message(cid, "📊 *Choose log filter:*", parse_mode="Markdown", reply_markup=logs_keyboard())
        elif cmd.startswith("logs_"):
            ftype = cmd.replace("logs_", "")
            await send_long_message(cid, analyze_logs(ftype), parse_mode="Markdown")
        elif cmd == "fim":
            await bot.send_message(cid, "📋 *File Integrity Monitor*", parse_mode="Markdown", reply_markup=fim_keyboard())
        elif cmd == "fim_add":
            await bot.send_message(cid, "📋 *Enter file path:*\nExample: `/etc/passwd`", parse_mode="Markdown")
            await state.set_state(BotStates.waiting_for_fim_path)
        elif cmd == "fim_check":
            await send_long_message(cid, fim_check(), parse_mode="Markdown")
        elif cmd == "cve":
            await bot.send_message(cid, "🧠 *Enter package name:*\nExample: `openssl`", parse_mode="Markdown")
            await state.set_state(BotStates.waiting_for_package)
        elif cmd == "hibp":
            await bot.send_message(cid, "🔐 *Enter email or domain:*", parse_mode="Markdown")
            await state.set_state(BotStates.waiting_for_hibp_input)
        elif cmd == "mitre":
            await bot.send_message(cid, "🧬 *Enter MITRE technique ID:*\nExample: `T1059`", parse_mode="Markdown")
            await state.set_state(BotStates.waiting_for_mitre_technique)
        elif cmd in _CMD_TABLE:
            await bot.send_message(cid, _CMD_TABLE[cmd]["prompt"], parse_mode="Markdown")
            await state.update_data(table_cmd=cmd)
            await state.set_state(BotStates.waiting_for_from_table)
        elif cmd == "status":
            await send_long_message(cid, format_status(), parse_mode="Markdown")
        elif cmd in ("top", "top_cpu", "top_ram", "top_pid", "top_name"):
            sort = cmd.split("_")[-1] if "_" in cmd else "cpu"
            await send_long_message(cid, format_top(sort), parse_mode="Markdown", reply_markup=top_keyboard(sort))
        elif cmd == "bandwidth":
            await send_long_message(cid, format_bandwidth(), parse_mode="Markdown")
        elif cmd == "fw":
            await send_long_message(cid, format_firewall(), parse_mode="Markdown")
        elif cmd == "compliance":
            await send_long_message(cid, format_compliance(), parse_mode="Markdown")
        elif cmd == "report":
            await bot.send_message(cid, "📄 *Generating PDF report...*")
            result = generate_report()
            if isinstance(result, str) and Path(result).exists():
                with open(result, "rb") as f:
                    await bot.send_document(cid, f, caption="📄 Cyber-Volt SOC Report")
            else:
                await bot.send_message(cid, f"❌ {result}")
        elif cmd == "alerts":
            with suricata_lock:
                if not suricata_alerts:
                    await bot.send_message(cid, "📋 *Suricata Alerts* — buffer empty. Suricata is running, pass rules suppress Telegram noise.", parse_mode="Markdown")
                else:
                    lines = ["📋 *Recent Suricata Alerts*\n"]
                    for a in reversed(suricata_alerts[-15:]):
                        stamp = a["time"].strftime("%H:%M:%S")
                        lines.append(f"`{stamp}` {escape_md(a['line'][:100])}")
                    await send_long_message(cid, "\n".join(lines), parse_mode="Markdown")
        elif cmd == "menu":
            await send_long_message(cid, menu_text(), parse_mode="Markdown", reply_markup=help_keyboard())
    except Exception as e:
        log.error("callback error (%s): %s", cmd, e)
        try:
            await bot.send_message(cid, f"❌ Error: {e}")
        except Exception:
            log.exception("Failed to send callback error message")


# ── FSM handlers — interactive input ──

@router.message(BotStates.waiting_for_ip)
@authorized_message
async def fsm_process_ip_hunt(message: Message, state: FSMContext):
    await state.clear()
    _set_alert_chat_id(message.chat.id)
    ip = message.text.strip()
    if not ip:
        await message.answer("❌ No IP entered.")
        return
    validated = security.validate_ip(ip)
    if not validated:
        await message.answer(f"❌ Invalid IP address: `{ip}`")
        return
    await message.answer(f"🎯 *Threat Hunting `{validated}`...*", parse_mode="Markdown")
    await send_long_message(message.chat.id, threat_hunt_ip(validated), parse_mode="Markdown")


@router.message(BotStates.waiting_for_domain)
@authorized_message
async def fsm_process_domain_hunt(message: Message, state: FSMContext):
    await state.clear()
    _set_alert_chat_id(message.chat.id)
    text = message.text.strip()
    if not text:
        await message.answer("❌ Nothing entered.")
        return
    ip = security.validate_ip(text)
    if ip:
        await message.answer(f"🎯 *Threat Hunting `{ip}`...*", parse_mode="Markdown")
        await send_long_message(message.chat.id, threat_hunt_ip(ip), parse_mode="Markdown")
        return
    domain = security.validate_domain(text)
    if domain:
        await message.answer(f"🌐 *Recon `{domain}`...*", parse_mode="Markdown")
        await send_long_message(message.chat.id, threat_hunt_domain(domain), parse_mode="Markdown")
        return
    await message.answer(f"❌ Not a valid IP address or domain: `{text}`")


@router.message(BotStates.waiting_for_scan_fast)
@authorized_message
async def fsm_process_scan_fast(message: Message, state: FSMContext):
    await state.clear()
    t = message.text.strip()
    if not t:
        await message.answer("❌ No target entered.")
        return
    await message.answer(f"⚡ *Fast scan `{t}`...*", parse_mode="Markdown")
    await send_long_message(message.chat.id, scan_network(t, all_ports=False), parse_mode="Markdown")


@router.message(BotStates.waiting_for_scan_full)
@authorized_message
async def fsm_process_scan_full(message: Message, state: FSMContext):
    await state.clear()
    t = message.text.strip()
    if not t:
        await message.answer("❌ No target entered.")
        return
    await message.answer(f"🔍 *Full scan `{t}`...* ~5-10 min ⏳", parse_mode="Markdown")
    await send_long_message(message.chat.id, scan_network(t, all_ports=True), parse_mode="Markdown")


@router.message(BotStates.waiting_for_fim_path)
@authorized_message
async def fsm_process_fim_add(message: Message, state: FSMContext):
    await state.clear()
    p = message.text.strip()
    if not p:
        await message.answer("❌ No path entered.")
        return
    await send_long_message(message.chat.id, fim_add(p), parse_mode="Markdown")


@router.message(BotStates.waiting_for_package)
@authorized_message
async def fsm_process_cve(message: Message, state: FSMContext):
    await state.clear()
    p = message.text.strip()
    if not p:
        await message.answer("❌ No package entered.")
        return
    if not security.validate_package_name(p):
        await message.answer(f"❌ Invalid package name: `{p}`")
        return
    await message.answer(f"🧠 *Checking CVE for `{p}`...*", parse_mode="Markdown")
    await send_long_message(message.chat.id, check_cve(p), parse_mode="Markdown")


@router.message(BotStates.waiting_for_hibp_input)
@authorized_message
async def fsm_process_hibp(message: Message, state: FSMContext):
    await state.clear()
    e = message.text.strip()
    if not e:
        await message.answer("❌ No email entered.")
        return
    await message.answer(f"🔐 *Checking `{e}`...*\n💡 Tip: use `name:BreachName` for details", parse_mode="Markdown")
    await send_long_message(message.chat.id, check_hibp(e), parse_mode="Markdown")


@router.message(BotStates.waiting_for_mitre_technique)
@authorized_message
async def fsm_process_mitre(message: Message, state: FSMContext):
    await state.clear()
    t = message.text.strip()
    if not t:
        await message.answer("❌ No technique ID entered.")
        return
    await message.answer(f"🧬 *Looking up `{t}` in MITRE...*", parse_mode="Markdown")
    await send_long_message(message.chat.id, mitre_lookup(t), parse_mode="Markdown")


@router.message(BotStates.waiting_for_from_table)
@authorized_message
async def fsm_process_from_table(message: Message, state: FSMContext):
    data = await state.get_data()
    cmd = data.get("table_cmd", "")
    config = _CMD_TABLE.get(cmd)
    await state.clear()
    if not config:
        return
    _set_alert_chat_id(message.chat.id)
    arg = message.text.strip()
    if not arg:
        await message.answer("❌ Nothing entered.")
        return
    validate_fn = config.get("validate")
    if validate_fn:
        transform = config.get("validate_transform")
        check_arg = transform(arg) if transform else arg
        if not validate_fn(check_arg):
            await message.answer(f"❌ Invalid input: `{arg}`")
            return
    success_msg = config.get("success_msg")
    if success_msg:
        await message.answer(success_msg.format(arg=arg), parse_mode="Markdown")
    await send_long_message(message.chat.id, config["fn"](arg), parse_mode="Markdown")


async def process_domain_hunt_inner(message: Message):
    """Called directly when args provided with /recon."""
    text = message.text.split(" ", 1)[1] if " " in message.text else ""
    ip = security.validate_ip(text)
    if ip:
        await message.answer(f"🎯 *Threat Hunting `{ip}`...*", parse_mode="Markdown")
        await send_long_message(message.chat.id, threat_hunt_ip(ip), parse_mode="Markdown")
        return
    domain = security.validate_domain(text)
    if domain:
        await message.answer(f"🌐 *Recon `{domain}`...*", parse_mode="Markdown")
        await send_long_message(message.chat.id, threat_hunt_domain(domain), parse_mode="Markdown")
        return
    await message.answer(f"❌ Not a valid IP address or domain: `{text}`")
