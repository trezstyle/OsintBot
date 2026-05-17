"""Telegram UI handlers for Cyber-Volt SOC Bot."""
import logging
from functools import wraps
from pathlib import Path
import re
import threading

import telebot

import security
from config import settings
from services.fim import fim_add, fim_check
from services.reporting import generate_report
from services.scanner import scan_network
from services.system import analyze_logs, check_cve, format_bandwidth, format_compliance, format_firewall, format_status, format_top
from services.threat_intel import check_blacklist, check_ctlogs, check_email, check_hibp, check_http_headers, check_phone, check_proxy, check_ssl, check_tor, get_whois, mitre_lookup, threat_hunt_domain, threat_hunt_ip
from ui.keyboards import fim_keyboard, help_keyboard, logs_keyboard, menu_text, scan_keyboard, top_keyboard
from watchers import suricata_alerts, suricata_lock, _set_alert_chat_id

log = logging.getLogger("cyber_volt")
security.load_authorization()

UNAUTHORIZED_TEXT = settings.unauthorized_text

bot = telebot.TeleBot(settings.api.telegram_token)

MAX_MSG_LEN = 4096


# ── Message length helper ──

def send_long_message(chat_id, text, parse_mode=None, reply_markup=None):
    if len(text) <= MAX_MSG_LEN:
        bot.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup)
    else:
        parts = []
        while text:
            if len(text) <= MAX_MSG_LEN:
                parts.append(text)
                break
            split_at = text.rfind("\n", 0, MAX_MSG_LEN)
            if split_at == -1:
                split_at = MAX_MSG_LEN
            parts.append(text[:split_at])
            text = text[split_at:]
        for i, part in enumerate(parts):
            bot.send_message(chat_id, part, parse_mode=parse_mode)


# ── Authorization decorator ──

def authorized_message(func):
    @wraps(func)
    def wrapper(m, *args, **kwargs):
        if not is_message_authorized(m):
            return
        return func(m, *args, **kwargs)
    return wrapper


def authorized_callback(func):
    @wraps(func)
    def wrapper(call, *args, **kwargs):
        if not is_callback_authorized(call):
            return
        return func(call, *args, **kwargs)
    return wrapper


def is_message_authorized(m):
    user_id = getattr(getattr(m, "from_user", None), "id", None)
    chat_id = getattr(getattr(m, "chat", None), "id", None)
    if security.is_authorized(user_id, chat_id):
        return True
    bot.reply_to(m, UNAUTHORIZED_TEXT)
    return False


def is_callback_authorized(call):
    user_id = getattr(getattr(call, "from_user", None), "id", None)
    message = getattr(call, "message", None)
    chat_id = getattr(getattr(message, "chat", None), "id", None)
    if security.is_authorized(user_id, chat_id):
        return True
    try:
        bot.answer_callback_query(call.id, text="❌ Unauthorized")
    except Exception:
        pass
    try:
        bot.send_message(chat_id, UNAUTHORIZED_TEXT)
    except Exception:
        pass
    return False


LOGO = """```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗
██║     ██║   ██║██████╔╝█████╗  ██████╔╝
██║     ╚██╗ ██╔╝██╔══██╗██╔══╝  ██╔══██╗
╚██████╗ ╚████╔╝ ██████╔╝███████╗██║  ██║
 ╚═════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
```"""


@bot.message_handler(commands=["start"])
@authorized_message
def cmd_start(m):
    _set_alert_chat_id(m.chat.id)
    bot.reply_to(m, f"{LOGO}\n🤖 *Cyber-Volt SOC Master v3.0*\n\nFull-featured SOC platform in Telegram.\n\nUse /start to open the menu.", parse_mode="Markdown", reply_markup=help_keyboard())


@bot.message_handler(commands=["status", "top", "logs", "whois", "recon", "scan", "fim", "cve", "hibp", "mitre", "report", "alerts", "ssl", "httpcheck", "bl", "bandwidth", "email", "tor", "proxy", "ctlogs", "phone", "fw", "compliance"])
@authorized_message
def cmd_handler(m):
    _set_alert_chat_id(m.chat.id)
    cmd = m.text.split()[0].replace("/", "")
    args = m.text.split()[1:]

    try:
        if cmd == "status": send_long_message(m.chat.id, format_status(), parse_mode="Markdown")
        elif cmd == "top":
            sort = args[0] if args and args[0] in ("cpu", "ram", "pid", "name") else "cpu"
            send_long_message(m.chat.id, format_top(sort), parse_mode="Markdown", reply_markup=top_keyboard(sort))
        elif cmd == "bandwidth": send_long_message(m.chat.id, format_bandwidth(), parse_mode="Markdown")
        elif cmd == "logs":
            if args:
                send_long_message(m.chat.id, analyze_logs(args[0]), parse_mode="Markdown")
            else:
                kb = logs_keyboard()
                bot.reply_to(m, "📊 *Choose log filter:*", parse_mode="Markdown", reply_markup=kb)
        elif cmd == "whois":
            if args:
                d = args[0]
                if not security.validate_domain(d):
                    bot.reply_to(m, "❌ Invalid domain format.")
                else:
                    send_long_message(m.chat.id, get_whois(d), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "🕵️ *Enter a domain for WHOIS:*", parse_mode="Markdown"), process_whois)
        elif cmd == "recon":
            if args:
                process_domain_hunt(m)
            else:
                bot.register_next_step_handler(bot.reply_to(m, "🌐 *Enter a domain or IP:*", parse_mode="Markdown"), process_domain_hunt)
        elif cmd == "scan":
            if args:
                fast = "fast" in args
                target = [a for a in args if a != "fast"][0] if fast else args[0]
                if fast:
                    bot.reply_to(m, f"⚡ *Fast scan `{target}`...*", parse_mode="Markdown")
                    send_long_message(m.chat.id, scan_network(target, all_ports=False), parse_mode="Markdown")
                else:
                    bot.reply_to(m, f"🔍 *Full scan `{target}`...* ~5-10 min ⏳", parse_mode="Markdown")
                    send_long_message(m.chat.id, scan_network(target, all_ports=True), parse_mode="Markdown")
            else:
                kb = scan_keyboard()
                bot.reply_to(m, "🕸 *Choose scan mode:*", parse_mode="Markdown", reply_markup=kb)
        elif cmd == "fim":
            if len(args) >= 2 and args[0] == "add":
                send_long_message(m.chat.id, fim_add(" ".join(args[1:])), parse_mode="Markdown")
            elif args and args[0] == "check":
                send_long_message(m.chat.id, fim_check(), parse_mode="Markdown")
            else:
                kb = fim_keyboard()
                bot.reply_to(m, "📋 *File Integrity Monitor*", parse_mode="Markdown", reply_markup=kb)
        elif cmd == "cve":
            if args:
                send_long_message(m.chat.id, check_cve(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "🧠 *Enter package name:*\nExample: `openssl`", parse_mode="Markdown"), process_cve)
        elif cmd == "hibp":
            if args:
                send_long_message(m.chat.id, check_hibp(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "🔐 *Enter email or domain:*", parse_mode="Markdown"), process_hibp)
        elif cmd == "ssl":
            if args:
                send_long_message(m.chat.id, check_ssl(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "🔒 *Enter domain for SSL check:*", parse_mode="Markdown"), process_ssl)
        elif cmd == "httpcheck":
            if args:
                send_long_message(m.chat.id, check_http_headers(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "🛡 *Enter domain or URL for HTTP header check:*", parse_mode="Markdown"), process_httpcheck)
        elif cmd == "bl":
            if args:
                send_long_message(m.chat.id, check_blacklist(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "⚫ *Enter IP address for blacklist check:*", parse_mode="Markdown"), process_bl)
        elif cmd == "email":
            if args:
                send_long_message(m.chat.id, check_email(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "📧 *Enter email address for OSINT:*", parse_mode="Markdown"), process_email)
        elif cmd == "tor":
            if args:
                send_long_message(m.chat.id, check_tor(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "🔍 *Enter IP address for Tor check:*", parse_mode="Markdown"), process_tor)
        elif cmd == "proxy":
            if args:
                send_long_message(m.chat.id, check_proxy(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "🌐 *Enter IP address for Proxy/VPN check:*", parse_mode="Markdown"), process_proxy)
        elif cmd == "ctlogs":
            if args:
                send_long_message(m.chat.id, check_ctlogs(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "📜 *Enter domain for CT logs:*", parse_mode="Markdown"), process_ctlogs)
        elif cmd == "phone":
            if args:
                send_long_message(m.chat.id, check_phone(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "📞 *Enter phone number:*\nExample: `+491234567`", parse_mode="Markdown"), process_phone)
        elif cmd == "fw":
            action = args[0] if args else "status"
            fw_args = " ".join(args[1:]) if len(args) > 1 else ""
            send_long_message(m.chat.id, format_firewall(action, fw_args), parse_mode="Markdown")
        elif cmd == "compliance":
            send_long_message(m.chat.id, format_compliance(), parse_mode="Markdown")
        elif cmd == "mitre":
            if args:
                send_long_message(m.chat.id, mitre_lookup(args[0]), parse_mode="Markdown")
            else:
                bot.register_next_step_handler(bot.reply_to(m, "🧬 *Enter technique ID:*\nExample: `T1059`", parse_mode="Markdown"), process_mitre)
        elif cmd == "report":
            bot.reply_to(m, "📄 *Generating PDF report...*")
            result = generate_report()
            if isinstance(result, str) and Path(result).exists():
                with open(result, "rb") as f: bot.send_document(m.chat.id, f, caption="📄 Cyber-Volt SOC Report")
            else: bot.reply_to(m, f"❌ {result}")
        elif cmd == "alerts":
            with suricata_lock:
                if not suricata_alerts:
                    bot.reply_to(m, f"📋 *Suricata Alerts*\nNo alerts recorded yet.\nMake sure Suricata is installed and logging to `{settings.paths.suricata_fast_log_file}`", parse_mode="Markdown")
                else:
                    lines = ["📋 *Recent Suricata Alerts*", f"Total: {len(suricata_alerts)} alerts\n"]
                    for a in reversed(suricata_alerts[-10:]):
                        t = a["time"].strftime("%H:%M:%S")
                        lines.append(f"`{t}` {a['line'][:80]}")
                    send_long_message(m.chat.id, "\n".join(lines), parse_mode="Markdown")
    except Exception as e:
        log.error(f"cmd_handler({cmd}): {e}")
        bot.reply_to(m, f"❌ Error: {e}")


@bot.message_handler(func=lambda m: True, content_types=["text"])
@authorized_message
def auto_threat_hunt(m):
    _set_alert_chat_id(m.chat.id)
    text = m.text.strip()
    if text.startswith("/"): return

    ip = security.validate_ip(text)
    if ip:
        bot.reply_to(m, f"🎯 *IP detected:* `{ip}`\nRunning threat hunt...", parse_mode="Markdown")
        send_long_message(m.chat.id, threat_hunt_ip(ip), parse_mode="Markdown")
        return

    domain = security.validate_domain(text)
    if domain:
        bot.reply_to(m, f"🌐 *Domain detected:* `{domain}`\nRunning recon...", parse_mode="Markdown")
        send_long_message(m.chat.id, threat_hunt_domain(domain), parse_mode="Markdown")
        return


@bot.callback_query_handler(func=lambda call: call.data.startswith("h_"))
@authorized_callback
def handle_callback(call):
    cmd = call.data[2:]
    cid = call.message.chat.id
    log.info(f"Callback: data={call.data!r}, cmd={cmd!r}")
    try:
        bot.answer_callback_query(call.id)
    except Exception as e:
        log.warning(f"answer_callback_query failed: {e}")

    try:
        if cmd == "ip":
            msg = bot.send_message(cid, "🎯 *Enter an IP address:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_ip_hunt)
        elif cmd == "domain":
            msg = bot.send_message(cid, "🌐 *Enter a domain:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_domain_hunt)
        elif cmd == "scan_common":
            msg = bot.send_message(cid, "⚡ *Enter target:* (Fast — 23 ports)", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_scan_fast)
        elif cmd == "scan_all":
            msg = bot.send_message(cid, "🔍 *Enter target:* (Full — all ports, ~5-10 min)", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_scan_full)
        elif cmd == "logs_menu":
            kb = logs_keyboard()
            bot.send_message(cid, "📊 *Choose log filter:*", parse_mode="Markdown", reply_markup=kb)
        elif cmd.startswith("logs_"):
            ftype = cmd.replace("logs_", "")
            send_long_message(cid, analyze_logs(ftype), parse_mode="Markdown")
        elif cmd == "fim":
            kb = fim_keyboard()
            bot.send_message(cid, "📋 *File Integrity Monitor*", parse_mode="Markdown", reply_markup=kb)
        elif cmd == "fim_add":
            msg = bot.send_message(cid, "📋 *Enter file path:*\nExample: `/etc/passwd`", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_fim_add)
        elif cmd == "fim_check":
            send_long_message(cid, fim_check(), parse_mode="Markdown")
        elif cmd == "cve":
            msg = bot.send_message(cid, "🧠 *Enter package name:*\nExample: `openssl`", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_cve)
        elif cmd == "hibp":
            msg = bot.send_message(cid, "🔐 *Enter email or domain:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_hibp)
        elif cmd == "mitre":
            msg = bot.send_message(cid, "🧬 *Enter MITRE technique ID:*\nExample: `T1059`", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_mitre)
        elif cmd == "ssl":
            msg = bot.send_message(cid, "🔒 *Enter domain for SSL check:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_ssl)
        elif cmd == "httpcheck":
            msg = bot.send_message(cid, "🛡 *Enter domain or URL for HTTP header check:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_httpcheck)
        elif cmd == "bl":
            msg = bot.send_message(cid, "⚫ *Enter IP address for blacklist check:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_bl)
        elif cmd == "email":
            msg = bot.send_message(cid, "📧 *Enter email address for OSINT:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_email)
        elif cmd == "tor":
            msg = bot.send_message(cid, "🔍 *Enter IP address for Tor check:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_tor)
        elif cmd == "proxy":
            msg = bot.send_message(cid, "🌐 *Enter IP address for Proxy/VPN check:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_proxy)
        elif cmd == "ctlogs":
            msg = bot.send_message(cid, "📜 *Enter domain for CT logs:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_ctlogs)
        elif cmd == "phone":
            msg = bot.send_message(cid, "📞 *Enter phone number:*\nExample: `+491234567`", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_phone)
        elif cmd == "status": send_long_message(cid, format_status(), parse_mode="Markdown")
        elif cmd in ("top", "top_cpu", "top_ram", "top_pid", "top_name"):
            sort = cmd.split("_")[-1] if "_" in cmd else "cpu"
            text = format_top(sort)
            kb = top_keyboard(sort)
            try:
                bot.edit_message_text(text, cid, call.message.id, parse_mode="Markdown", reply_markup=kb)
            except Exception:
                send_long_message(cid, text, parse_mode="Markdown", reply_markup=kb)
        elif cmd == "bandwidth": send_long_message(cid, format_bandwidth(), parse_mode="Markdown")
        elif cmd == "fw": send_long_message(cid, format_firewall(), parse_mode="Markdown")
        elif cmd == "compliance": send_long_message(cid, format_compliance(), parse_mode="Markdown")
        elif cmd == "report":
            bot.send_message(cid, "📄 *Generating PDF report...*")
            result = generate_report()
            if isinstance(result, str) and Path(result).exists():
                with open(result, "rb") as f: bot.send_document(cid, f, caption="📄 Cyber-Volt SOC Report")
            else: bot.send_message(cid, f"❌ {result}")
        elif cmd == "alerts":
            with suricata_lock:
                if not suricata_alerts:
                    bot.send_message(cid, "📋 *Suricata Alerts*\nNo alerts yet. Suricata must be installed first.", parse_mode="Markdown")
                else:
                    lines = ["📋 *Recent Suricata Alerts*\n"]
                    for a in reversed(suricata_alerts[-15:]):
                        t = a["time"].strftime("%H:%M:%S")
                        lines.append(f"`{t}` {a['line'][:100]}")
                    send_long_message(cid, "\n".join(lines), parse_mode="Markdown")
        elif cmd == "menu": send_long_message(cid, menu_text(), parse_mode="Markdown", reply_markup=help_keyboard())
        elif cmd == "hello": cmd_start(call.message)
    except Exception as e:
        log.error(f"callback error ({cmd}): {e}")
        try: bot.send_message(cid, f"❌ Error: {e}")
        except: pass


# ── Next-step handlers with input validation ──

def process_ip_hunt(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    ip = m.text.strip()
    if not ip: bot.reply_to(m, "❌ No IP entered."); return
    validated = security.validate_ip(ip)
    if not validated:
        bot.reply_to(m, f"❌ Invalid IP address: `{ip}`")
        return
    bot.reply_to(m, f"🎯 *Threat Hunting `{validated}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, threat_hunt_ip(validated), parse_mode="Markdown")


def process_domain_hunt(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    text = m.text.strip()
    if not text: bot.reply_to(m, "❌ Nothing entered."); return

    ip = security.validate_ip(text)
    if ip:
        bot.reply_to(m, f"🎯 *Threat Hunting `{ip}`...*", parse_mode="Markdown")
        send_long_message(m.chat.id, threat_hunt_ip(ip), parse_mode="Markdown")
        return

    domain = security.validate_domain(text)
    if domain:
        bot.reply_to(m, f"🌐 *Recon `{domain}`...*", parse_mode="Markdown")
        send_long_message(m.chat.id, threat_hunt_domain(domain), parse_mode="Markdown")
        return

    bot.reply_to(m, f"❌ Not a valid IP address or domain: `{text}`")


def process_scan_fast(m):
    if not is_message_authorized(m): return
    t = m.text.strip()
    if not t: bot.reply_to(m, "❌ No target entered."); return
    bot.reply_to(m, f"⚡ *Fast scan `{t}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, scan_network(t, all_ports=False), parse_mode="Markdown")


def process_scan_full(m):
    if not is_message_authorized(m): return
    t = m.text.strip()
    if not t: bot.reply_to(m, "❌ No target entered."); return
    bot.reply_to(m, f"🔍 *Full scan `{t}`...* ~5-10 min ⏳", parse_mode="Markdown")
    send_long_message(m.chat.id, scan_network(t, all_ports=True), parse_mode="Markdown")


def process_fim_add(m):
    if not is_message_authorized(m): return
    p = m.text.strip()
    if not p: bot.reply_to(m, "❌ No path entered."); return
    send_long_message(m.chat.id, fim_add(p), parse_mode="Markdown")


def process_cve(m):
    if not is_message_authorized(m): return
    p = m.text.strip()
    if not p: bot.reply_to(m, "❌ No package entered."); return
    if not security.validate_package_name(p):
        bot.reply_to(m, f"❌ Invalid package name: `{p}`")
        return
    bot.reply_to(m, f"🧠 *Checking CVE for `{p}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, check_cve(p), parse_mode="Markdown")


def process_hibp(m):
    if not is_message_authorized(m): return
    e = m.text.strip()
    if not e: bot.reply_to(m, "❌ No email entered."); return
    bot.reply_to(m, f"🔐 *Checking `{e}`...*\n💡 Tip: use `name:BreachName` for details", parse_mode="Markdown")
    send_long_message(m.chat.id, check_hibp(e), parse_mode="Markdown")


def process_ssl(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    d = m.text.strip()
    if not d: bot.reply_to(m, "❌ No domain entered."); return
    bot.reply_to(m, f"🔒 *Checking SSL for `{d}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, check_ssl(d), parse_mode="Markdown")


def process_httpcheck(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    u = m.text.strip()
    if not u: bot.reply_to(m, "❌ No URL entered."); return
    bot.reply_to(m, f"🛡 *Checking HTTP headers for `{u}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, check_http_headers(u), parse_mode="Markdown")


def process_bl(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    ip = m.text.strip()
    if not ip: bot.reply_to(m, "❌ No IP entered."); return
    if not security.validate_ip(ip):
        bot.reply_to(m, f"❌ Invalid IP address: `{ip}`")
        return
    bot.reply_to(m, f"⚫ *Checking DNSBLs for `{ip}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, check_blacklist(ip), parse_mode="Markdown")


def process_email(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    e = m.text.strip()
    if not e: bot.reply_to(m, "❌ No email entered."); return
    bot.reply_to(m, f"📧 *Running Email OSINT for `{e}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, check_email(e), parse_mode="Markdown")


def process_tor(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    ip = m.text.strip()
    if not ip: bot.reply_to(m, "❌ No IP entered."); return
    if not security.validate_ip(ip):
        bot.reply_to(m, f"❌ Invalid IP address: `{ip}`")
        return
    bot.reply_to(m, f"🔍 *Checking Tor exit status for `{ip}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, check_tor(ip), parse_mode="Markdown")


def process_proxy(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    ip = m.text.strip()
    if not ip: bot.reply_to(m, "❌ No IP entered."); return
    if not security.validate_ip(ip):
        bot.reply_to(m, f"❌ Invalid IP address: `{ip}`")
        return
    bot.reply_to(m, f"🌐 *Checking Proxy/VPN status for `{ip}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, check_proxy(ip), parse_mode="Markdown")


def process_ctlogs(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    d = m.text.strip()
    if not d: bot.reply_to(m, "❌ No domain entered."); return
    bot.reply_to(m, f"📜 *Checking CT logs for `{d}`...*", parse_mode="Markdown")
    send_long_message(m.chat.id, check_ctlogs(d), parse_mode="Markdown")


def process_phone(m):
    if not is_message_authorized(m): return
    _set_alert_chat_id(m.chat.id)
    p = m.text.strip()
    if not p: bot.reply_to(m, "❌ No phone number entered."); return
    send_long_message(m.chat.id, check_phone(p), parse_mode="Markdown")


def process_mitre(m):
    if not is_message_authorized(m): return
    t = m.text.strip()
    if not t: bot.reply_to(m, "❌ No technique ID entered."); return
    bot.reply_to(m, f"🧬 *Looking up `{t}` in MITRE...*", parse_mode="Markdown")
    send_long_message(m.chat.id, mitre_lookup(t), parse_mode="Markdown")


def process_whois(m):
    if not is_message_authorized(m): return
    d = m.text.strip()
    if not d:
        bot.reply_to(m, "❌ No domain entered.")
        return
    if not security.validate_domain(d):
        bot.reply_to(m, f"❌ Invalid domain: `{d}`")
        return
    send_long_message(m.chat.id, get_whois(d), parse_mode="Markdown")
