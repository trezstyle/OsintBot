"""Telegram keyboard builders."""
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

def help_keyboard():
    kb = InlineKeyboardMarkup(inline_keyboard=[])
    kb.inline_keyboard = [
        [InlineKeyboardButton(text="🎯 IP Threat Hunt", callback_data="h_ip"),
         InlineKeyboardButton(text="🌐 Domain Recon", callback_data="h_domain"),
         InlineKeyboardButton(text="🔑 Hash Check", callback_data="h_hash")],
        [InlineKeyboardButton(text="⚡ Fast Scan", callback_data="h_scan_common"),
         InlineKeyboardButton(text="🔍 Full Scan", callback_data="h_scan_all")],
        [InlineKeyboardButton(text="🖥 System Status", callback_data="h_status"),
         InlineKeyboardButton(text="📊 Top Processes", callback_data="h_top")],
        [InlineKeyboardButton(text="📜 Logs [filter]", callback_data="h_logs_menu")],
        [InlineKeyboardButton(text="✅ Compliance", callback_data="h_compliance"),
         InlineKeyboardButton(text="📋 FIM Monitor", callback_data="h_fim")],
        [InlineKeyboardButton(text="🧠 CVE Check", callback_data="h_cve"),
         InlineKeyboardButton(text="🔐 HIBP Check", callback_data="h_hibp")],
        [InlineKeyboardButton(text="🔒 SSL Check", callback_data="h_ssl"),
         InlineKeyboardButton(text="🛡 HTTP Headers", callback_data="h_httpcheck")],
        [InlineKeyboardButton(text="⚫ Blacklist", callback_data="h_bl"),
         InlineKeyboardButton(text="🌐 Bandwidth", callback_data="h_bandwidth")],
        [InlineKeyboardButton(text="🧬 MITRE ATT&CK", callback_data="h_mitre"),
         InlineKeyboardButton(text="🧬 Attack Sim", callback_data="h_attack")],
        [InlineKeyboardButton(text="📧 Email OSINT", callback_data="h_email")],
        [InlineKeyboardButton(text="🔍 Tor Check", callback_data="h_tor"),
         InlineKeyboardButton(text="🌐 Proxy Check", callback_data="h_proxy"),
         InlineKeyboardButton(text="🔗 URL Scan", callback_data="h_urlscan")],
        [InlineKeyboardButton(text="📜 CT Logs", callback_data="h_ctlogs"),
         InlineKeyboardButton(text="📞 Phone OSINT", callback_data="h_phone")],
        [InlineKeyboardButton(text="🛡 Firewall", callback_data="h_fw")],
        [InlineKeyboardButton(text="📄 PDF Report", callback_data="h_report")],
        [InlineKeyboardButton(text="🚨 Suricata Alerts", callback_data="h_alerts")],
    ]
    return kb

def menu_text():
    return (
        "🤖 *Cyber-Volt SOC Master v3.0*\n\n"
        "Choose a category:\n\n"
        "🛡 *Threat Intel*   — IP / Domain, Tor, Proxy, CT, Phone\n"
        "🕸 *Network*        — Fast / Full nmap scan\n"
        "📊 *Monitoring*     — Status, Top, Logs\n"
        "🔐 *Security*       — Audit, CIS, Firewall, FIM, CVE\n"
        "📄 *Reports*        — PDF report generator\n\n"
        "💡 *Tip:* just send an IP or domain\ninto the chat — the bot auto-hunts it!"
    )

def logs_keyboard():
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🚫 Failed", callback_data="h_logs_failed"),
         InlineKeyboardButton(text="👤 Sudo", callback_data="h_logs_sudo")],
        [InlineKeyboardButton(text="🔐 SSH", callback_data="h_logs_ssh"),
         InlineKeyboardButton(text="🛡 Attackers", callback_data="h_logs_attack")],
        [InlineKeyboardButton(text="🔙 Menu", callback_data="h_menu")],
    ])
    return kb

def scan_keyboard():
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔍 Full (65535 ports)", callback_data="h_scan_all"),
         InlineKeyboardButton(text="⚡ Fast (23 ports)", callback_data="h_scan_common")],
        [InlineKeyboardButton(text="🔙 Menu", callback_data="h_menu")],
    ])
    return kb

def fim_keyboard():
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Add File", callback_data="h_fim_add"),
         InlineKeyboardButton(text="🔍 Check All", callback_data="h_fim_check")],
        [InlineKeyboardButton(text="🔙 Menu", callback_data="h_menu")],
    ])
    return kb

def top_keyboard(current_sort="cpu"):
    sorts = [
        ("🔥 CPU", "h_top_cpu"),
        ("💾 RAM", "h_top_ram"),
        ("🆔 PID", "h_top_pid"),
        ("🔤 Name", "h_top_name"),
    ]
    buttons = []
    for label, data in sorts:
        text = f"• {label} •" if data.endswith(current_sort) else label
        buttons.append(InlineKeyboardButton(text=text, callback_data=data))
    kb = InlineKeyboardMarkup(inline_keyboard=[
        buttons,
        [InlineKeyboardButton(text="🔄 Refresh", callback_data=f"h_top_{current_sort}")],
        [InlineKeyboardButton(text="🔙 Menu", callback_data="h_menu")],
    ])
    return kb
