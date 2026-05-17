"""Telegram keyboard builders."""
from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup

def help_keyboard():
    kb = InlineKeyboardMarkup(row_width=2)
    # Threat Intel
    kb.add(
        InlineKeyboardButton("🎯 IP Threat Hunt", callback_data="h_ip"),
        InlineKeyboardButton("🌐 Domain Recon", callback_data="h_domain"),
    )
    # Network
    kb.add(
        InlineKeyboardButton("⚡ Fast Scan", callback_data="h_scan_common"),
        InlineKeyboardButton("🔍 Full Scan", callback_data="h_scan_all"),
    )
    # Monitoring
    kb.add(
        InlineKeyboardButton("🖥 System Status", callback_data="h_status"),
        InlineKeyboardButton("📊 Top Processes", callback_data="h_top"),
    )
    kb.add(
        InlineKeyboardButton("📜 Logs [filter]", callback_data="h_logs_menu"),
    )
    # Security
    kb.add(
        InlineKeyboardButton("🛡 BSI Audit", callback_data="h_audit"),
        InlineKeyboardButton("📋 FIM Monitor", callback_data="h_fim"),
    )
    kb.add(
        InlineKeyboardButton("🧠 CVE Check", callback_data="h_cve"),
        InlineKeyboardButton("🔐 HIBP Check", callback_data="h_hibp"),
    )
    kb.add(
        InlineKeyboardButton("🔒 SSL Check", callback_data="h_ssl"),
        InlineKeyboardButton("🛡 HTTP Headers", callback_data="h_httpcheck"),
    )
    kb.add(
        InlineKeyboardButton("⚫ Blacklist", callback_data="h_bl"),
        InlineKeyboardButton("🌐 Bandwidth", callback_data="h_bandwidth"),
    )
    kb.add(
        InlineKeyboardButton("🧬 MITRE ATT&CK", callback_data="h_mitre"),
    )
    kb.add(
        InlineKeyboardButton("📧 Email OSINT", callback_data="h_email"),
    )
    # Reports
    kb.add(
        InlineKeyboardButton("📄 PDF Report", callback_data="h_report"),
    )
    # Alerts
    kb.add(
        InlineKeyboardButton("🚨 Suricata Alerts", callback_data="h_alerts"),
    )
    # Navigation
    kb.add(
        InlineKeyboardButton("📖 Help", callback_data="h_help"),
    )
    return kb

def menu_text():
    return (
        "🤖 *Cyber-Volt SOC Master v3.0*\n\n"
        "Choose a category:\n\n"
        "🛡 *Threat Intel*   — IP / Domain reconnaissance\n"
        "🕸 *Network*        — Fast / Full nmap scan\n"
        "📊 *Monitoring*     — Status, Top, Logs\n"
        "🔐 *Security*       — Audit, FIM, CVE, HIBP, MITRE\n"
        "📄 *Reports*        — PDF report generator\n\n"
        "💡 *Tip:* just send an IP or domain\ninto the chat — the bot auto-hunts it!"
    )


def logs_keyboard():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("🚫 Failed", callback_data="h_logs_failed"), InlineKeyboardButton("👤 Sudo", callback_data="h_logs_sudo"))
    kb.add(InlineKeyboardButton("🔐 SSH", callback_data="h_logs_ssh"), InlineKeyboardButton("🛡 Attackers", callback_data="h_logs_attack"))
    kb.add(InlineKeyboardButton("🔙 Menu", callback_data="h_menu"))
    return kb


def scan_keyboard():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("🔍 Full (65535 ports)", callback_data="h_scan_all"), InlineKeyboardButton("⚡ Fast (23 ports)", callback_data="h_scan_common"))
    kb.add(InlineKeyboardButton("🔙 Menu", callback_data="h_menu"))
    return kb


def fim_keyboard():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("➕ Add File", callback_data="h_fim_add"), InlineKeyboardButton("🔍 Check All", callback_data="h_fim_check"))
    kb.add(InlineKeyboardButton("🔙 Menu", callback_data="h_menu"))
    return kb
