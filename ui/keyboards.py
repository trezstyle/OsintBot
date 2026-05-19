"""Telegram keyboard builders."""
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from services.tasks import CalendarData, PRIORITIES, VALID_STATUSES

_MONTH_NAMES = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


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


# ── Calendar Keyboard ──

_DAY_HEADERS = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"]


def calendar_keyboard(cal: CalendarData, task_days: list[int]) -> InlineKeyboardMarkup:
    rows = []
    rows.append([InlineKeyboardButton(
        text=f"📅 {cal.month_name} {cal.year}",
        callback_data="cal_ignore",
    )])
    rows.append([
        InlineKeyboardButton(text=h, callback_data="cal_ignore") for h in _DAY_HEADERS
    ])
    for week in cal.weeks:
        row = []
        for d in week:
            if d == 0:
                row.append(InlineKeyboardButton(text=" ", callback_data="cal_ignore"))
            else:
                has_task = d in task_days
                text = f"{d}📌" if has_task else str(d)
                row.append(InlineKeyboardButton(
                    text=text,
                    callback_data=f"cal_day_{cal.year}_{cal.month}_{d}",
                ))
        rows.append(row)

    prev_m = cal.month - 1 if cal.month > 1 else 12
    prev_y = cal.year if cal.month > 1 else cal.year - 1
    next_m = cal.month + 1 if cal.month < 12 else 1
    next_y = cal.year if cal.month < 12 else cal.year + 1

    nav = [
        InlineKeyboardButton(text="◀️", callback_data=f"cal_month_{prev_y}_{prev_m}"),
        InlineKeyboardButton(text="📆 Today", callback_data="cal_today"),
        InlineKeyboardButton(text="▶️", callback_data=f"cal_month_{next_y}_{next_m}"),
    ]
    rows.append(nav)
    rows.append([
        InlineKeyboardButton(text="📋 My Tasks", callback_data="task_list"),
        InlineKeyboardButton(text="➕ New", callback_data="task_add_prompt"),
    ])
    rows.append([InlineKeyboardButton(text="🔙 Menu", callback_data="h_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


# ── Task Action Keyboards ──


def task_view_keyboard(task_id: int) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(text="✅ Done", callback_data=f"task_status_{task_id}_done"),
            InlineKeyboardButton(text="🔄 In Progress", callback_data=f"task_status_{task_id}_in_progress"),
        ],
        [
            InlineKeyboardButton(text="⏳ Pending", callback_data=f"task_status_{task_id}_pending"),
            InlineKeyboardButton(text="❌ Cancel", callback_data=f"task_status_{task_id}_cancelled"),
        ],
        [
            InlineKeyboardButton(text="🗑 Delete", callback_data=f"task_del_{task_id}"),
            InlineKeyboardButton(text="🔙 List", callback_data="task_list"),
        ],
        [InlineKeyboardButton(text="📅 Calendar", callback_data="task_calendar")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def task_confirm_delete_keyboard(task_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🗑 Yes, delete", callback_data=f"task_del_confirm_{task_id}")],
        [InlineKeyboardButton(text="↩️ No, keep it", callback_data=f"task_view_{task_id}")],
    ])


def task_list_keyboard(
    tasks: list[dict],
    page: int,
    total_pages: int,
) -> InlineKeyboardMarkup:
    rows = []
    for t in tasks:
        emoji = "🔴" if t["priority"] == "critical" else ("🟠" if t["priority"] == "high" else "🟡" if t["priority"] == "medium" else "🟢")
        done_mark = " ✅" if t["status"] == "done" else (" ❌" if t["status"] == "cancelled" else "")
        label = f"{emoji} #{t['id']} {t['title'][:35]}{done_mark}"
        rows.append([InlineKeyboardButton(text=label, callback_data=f"task_view_{t['id']}")])

    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="◀️", callback_data=f"task_page_{page - 1}"))
    nav.append(InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="cal_ignore"))
    if page + 1 < total_pages:
        nav.append(InlineKeyboardButton(text="▶️", callback_data=f"task_page_{page + 1}"))
    if nav:
        rows.append(nav)

    rows.append([
        InlineKeyboardButton(text="📅 Calendar", callback_data="task_calendar"),
        InlineKeyboardButton(text="➕ New", callback_data="task_add_prompt"),
    ])
    rows.append([InlineKeyboardButton(text="🔙 Menu", callback_data="h_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def task_priority_keyboard(prefix: str = "task_setprio") -> InlineKeyboardMarkup:
    labels = {"low": "🟢 Low", "medium": "🟡 Medium", "high": "🟠 High", "critical": "🔴 Critical"}
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=v, callback_data=f"{prefix}_{k}") for k, v in list(labels.items())[:2]],
        [InlineKeyboardButton(text=v, callback_data=f"{prefix}_{k}") for k, v in list(labels.items())[2:]],
    ])
