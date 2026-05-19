"""Task planner: production-ready CRUD, calendar, and reminder scheduler."""
import calendar
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from services.database import get_db
from services.notifier import send_message_sync

log = logging.getLogger("cyber_volt.tasks")

PRIORITIES = ("low", "medium", "high", "critical")
VALID_STATUSES = frozenset({"pending", "in_progress", "done", "cancelled"})
PRIORITY_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
STATUS_EMOJI = {"pending": "⏳", "in_progress": "🔄", "done": "✅", "cancelled": "❌"}
PRIORITY_SORT = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_PAGE_SIZE = 15


class TaskError(Exception):
    pass


class TaskNotFoundError(TaskError):
    pass


class TaskOwnershipError(TaskError):
    pass


class TaskValidationError(TaskError):
    pass


# ── Helpers ──

def _parse_deadline(raw: str) -> str | None:
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    fmts = [
        ("%Y-%m-%d %H:%M", r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$"),
        ("%Y-%m-%d", r"^\d{4}-\d{2}-\d{2}$"),
        ("%d.%m.%Y", r"^\d{2}\.\d{2}\.\d{4}$"),
        ("%d.%m", r"^\d{2}\.\d{2}$"),
    ]
    for fmt, pattern in fmts:
        if re.match(pattern, raw):
            try:
                parsed = datetime.strptime(raw, fmt)
                if fmt == "%d.%m":
                    parsed = parsed.replace(year=datetime.now().year)
                return parsed.strftime("%Y-%m-%d %H:%M") if " " in raw else parsed.strftime("%Y-%m-%d")
            except ValueError:
                continue
    return None


def _validate_priority(p: str) -> str:
    p = p.strip().lower()
    return p if p in PRIORITIES else "medium"


def _validate_status(s: str) -> str:
    s = s.strip().lower()
    return s if s in VALID_STATUSES else "pending"


def _fmt_reminder(minutes: int) -> str:
    if minutes <= 0:
        return "no reminder"
    if minutes < 60:
        return f"{minutes}m before"
    if minutes < 1440:
        return f"{minutes // 60}h before"
    return f"{minutes // 1440}d before"


def _fmt_date(d: str) -> str:
    if not d:
        return ""
    try:
        dt = datetime.fromisoformat(d)
        now = datetime.now()
        if dt.date() == now.date():
            return f"Today {dt.strftime('%H:%M')}"
        if dt.date() == (now + timedelta(days=1)).date():
            return f"Tomorrow {dt.strftime('%H:%M')}"
        if dt.year == now.year:
            return dt.strftime("%b %d %H:%M")
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return d[:16]


def _fmt_progress(t: dict) -> str:
    if t.get("status") == "done":
        return "▓" * 10 + " 100%"
    if t.get("status") == "cancelled":
        return "─" * 10 + " cancelled"
    due = t.get("deadline")
    if not due:
        return "░" * 10 + " 0%"
    try:
        remaining = (datetime.fromisoformat(due) - datetime.now()).total_seconds()
        if remaining <= 0:
            return "🔴 OVERDUE"
        days = remaining / 86400
        if days > 7:
            return "🟢" + "▓" * 2 + "░" * 8 + f" {int(days)}d left"
        if days > 1:
            filled = max(1, 10 - int(days))
            return "🟡" + "▓" * filled + "░" * (10 - filled) + f" {int(days)}d left"
        hours = int(remaining / 3600)
        return "🔴" + "▓" * 3 + "░" * 7 + f" {max(0, hours)}h left"
    except (ValueError, TypeError):
        return ""


# ── CRUD ──

def add_task(
    user_id: int,
    title: str,
    description: str = "",
    deadline: str | None = None,
    priority: str = "medium",
    reminder_minutes: int = 60,
) -> int:
    if not title or not title.strip():
        raise TaskValidationError("Title is required")
    if len(title) > 200:
        raise TaskValidationError("Title too long (max 200 chars)")
    if len(description) > 2000:
        raise TaskValidationError("Description too long (max 2000 chars)")

    deadline = _parse_deadline(deadline) if deadline else None
    priority = _validate_priority(priority)

    db = get_db()
    db.execute("BEGIN")
    try:
        cur = db.execute(
            "INSERT INTO tasks (user_id, title, description, deadline, priority, created, reminder_minutes) "
            "VALUES (?, ?, ?, ?, ?, datetime('now'), ?)",
            (user_id, title.strip(), description.strip(), deadline, priority, reminder_minutes),
        )
        db.commit()
        return cur.lastrowid
    except Exception:
        db.rollback()
        raise


def update_task(task_id: int, user_id: int | None = None, **kwargs) -> bool:
    allowed = {"title", "description", "deadline", "priority", "status", "reminder_minutes", "reminded"}
    sets: dict[str, Any] = {}
    for k, v in kwargs.items():
        if k not in allowed:
            continue
        if k == "priority":
            v = _validate_priority(v)
        elif k == "status":
            v = _validate_status(v)
        elif k == "deadline":
            v = _parse_deadline(v) if v else None
        sets[k] = v

    if not sets:
        return False

    db = get_db()
    if user_id is not None:
        existing = db.execute("SELECT user_id FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not existing:
            raise TaskNotFoundError(f"Task #{task_id} not found")
        if existing["user_id"] != user_id:
            raise TaskOwnershipError(f"Task #{task_id} does not belong to you")

    placeholders = ", ".join(f"{k}=?" for k in sets)
    params = list(sets.values()) + [task_id]
    db.execute(f"UPDATE tasks SET {placeholders} WHERE id=?", params)
    db.commit()
    return db.total_changes > 0


def delete_task(task_id: int, user_id: int | None = None) -> bool:
    db = get_db()
    if user_id is not None:
        existing = db.execute("SELECT user_id FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not existing:
            raise TaskNotFoundError(f"Task #{task_id} not found")
        if existing["user_id"] != user_id:
            raise TaskOwnershipError(f"Task #{task_id} does not belong to you")
        db.execute("DELETE FROM tasks WHERE id=? AND user_id=?", (task_id, user_id))
    else:
        db.execute("DELETE FROM tasks WHERE id=?", (task_id,))
    db.commit()
    return db.total_changes > 0


def get_task(task_id: int, user_id: int | None = None) -> dict[str, Any] | None:
    db = get_db()
    if user_id is not None:
        row = db.execute(
            "SELECT id, user_id, title, description, deadline, priority, status, created, reminder_minutes, reminded "
            "FROM tasks WHERE id=? AND user_id=?",
            (task_id, user_id),
        ).fetchone()
    else:
        row = db.execute(
            "SELECT id, user_id, title, description, deadline, priority, status, created, reminder_minutes, reminded "
            "FROM tasks WHERE id=?",
            (task_id,),
        ).fetchone()
    return dict(row) if row else None


def list_tasks(
    user_id: int | None = None,
    status: str | None = None,
    priority: str | None = None,
    due_before: str | None = None,
    due_after: str | None = None,
    search: str | None = None,
    page: int = 0,
    page_size: int = _PAGE_SIZE,
) -> tuple[list[dict[str, Any]], int]:
    clauses: list[str] = []
    params: list[Any] = []

    if user_id is not None:
        clauses.append("user_id=?")
        params.append(user_id)
    if status:
        clauses.append("status=?")
        params.append(_validate_status(status))
    if priority:
        clauses.append("priority=?")
        params.append(_validate_priority(priority))
    if due_before:
        clauses.append("deadline IS NOT NULL AND deadline <= ?")
        params.append(due_before)
    if due_after:
        clauses.append("deadline IS NOT NULL AND deadline >= ?")
        params.append(due_after)
    if search:
        clauses.append("(title LIKE ? OR description LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    db = get_db()
    count_row = db.execute(f"SELECT COUNT(*) as cnt FROM tasks{where}", params).fetchone()
    total = count_row["cnt"]

    offset = page * page_size
    rows = db.execute(
        "SELECT id, user_id, title, description, deadline, priority, status, created, reminder_minutes, reminded "
        f"FROM tasks{where} ORDER BY "
        f"  CASE status WHEN 'done' THEN 1 WHEN 'cancelled' THEN 2 ELSE 0 END, "
        f"  CASE WHEN deadline IS NULL THEN 1 ELSE 0 END, "
        f"  deadline ASC, "
        f"  CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END "
        f"LIMIT ? OFFSET ?",
        (*params, page_size, offset),
    ).fetchall()
    return [dict(r) for r in rows], total


def tasks_for_date(user_id: int, date_str: str, page: int = 0) -> tuple[list[dict[str, Any]], int]:
    return list_tasks(
        user_id=user_id,
        due_after=f"{date_str} 00:00",
        due_before=f"{date_str} 23:59",
        page=page,
    )


def tasks_overdue(user_id: int, page: int = 0) -> tuple[list[dict[str, Any]], int]:
    now = datetime.now().isoformat()
    return list_tasks(
        user_id=user_id,
        status="pending",
        due_before=now,
        page=page,
    )


def tasks_this_week(user_id: int, page: int = 0) -> tuple[list[dict[str, Any]], int]:
    now = datetime.now()
    end = (now + timedelta(days=7)).isoformat()
    return list_tasks(
        user_id=user_id,
        due_after=now.isoformat(),
        due_before=end,
        page=page,
    )


def tasks_with_deadlines_in_month(user_id: int, year: int, month: int) -> list[int]:
    start = f"{year:04d}-{month:02d}-01"
    end = f"{year + 1:04d}-01-01" if month == 12 else f"{year:04d}-{month + 1:02d}-01"
    rows = get_db().execute(
        "SELECT DISTINCT CAST(strftime('%d', deadline) AS INTEGER) AS day FROM tasks "
        "WHERE user_id=? AND status NOT IN ('done', 'cancelled') AND deadline >= ? AND deadline < ?",
        (user_id, start, end),
    ).fetchall()
    return [r["day"] for r in rows]


def task_counts(user_id: int) -> dict[str, int]:
    db = get_db()
    row = db.execute(
        "SELECT "
        "  COUNT(*) AS total, "
        "  COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END), 0) AS pending, "
        "  COALESCE(SUM(CASE WHEN status='in_progress' THEN 1 ELSE 0 END), 0) AS in_progress, "
        "  COALESCE(SUM(CASE WHEN status='done' THEN 1 ELSE 0 END), 0) AS done, "
        "  COALESCE(SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END), 0) AS cancelled, "
        "  COALESCE(SUM(CASE WHEN status='pending' AND deadline IS NOT NULL AND deadline < datetime('now') THEN 1 ELSE 0 END), 0) AS overdue "
        "FROM tasks WHERE user_id=?",
        (user_id,),
    ).fetchone()
    return dict(row) if row else {"total": 0, "pending": 0, "in_progress": 0, "done": 0, "cancelled": 0, "overdue": 0}


# ── Formatting ──

def _card_pagination(page: int, total: int, page_size: int = _PAGE_SIZE) -> str:
    total_pages = max(1, (total + page_size - 1) // page_size)
    if total_pages <= 1:
        return ""
    return f"\n\nPage `{page + 1}/{total_pages}` ({total} tasks)"


def format_task(t: dict[str, Any]) -> str:
    emoji = PRIORITY_EMOJI.get(t["priority"], "🟡")
    status_e = STATUS_EMOJI.get(t["status"], "⏳")
    lines = [
        f"{emoji} *{t['title']}*",
        f"ID: `#{t['id']}` · {status_e} *{t['status']}* · Priority: *{t['priority']}*",
        f"Progress: {_fmt_progress(t)}",
    ]
    if t.get("deadline"):
        lines.append(f"📅 Deadline: `{_fmt_date(t['deadline'])}`")
    if t.get("description"):
        desc = t["description"][:500]
        lines.append(f"📝 {desc}")
    lines.append(f"🔔 Remind: {_fmt_reminder(t['reminder_minutes'])}")
    if t.get("created"):
        lines.append(f"🕐 Created: `{t['created'][:16]}`")
    return "\n".join(lines)


def format_task_list(
    tasks: list[dict[str, Any]],
    total: int,
    header: str = "📋 Tasks",
    page: int = 0,
    empty_msg: str = "No tasks found.",
) -> str:
    if not tasks:
        return f"{header}\n{empty_msg}"
    lines = [f"{header} ({total})"]
    for t in tasks:
        emoji = PRIORITY_EMOJI.get(t["priority"], "🟡")
        deadline = ""
        if t.get("deadline"):
            try:
                dt = datetime.fromisoformat(t["deadline"])
                now = datetime.now()
                if dt.date() == now.date():
                    deadline = " ⏰ Today"
                elif dt.date() == (now + timedelta(days=1)).date():
                    deadline = " 📅 Tomorrow"
                elif dt < now:
                    deadline = " 🔴 OVERDUE"
                else:
                    deadline = f" {dt.strftime('%b %d')}"
            except (ValueError, TypeError):
                pass
        status_mark = "✅" if t["status"] == "done" else ("❌" if t["status"] == "cancelled" else "")
        lines.append(f"{emoji} `#{t['id']}` {status_mark}*{t['title'][:50]}*{deadline}")
    lines.append(_card_pagination(page, total))
    return "\n".join(lines)


def format_task_counts(counts: dict[str, int]) -> str:
    return (
        f"📊 *Task Summary*\n"
        f"Total: `{counts['total']}` | "
        f"Pending: `{counts['pending']}` | "
        f"In progress: `{counts['in_progress']}` | "
        f"Done: `{counts['done']}` | "
        f"Overdue: `{counts['overdue']}` 🔴"
    )


# ── Calendar ──

@dataclass
class CalendarData:
    year: int
    month: int
    month_name: str
    weeks: list[list[int]]


def build_calendar_data(year: int, month: int) -> CalendarData:
    cal = calendar.Calendar()
    days = list(cal.itermonthdays(year, month))
    weeks = [days[i:i + 7] for i in range(0, len(days), 7)]
    return CalendarData(
        year=year,
        month=month,
        month_name=calendar.month_name[month],
        weeks=weeks,
    )


# ── Reminder Scheduler ──

_scheduler_shutdown = threading.Event()
_scheduler_cond = threading.Condition()


def _scheduler_worker():
    while not _scheduler_shutdown.is_set():
        with _scheduler_cond:
            waited = _scheduler_cond.wait(timeout=60)
        if _scheduler_shutdown.is_set():
            break
        if waited:
            continue
        _process_reminders()


def _process_reminders():
    now = datetime.now()
    try:
        rows = get_db().execute(
            "SELECT id, user_id, title, deadline, reminder_minutes, reminded FROM tasks "
            "WHERE status NOT IN ('done','cancelled') AND reminder_minutes > 0 AND reminded = 0 "
            "AND deadline IS NOT NULL",
        ).fetchall()
    except Exception as e:
        log.error("Scheduler query failed: %s", e)
        return

    for r in rows:
        try:
            _process_single_reminder(r, now)
        except Exception as e:
            log.error("Scheduler: failed to process reminder for task %s: %s", r["id"], e)


def _process_single_reminder(r: dict, now: datetime):
    dl = datetime.fromisoformat(r["deadline"])
    remind_before = timedelta(minutes=r["reminder_minutes"])
    if not (now >= dl - remind_before and now < dl):
        return
    msg = (
        f"⏰ *Task Reminder*\n"
        f"*{r['title']}*\n"
        f"📅 Deadline: `{dl.strftime('%Y-%m-%d %H:%M')}`\n"
        f"`/task {r['id']}` — view details"
    )
    send_message_sync(r["user_id"], msg, parse_mode="Markdown")
    try:
        get_db().execute("UPDATE tasks SET reminded=1 WHERE id=?", (r["id"],))
        get_db().commit()
    except Exception as e:
        log.error("Scheduler: failed to mark reminded for task %s: %s", r["id"], e)


def _reminder_recovery_worker():
    while not _scheduler_shutdown.is_set():
        _scheduler_shutdown.wait(300)
        if _scheduler_shutdown.is_set():
            break
        try:
            now = datetime.now()
            rows = get_db().execute(
                "SELECT id, user_id, title, deadline, reminder_minutes, reminded FROM tasks "
                "WHERE status NOT IN ('done','cancelled') AND reminder_minutes > 0 AND reminded = 0 "
                "AND deadline IS NOT NULL AND deadline <= datetime('now', '+1 hour')",
            ).fetchall()
            for r in rows:
                try:
                    _process_single_reminder(r, now)
                except Exception as e:
                    log.error("Recovery: task %s error: %s", r["id"], e)
        except Exception as e:
            log.error("Reminder recovery error: %s", e)


def notify_scheduler_change():
    """Wake the scheduler loop so it picks up new/changed tasks sooner."""
    with _scheduler_cond:
        _scheduler_cond.notify_all()


def start_scheduler():
    global _scheduler_shutdown, _scheduler_cond
    _scheduler_shutdown = threading.Event()
    _scheduler_cond = threading.Condition()
    t = threading.Thread(target=_scheduler_worker, daemon=True, name="task-scheduler")
    t.start()
    t2 = threading.Thread(target=_reminder_recovery_worker, daemon=True, name="task-recovery")
    t2.start()
    log.info("Task reminder scheduler started")


def stop_scheduler():
    _scheduler_shutdown.set()
    with _scheduler_cond:
        _scheduler_cond.notify_all()
    log.info("Task reminder scheduler stopped")
