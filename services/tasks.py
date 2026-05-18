"""Task planner: CRUD, calendar helpers, reminder scheduler."""
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any

from services.database import get_db
from services.notifier import send_message_sync

log = logging.getLogger("cyber_volt.tasks")

PRIORITIES = ("low", "medium", "high", "critical")
PRIORITY_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


# ── CRUD ──

def add_task(
    user_id: int,
    title: str,
    description: str = "",
    deadline: str | None = None,
    priority: str = "medium",
    reminder_minutes: int = 1440,
) -> int:
    db = get_db()
    cur = db.execute(
        "INSERT INTO tasks (user_id, title, description, deadline, priority, created, reminder_minutes) "
        "VALUES (?, ?, ?, ?, ?, datetime('now'), ?)",
        (user_id, title, description, deadline, priority, reminder_minutes),
    )
    db.commit()
    return cur.lastrowid


def update_task(task_id: int, **kwargs) -> bool:
    allowed = {"title", "description", "deadline", "priority", "status", "reminder_minutes", "reminded"}
    sets = {k: v for k, v in kwargs.items() if k in allowed}
    if not sets:
        return False
    db = get_db()
    db.execute(
        f"UPDATE tasks SET {', '.join(f'{k}=?' for k in sets)} WHERE id=?",
        (*sets.values(), task_id),
    )
    db.commit()
    return db.total_changes > 0


def delete_task(task_id: int) -> bool:
    db = get_db()
    db.execute("DELETE FROM tasks WHERE id=?", (task_id,))
    db.commit()
    return db.total_changes > 0


def get_task(task_id: int) -> dict[str, Any] | None:
    row = get_db().execute(
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
    limit: int = 30,
) -> list[dict[str, Any]]:
    clauses = []
    params: list[Any] = []
    if user_id is not None:
        clauses.append("user_id=?")
        params.append(user_id)
    if status:
        clauses.append("status=?")
        params.append(status)
    if priority:
        clauses.append("priority=?")
        params.append(priority)
    if due_before:
        clauses.append("deadline IS NOT NULL AND deadline <= ?")
        params.append(due_before)
    if due_after:
        clauses.append("deadline IS NOT NULL AND deadline >= ?")
        params.append(due_after)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = get_db().execute(
        f"SELECT id, user_id, title, description, deadline, priority, status, created, reminder_minutes, reminded "
        f"FROM tasks{where} ORDER BY deadline ASC, priority DESC LIMIT ?",
        (*params, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def tasks_for_date(user_id: int, date_str: str) -> list[dict[str, Any]]:
    """Tasks due on a specific date (YYYY-MM-DD)."""
    return list_tasks(user_id=user_id, due_after=f"{date_str} 00:00", due_before=f"{date_str} 23:59")


def tasks_with_deadlines_in_month(user_id: int, year: int, month: int) -> list[int]:
    """Return day-of-month numbers that have deadline tasks."""
    start = f"{year:04d}-{month:02d}-01"
    if month == 12:
        end = f"{year+1:04d}-01-01"
    else:
        end = f"{year:04d}-{month+1:02d}-01"
    rows = get_db().execute(
        "SELECT DISTINCT CAST(strftime('%d', deadline) AS INTEGER) AS day FROM tasks "
        "WHERE user_id=? AND status != 'done' AND status != 'cancelled' "
        "AND deadline >= ? AND deadline < ?",
        (user_id, start, end),
    ).fetchall()
    return [r["day"] for r in rows]


# ── Formatting ──

def format_task(t: dict[str, Any]) -> str:
    emoji = PRIORITY_EMOJI.get(t["priority"], "🟡")
    status_emoji = {"pending": "⏳", "in_progress": "🔄", "done": "✅", "cancelled": "❌"}.get(t["status"], "⏳")
    lines = [f"{emoji} *{t['title']}*"]
    lines.append(f"ID: `{t['id']}` | Status: {status_emoji} *{t['status']}*")
    if t.get("deadline"):
        lines.append(f"📅 Deadline: `{t['deadline'][:16]}`")
    if t.get("description"):
        lines.append(f"📝 {t['description'][:200]}")
    lines.append(f"🔔 Remind: {_fmt_reminder(t['reminder_minutes'])}")
    return "\n".join(lines)


def _fmt_reminder(minutes: int) -> str:
    if minutes <= 0:
        return "no reminder"
    if minutes < 60:
        return f"{minutes}m before"
    if minutes < 1440:
        return f"{minutes // 60}h before"
    return f"{minutes // 1440}d before"


def format_task_list(tasks: list[dict[str, Any]], header: str = "📋 Tasks") -> str:
    if not tasks:
        return f"{header}\nNo tasks found."
    lines = [f"{header} ({len(tasks)})"]
    for t in tasks:
        emoji = PRIORITY_EMOJI.get(t["priority"], "🟡")
        deadline = f" `{t['deadline'][:16]}`" if t.get("deadline") else ""
        lines.append(f"{emoji} `#{t['id']}` *{t['title'][:40]}*{deadline}")
    return "\n".join(lines)


# ── Calendar keyboard data ──

def build_calendar_data(year: int, month: int) -> dict[str, Any]:
    """Return month metadata for calendar rendering."""
    import calendar
    cal = calendar.Calendar()
    days = list(cal.itermonthdays(year, month))
    weeks: list[list[int]] = []
    for i in range(0, len(days), 7):
        weeks.append(days[i:i + 7])
    return {
        "year": year,
        "month": month,
        "month_name": calendar.month_name[month],
        "weeks": weeks,
    }


# ── Reminder scheduler ──

def _scheduler_worker():
    """Check every 60s for tasks needing reminders."""
    while True:
        time.sleep(60)
        try:
            now = datetime.now()
            rows = get_db().execute(
                "SELECT id, user_id, title, deadline, reminder_minutes, reminded FROM tasks "
                "WHERE status NOT IN ('done','cancelled') AND reminder_minutes > 0 AND reminded = 0 "
                "AND deadline IS NOT NULL",
            ).fetchall()
            for r in rows:
                try:
                    dl = datetime.fromisoformat(r["deadline"])
                    remind_before = timedelta(minutes=r["reminder_minutes"])
                    if now >= dl - remind_before and now < dl:
                        msg = (
                            f"⏰ *Task Reminder*\n"
                            f"*{r['title']}*\n"
                            f"📅 Deadline: `{dl.strftime('%Y-%m-%d %H:%M')}`\n"
                            f"`/task {r['id']}` — view details"
                        )
                        send_message_sync(r["user_id"], msg, parse_mode="Markdown")
                        get_db().execute("UPDATE tasks SET reminded=1 WHERE id=?", (r["id"],))
                        get_db().commit()
                except (ValueError, TypeError):
                    continue
        except Exception as e:
            log.error("Scheduler error: %s", e)


def start_scheduler():
    """Start the reminder scheduler in a daemon thread."""
    t = threading.Thread(target=_scheduler_worker, daemon=True)
    t.start()
    log.info("Task reminder scheduler started")
