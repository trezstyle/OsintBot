"""Task planner handlers: commands, callbacks, FSM."""
import logging
from datetime import datetime

from aiogram import Bot, Router
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, Message, InlineKeyboardMarkup

from services.tasks import (
    CalendarData,
    TaskNotFoundError,
    TaskOwnershipError,
    TaskValidationError,
    add_task,
    build_calendar_data,
    delete_task,
    format_task,
    format_task_counts,
    format_task_list,
    get_task,
    list_tasks,
    notify_scheduler_change,
    task_counts,
    tasks_for_date,
    tasks_overdue,
    tasks_this_week,
    tasks_with_deadlines_in_month,
    update_task,
)
from ui.handlers import authorized_callback, authorized_message, bot, send_long_message
from ui.keyboards import (
    calendar_keyboard,
    day_view_keyboard,
    task_confirm_delete_keyboard,
    task_list_keyboard,
    task_view_keyboard,
)

log = logging.getLogger("cyber_volt.tasks.ui")

router = Router()

_PAGE_SIZE = 10


# ── FSM ──

class TaskStates(StatesGroup):
    waiting_for_title = State()
    waiting_for_description = State()
    waiting_for_deadline = State()
    waiting_for_priority = State()


# ── Helpers ──

def _uid(msg_or_call) -> int | None:
    from aiogram.types import CallbackQuery, Message
    user = getattr(msg_or_call, "from_user", None)
    return getattr(user, "id", None)


def _get_now():
    from datetime import datetime
    return datetime.now()


def _calendar_header(uid: int | None, year: int | None = None, month: int | None = None) -> tuple[str, InlineKeyboardMarkup]:
    now = _get_now()
    y = year if year else now.year
    m = month if month else now.month
    cal = build_calendar_data(y, m)
    task_days = tasks_with_deadlines_in_month(uid, y, m) if uid else []
    text = f"📅 *{cal.month_name} {cal.year}*"
    return text, calendar_keyboard(cal, task_days)


# ── Command: /task, /tasks ──

@router.message(Command("task", "tasks"))
@authorized_message
async def cmd_task(message: Message, command: CommandObject):
    uid = _uid(message)
    args = command.args.strip().split() if command.args else []

    if not args:
        text, kb = _calendar_header(uid)
        await message.answer(text, parse_mode="Markdown", reply_markup=kb)
        return

    sub = args[0].lower()

    # ── View single task ──
    if sub.isdigit():
        tid = int(sub)
        t = get_task(tid, user_id=uid)
        if not t:
            await message.answer(f"❌ Task #{tid} not found")
            return
        text = format_task(t)
        await message.answer(text, parse_mode="Markdown", reply_markup=task_view_keyboard(tid))
        return

    # ── Add task ──
    if sub == "add":
        rest = " ".join(args[1:])
        if not rest:
            text = (
                "➕ *Create a new task*\n\n"
                "Send me the title inline:\n"
                "`/task add Buy groceries`\n\n"
                "Or with options:\n"
                "`/task add <title> | deadline: YYYY-MM-DD HH:MM | priority: low|medium|high|critical | desc: ...`\n\n"
                "💡 *Tip:* Use `/task` to pick a date from the calendar!"
            )
            await message.answer(text, parse_mode="Markdown")
            return
        try:
            tid = _parse_and_add(uid, rest)
            t = get_task(tid)
            await message.answer(
                f"✅ *Task #{tid} created*",
                parse_mode="Markdown",
                reply_markup=task_view_keyboard(tid) if t else None,
            )
            notify_scheduler_change()
        except TaskValidationError as e:
            await message.answer(f"❌ {e}")
        return

    # ── Status change shortcuts ──
    if sub == "done" and len(args) >= 2:
        _set_task_status(message, uid, args[1], "done")
        return
    if sub == "del" and len(args) >= 2:
        await _delete_task_interactive(message, uid, args[1])
        return

    # ── List views ──
    if sub in ("today", "overdue", "week", "pending", "in_progress", "done", "cancelled"):
        page = int(args[1]) - 1 if len(args) >= 2 and args[1].isdigit() else 0
        await _show_task_list(message, uid, sub, page)
        return

    # ── Stats ──
    if sub in ("stats", "count"):
        counts = task_counts(uid)
        await message.answer(format_task_counts(counts), parse_mode="Markdown")
        return

    # ── Calendar ──
    if sub in ("cal", "calendar"):
        text, kb = _calendar_header(uid)
        await message.answer(text, parse_mode="Markdown", reply_markup=kb)
        return

    # ── Search ──
    if sub == "search" and len(args) >= 2:
        query = " ".join(args[1:])
        items, total = list_tasks(user_id=uid, search=query)
        text = format_task_list(items, total, header=f"🔍 Search: {query}")
        await send_long_message(message.chat.id, text, parse_mode="Markdown")
        return

    # ── List all (paginated by default) ──
    page = int(sub) - 1 if sub.isdigit() else 0
    items, total = list_tasks(user_id=uid, page=page, page_size=_PAGE_SIZE)
    if page > 0 and not items:
        await message.answer("❌ Page not found")
        return
    header = f"📋 All Tasks"
    text = format_task_list(items, total, header=header, page=page, page_size=_PAGE_SIZE)
    total_pages = max(1, (total + _PAGE_SIZE - 1) // _PAGE_SIZE)
    kb = task_list_keyboard(items, page, total_pages) if items else None
    await message.answer(text, parse_mode="Markdown", reply_markup=kb)


def _parse_and_add(uid: int, text: str) -> int:
    parts = text.split("|")
    title = parts[0].strip()
    deadline = None
    priority = "medium"
    description = ""
    reminder_minutes = 60
    for p in parts[1:]:
        p = p.strip()
        if p.startswith("deadline:"):
            deadline = p[len("deadline:"):].strip()
        elif p.startswith("priority:"):
            priority = p[len("priority:"):].strip().lower()
        elif p.startswith("desc:"):
            description = p[len("desc:"):].strip()
        elif p.startswith("remind:"):
            try:
                reminder_minutes = int(p[len("remind:"):].strip())
            except ValueError:
                pass
    return add_task(uid, title, description, deadline, priority, reminder_minutes)


def _set_task_status(message: Message, uid: int, task_id_str: str, status: str):
    try:
        tid = int(task_id_str)
    except ValueError:
        message.answer("❌ Invalid task ID")
        return
    try:
        update_task(tid, user_id=uid, status=status)
        message.answer(f"✅ Task #{tid} → *{status}*", parse_mode="Markdown")
        notify_scheduler_change()
    except TaskNotFoundError:
        message.answer(f"❌ Task #{tid} not found")
    except TaskOwnershipError:
        message.answer("❌ Not your task")


async def _delete_task_interactive(message: Message, uid: int, task_id_str: str):
    try:
        tid = int(task_id_str)
    except ValueError:
        await message.answer("❌ Invalid task ID")
        return
    t = get_task(tid, user_id=uid)
    if not t:
        await message.answer(f"❌ Task #{tid} not found")
        return
    text = f"🗑 *Delete task #{tid}?*\n\n{t['title'][:100]}"
    await message.answer(text, parse_mode="Markdown", reply_markup=task_confirm_delete_keyboard(tid))


async def _show_task_list(message: Message, uid: int, view: str, page: int):
    now = _get_now()
    items: list[dict] = []
    total = 0

    if view == "today":
        date_str = now.strftime("%Y-%m-%d")
        items, total = tasks_for_date(uid, date_str, page=page)
        header = f"📋 Today ({date_str})"
    elif view == "overdue":
        items, total = tasks_overdue(uid, page=page)
        header = "⚠️ Overdue"
    elif view == "week":
        items, total = tasks_this_week(uid, page=page)
        header = "📋 This Week"
    else:
        items, total = list_tasks(user_id=uid, status=view, page=page, page_size=_PAGE_SIZE)
        header = f"📋 {view.replace('_', ' ').title()}"

    total_pages = max(1, (total + _PAGE_SIZE - 1) // _PAGE_SIZE)
    text = format_task_list(items, total, header=header, page=page, page_size=_PAGE_SIZE)
    kb = task_list_keyboard(items, page, total_pages) if items else None
    await message.answer(text, parse_mode="Markdown", reply_markup=kb)


# ── FSM: Interactive Task Creation ──

@router.message(TaskStates.waiting_for_title)
@authorized_message
async def fsm_task_title(message: Message, state: FSMContext):
    title = message.text.strip() if message.text else ""
    if not title:
        await message.answer("❌ Title cannot be empty.")
        return
    if len(title) > 200:
        await message.answer("❌ Title too long (max 200 chars).")
        return
    uid = _uid(message)
    data = await state.get_data()
    deadline = data.get("add_date")
    try:
        tid = add_task(uid, title, deadline=deadline)
        t = get_task(tid)
        text = f"✅ *Task #{tid} created!*\n\n{format_task(t)}"
        await message.answer(
            text,
            parse_mode="Markdown",
            reply_markup=task_view_keyboard(tid),
        )
        notify_scheduler_change()
    except TaskValidationError as e:
        await message.answer(f"❌ {e}")
    await state.clear()


# ── Calendar Callbacks ──

@router.callback_query(lambda c: c.data and c.data.startswith("cal_"))
@authorized_callback
async def handle_calendar(call: CallbackQuery):
    uid = _uid(call)
    parts = call.data.split("_")
    cmd = parts[1]

    try:
        if cmd == "month":
            y, m = int(parts[2]), int(parts[3])
            text, kb = _calendar_header(uid, y, m)
            await call.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)

        elif cmd == "today":
            text, kb = _calendar_header(uid)
            await call.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)

        elif cmd == "day":
            y, m, d = int(parts[2]), int(parts[3]), int(parts[4])
            date_str = f"{y:04d}-{m:02d}-{d:02d}"
            items, total = tasks_for_date(uid, date_str)
            day_kb = day_view_keyboard(y, m, d)
            if not items:
                await call.message.edit_text(
                    f"📅 *{date_str}*\nNo tasks for this day.\n\n➕ Tap below to add one:",
                    parse_mode="Markdown",
                    reply_markup=day_kb,
                )
            else:
                text = format_task_list(items, total, header=f"📋 {date_str}")
                await call.message.edit_text(text, parse_mode="Markdown", reply_markup=day_kb)

        elif cmd == "ignore":
            await call.answer()
            return

    except Exception as e:
        log.error("Calendar callback error: %s", e)
        await call.answer("❌ Error", show_alert=True)
        return

    await call.answer()


# ── Task Action Callbacks ──

@router.callback_query(lambda c: c.data and c.data.startswith("task_"))
@authorized_callback
async def handle_task_actions(call: CallbackQuery, state: FSMContext = None):
    uid = _uid(call)
    data = call.data
    parts = data.split("_")
    action = parts[1]

    # task_view_<id>
    if action == "view" and len(parts) >= 3:
        tid = int(parts[2])
        t = get_task(tid, user_id=uid)
        if not t:
            await call.message.edit_text(f"❌ Task #{tid} not found")
        else:
            text = format_task(t)
            await call.message.edit_text(text, parse_mode="Markdown", reply_markup=task_view_keyboard(tid))
        await call.answer()
        return

    # task_list — show all tasks page 0
    if action == "list":
        items, total = list_tasks(user_id=uid, page=0, page_size=_PAGE_SIZE)
        total_pages = max(1, (total + _PAGE_SIZE - 1) // _PAGE_SIZE)
        header = "📋 All Tasks"
        text = format_task_list(items, total, header=header, page=0, page_size=_PAGE_SIZE)
        kb = task_list_keyboard(items, 0, total_pages) if items else None
        await call.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
        await call.answer()
        return

    # task_page_<n>
    if action == "page" and len(parts) >= 3:
        page = int(parts[2])
        items, total = list_tasks(user_id=uid, page=page, page_size=_PAGE_SIZE)
        total_pages = max(1, (total + _PAGE_SIZE - 1) // _PAGE_SIZE)
        header = "📋 All Tasks"
        text = format_task_list(items, total, header=header, page=page, page_size=_PAGE_SIZE)
        kb = task_list_keyboard(items, page, total_pages) if items else None
        await call.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
        await call.answer()
        return

    # task_calendar
    if action == "calendar":
        text, kb = _calendar_header(uid)
        await call.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
        await call.answer()
        return

    # task_status_<id>_<status>
    if action == "status" and len(parts) >= 4:
        tid = int(parts[2])
        status = parts[3]
        try:
            update_task(tid, user_id=uid, status=status)
            t = get_task(tid)
            text = format_task(t) if t else f"✅ Task #{tid} → *{status}*"
            kb = task_view_keyboard(tid) if t else None
            await call.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
            notify_scheduler_change()
        except (TaskNotFoundError, TaskOwnershipError) as e:
            await call.answer(str(e), show_alert=True)
        await call.answer()
        return

    # task_del_<id> — confirm prompt
    if action == "del" and len(parts) >= 3:
        tid = int(parts[2])
        t = get_task(tid, user_id=uid)
        if not t:
            await call.answer("❌ Task not found", show_alert=True)
            return
        text = f"🗑 *Delete task #{tid}?*\n\n{t['title'][:100]}"
        await call.message.edit_text(text, parse_mode="Markdown", reply_markup=task_confirm_delete_keyboard(tid))
        await call.answer()
        return

    # task_del_confirm_<id> — actual delete
    if action == "del" and parts[2] == "confirm" and len(parts) >= 4:
        tid = int(parts[3])
        try:
            delete_task(tid, user_id=uid)
            await call.message.edit_text(f"🗑 Task #{tid} deleted")
            notify_scheduler_change()
        except (TaskNotFoundError, TaskOwnershipError) as e:
            await call.answer(str(e), show_alert=True)
        await call.answer()
        return

    # task_add_prompt
    if action == "add" and parts[2] == "prompt":
        await call.message.edit_text(
            "➕ *Create a new task*\n\nJust send me the title, I'll handle the rest.\n\n"
            "For advanced options use:\n"
            "`/task add <title> | deadline: YYYY-MM-DD HH:MM | priority: low|medium|high|critical | desc: ...`",
            parse_mode="Markdown",
        )
        if state is not None:
            await state.set_state(TaskStates.waiting_for_title)
        await call.answer()
        return

    # task_add_date_YYYY_MM_DD — add task for a specific date
    if action == "add" and parts[2] == "date" and len(parts) >= 4:
        date_str = f"{parts[3]}-{parts[4]}-{parts[5]}"
        await call.message.edit_text(
            f"📅 *Add task for {date_str}*\n\nSend me the task title:",
            parse_mode="Markdown",
        )
        if state is not None:
            await state.update_data(add_date=date_str)
            await state.set_state(TaskStates.waiting_for_title)
        await call.answer()
        return

    await call.answer("Unknown action", show_alert=True)
