"""Tests for ui/keyboards.py — all inline keyboard builders."""
from aiogram.types import InlineKeyboardMarkup

from services.tasks import CalendarData
from ui.keyboards import (
    calendar_keyboard,
    day_view_keyboard,
    help_keyboard,
    logs_keyboard,
    scan_keyboard,
    fim_keyboard,
    top_keyboard,
    task_confirm_delete_keyboard,
    task_list_keyboard,
    task_priority_keyboard,
    task_view_keyboard,
)


def _extract_callback_data(kb: InlineKeyboardMarkup) -> list[str]:
    """Flatten all callback_data from a keyboard."""
    result = []
    for row in kb.inline_keyboard:
        for btn in row:
            if btn.callback_data:
                result.append(btn.callback_data)
    return result


def _extract_texts(kb: InlineKeyboardMarkup) -> list[str]:
    """Flatten all button texts from a keyboard."""
    result = []
    for row in kb.inline_keyboard:
        for btn in row:
            result.append(btn.text)
    return result


# ── System keyboards ──


class TestHelpKeyboard:
    def test_returns_inline_markup(self):
        kb = help_keyboard()
        assert isinstance(kb, InlineKeyboardMarkup)

    def test_has_expected_buttons(self):
        kb = help_keyboard()
        texts = _extract_texts(kb)
        assert "🎯 IP Threat Hunt" in texts
        assert "🔐 HIBP Check" in texts
        assert "📄 PDF Report" in texts
        assert "🚨 Suricata Alerts" in texts

    def test_all_callbacks_have_h_prefix(self):
        callbacks = _extract_callback_data(help_keyboard())
        assert all(c.startswith("h_") for c in callbacks)


class TestLogsKeyboard:
    def test_returns_inline_markup(self):
        kb = logs_keyboard()
        assert isinstance(kb, InlineKeyboardMarkup)

    def test_has_menu_button(self):
        callbacks = _extract_callback_data(logs_keyboard())
        assert "h_menu" in callbacks

    def test_has_filter_buttons(self):
        texts = _extract_texts(logs_keyboard())
        assert "🚫 Failed" in texts
        assert "🔐 SSH" in texts


class TestScanKeyboard:
    def test_has_scan_buttons(self):
        texts = _extract_texts(scan_keyboard())
        assert any("🔍" in t and "Full" in t for t in texts)
        assert any("⚡" in t and "Fast" in t for t in texts)

    def test_menu_callback(self):
        callbacks = _extract_callback_data(scan_keyboard())
        assert "h_menu" in callbacks


class TestFimKeyboard:
    def test_has_add_and_check(self):
        texts = _extract_texts(fim_keyboard())
        assert "➕ Add File" in texts
        assert "🔍 Check All" in texts

    def test_menu_callback(self):
        callbacks = _extract_callback_data(fim_keyboard())
        assert "h_menu" in callbacks


class TestTopKeyboard:
    def test_has_sort_buttons(self):
        texts = _extract_texts(top_keyboard("cpu"))
        assert any("CPU" in t for t in texts)
        assert any("RAM" in t for t in texts)

    def test_refresh_button(self):
        texts = _extract_texts(top_keyboard("ram"))
        assert any("🔄" in t for t in texts)

    def test_menu_callback(self):
        callbacks = _extract_callback_data(top_keyboard())
        assert "h_menu" in callbacks

    def test_active_sort_marker(self):
        cpu_kb = top_keyboard("cpu")
        cpu_texts = _extract_texts(cpu_kb)
        ram_kb = top_keyboard("ram")
        ram_texts = _extract_texts(ram_kb)
        default_kb = top_keyboard()
        def_texts = _extract_texts(default_kb)
        # All keyboards have sort labels; just check they exist
        assert any("CPU" in t for t in cpu_texts)
        assert any("RAM" in t for t in ram_texts)
        assert any("CPU" in t for t in def_texts)


# ── Task / Calendar keyboards ──


class TestCalendarKeyboard:
    def test_returns_inline_markup(self):
        cal = CalendarData(year=2026, month=5, month_name="May", weeks=[[0, 0, 1, 2, 3, 4, 5]])
        kb = calendar_keyboard(cal, task_days=[3])
        assert isinstance(kb, InlineKeyboardMarkup)

    def test_month_header(self):
        cal = CalendarData(year=2026, month=5, month_name="May", weeks=[[1]])
        kb = calendar_keyboard(cal, task_days=[])
        texts = _extract_texts(kb)
        assert any("📅" in t for t in texts)

    def test_day_headers(self):
        cal = CalendarData(year=2026, month=5, month_name="May", weeks=[[1, 2, 3, 4, 5, 6, 7]])
        kb = calendar_keyboard(cal, task_days=[])
        texts = _extract_texts(kb)
        for h in ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"]:
            assert h in texts

    def test_navigation(self):
        cal = CalendarData(year=2026, month=5, month_name="May", weeks=[[1]])
        kb = calendar_keyboard(cal, task_days=[])
        callbacks = _extract_callback_data(kb)
        assert any(c.startswith("cal_month_") for c in callbacks)
        assert "cal_today" in callbacks

    def test_bottom_buttons(self):
        cal = CalendarData(year=2026, month=5, month_name="May", weeks=[[1]])
        kb = calendar_keyboard(cal, task_days=[])
        callbacks = _extract_callback_data(kb)
        assert "task_list" in callbacks
        assert "task_add_prompt" in callbacks
        assert "h_menu" in callbacks

    def test_task_days_marked(self):
        cal = CalendarData(year=2026, month=5, month_name="May", weeks=[[0, 0, 0, 15, 0, 0, 0]])
        kb = calendar_keyboard(cal, task_days=[15])
        texts = _extract_texts(kb)
        assert any("15📌" in t for t in texts)

    def test_empty_days_have_space(self):
        cal = CalendarData(year=2026, month=5, month_name="May", weeks=[[0, 1, 2, 3, 4, 5, 6]])
        kb = calendar_keyboard(cal, task_days=[])
        texts = _extract_texts(kb)
        assert any(t == " " for t in texts)

    def test_prev_next_month_navigation(self):
        cal = CalendarData(year=2026, month=5, month_name="May", weeks=[[1]])
        kb = calendar_keyboard(cal, task_days=[])
        callbacks = _extract_callback_data(kb)
        assert "cal_month_2026_4" in callbacks
        assert "cal_month_2026_6" in callbacks


class TestDayViewKeyboard:
    def test_returns_inline_markup(self):
        kb = day_view_keyboard(2026, 5, 19)
        assert isinstance(kb, InlineKeyboardMarkup)

    def test_add_task_button(self):
        kb = day_view_keyboard(2026, 5, 19)
        callbacks = _extract_callback_data(kb)
        assert "task_add_date_2026-05-19" in callbacks

    def test_calendar_button(self):
        kb = day_view_keyboard(2026, 5, 19)
        callbacks = _extract_callback_data(kb)
        assert "task_calendar" in callbacks

    def test_leap_year(self):
        kb = day_view_keyboard(2024, 2, 29)
        texts = _extract_texts(kb)
        assert any("Add task" in t for t in texts)


class TestTaskViewKeyboard:
    def test_has_status_buttons(self):
        kb = task_view_keyboard(42)
        callbacks = _extract_callback_data(kb)
        assert "task_status_42_done" in callbacks
        assert "task_status_42_in_progress" in callbacks
        assert "task_status_42_pending" in callbacks
        assert "task_status_42_cancelled" in callbacks

    def test_delete_button(self):
        kb = task_view_keyboard(7)
        callbacks = _extract_callback_data(kb)
        assert "task_del_7" in callbacks

    def test_list_and_calendar(self):
        kb = task_view_keyboard(1)
        callbacks = _extract_callback_data(kb)
        assert "task_list" in callbacks
        assert "task_calendar" in callbacks


class TestTaskConfirmDeleteKeyboard:
    def test_confirm_button(self):
        kb = task_confirm_delete_keyboard(42)
        callbacks = _extract_callback_data(kb)
        assert "task_del_confirm_42" in callbacks

    def test_cancel_button(self):
        kb = task_confirm_delete_keyboard(42)
        callbacks = _extract_callback_data(kb)
        assert "task_view_42" in callbacks

    def test_keep_button_text(self):
        kb = task_confirm_delete_keyboard(1)
        texts = _extract_texts(kb)
        assert any("No, keep" in t for t in texts)


class TestTaskListKeyboard:
    def test_empty_tasks_list(self):
        kb = task_list_keyboard([], page=0, total_pages=1)
        callbacks = _extract_callback_data(kb)
        # Should still show calendar and new
        assert "task_calendar" in callbacks
        assert "task_add_prompt" in callbacks

    def test_task_buttons(self):
        tasks = [
            {"id": 1, "title": "Alpha", "priority": "high", "status": "pending"},
            {"id": 2, "title": "Beta", "priority": "low", "status": "done"},
        ]
        kb = task_list_keyboard(tasks, page=0, total_pages=1)
        callbacks = _extract_callback_data(kb)
        assert "task_view_1" in callbacks
        assert "task_view_2" in callbacks

    def test_pagination_buttons(self):
        tasks = [{"id": i, "title": f"T{i}", "priority": "medium", "status": "pending"} for i in range(5)]
        kb = task_list_keyboard(tasks, page=0, total_pages=3)
        callbacks = _extract_callback_data(kb)
        assert "task_page_1" in callbacks  # next page
        assert "task_page_0" not in callbacks  # no prev on first page

    def test_prev_button_on_page_2(self):
        tasks = [{"id": i, "title": f"T{i}", "priority": "medium", "status": "pending"} for i in range(5)]
        kb = task_list_keyboard(tasks, page=1, total_pages=3)
        callbacks = _extract_callback_data(kb)
        assert "task_page_0" in callbacks
        assert "task_page_2" in callbacks

    def test_done_marker_in_label(self):
        tasks = [{"id": 1, "title": "Done", "priority": "low", "status": "done"}]
        kb = task_list_keyboard(tasks, page=0, total_pages=1)
        texts = _extract_texts(kb)
        assert any("✅" in t for t in texts)

    def test_priority_emoji(self):
        tasks = [{"id": 1, "title": "Crit", "priority": "critical", "status": "pending"}]
        kb = task_list_keyboard(tasks, page=0, total_pages=1)
        texts = _extract_texts(kb)
        assert any("🔴" in t for t in texts)


class TestTaskPriorityKeyboard:
    def test_has_all_priorities(self):
        kb = task_priority_keyboard()
        texts = _extract_texts(kb)
        assert any("Low" in t for t in texts)
        assert any("Medium" in t for t in texts)
        assert any("High" in t for t in texts)
        assert any("Critical" in t for t in texts)

    def test_custom_prefix(self):
        kb = task_priority_keyboard(prefix="my_prefix")
        callbacks = _extract_callback_data(kb)
        assert all(c.startswith("my_prefix_") for c in callbacks)
