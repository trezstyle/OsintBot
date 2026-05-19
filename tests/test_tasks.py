"""Tests for services/tasks.py — CRUD, helpers, formatting, calendar, scheduler."""
from datetime import datetime, timedelta
from unittest.mock import ANY, MagicMock, patch

import pytest

from services.tasks import (
    CalendarData,
    PRIORITIES,
    TaskNotFoundError,
    TaskOwnershipError,
    TaskValidationError,
    VALID_STATUSES,
    _fmt_date,
    _fmt_progress,
    _fmt_reminder,
    _parse_deadline,
    _validate_priority,
    _validate_status,
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
from services.database import get_db


# ── Helper tests ──


class TestParseDeadline:
    def test_empty(self):
        assert _parse_deadline("") is None
        assert _parse_deadline(None) is None
        assert _parse_deadline("  ") is None

    def test_yyyy_mm_dd(self):
        assert _parse_deadline("2026-05-20") == "2026-05-20"

    def test_yyyy_mm_dd_hh_mm(self):
        assert _parse_deadline("2026-05-20 14:30") == "2026-05-20 14:30"

    def test_dd_mm_yyyy(self):
        assert _parse_deadline("20.05.2026") == "2026-05-20"

    def test_dd_mm(self):
        result = _parse_deadline("20.05")
        assert result == f"{datetime.now().year}-05-20"

    def test_invalid_format(self):
        assert _parse_deadline("not a date") is None
        assert _parse_deadline("2026/05/20") is None


class TestValidatePriority:
    def test_valid(self):
        for p in PRIORITIES:
            assert _validate_priority(p) == p

    def test_case_insensitive(self):
        assert _validate_priority("HIGH") == "high"

    def test_invalid_defaults_to_medium(self):
        assert _validate_priority("urgent") == "medium"
        assert _validate_priority("") == "medium"


class TestValidateStatus:
    def test_valid(self):
        for s in VALID_STATUSES:
            assert _validate_status(s) == s

    def test_case_insensitive(self):
        assert _validate_status("DONE") == "done"

    def test_invalid_defaults_to_pending(self):
        assert _validate_status("archived") == "pending"
        assert _validate_status("") == "pending"


class TestFmtReminder:
    def test_no_reminder(self):
        assert _fmt_reminder(0) == "no reminder"
        assert _fmt_reminder(-1) == "no reminder"

    def test_minutes(self):
        assert _fmt_reminder(30) == "30m before"

    def test_hours(self):
        assert _fmt_reminder(120) == "2h before"

    def test_days(self):
        assert _fmt_reminder(2880) == "2d before"


class TestFmtDate:
    def test_empty(self):
        assert _fmt_date("") == ""
        assert _fmt_date(None) == ""

    @patch("services.tasks.datetime")
    def test_today(self, mock_dt):
        mock_dt.now.return_value = datetime(2026, 5, 19, 10, 0)
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        result = _fmt_date("2026-05-19 08:00")
        assert "Today" in result

    @patch("services.tasks.datetime")
    def test_tomorrow(self, mock_dt):
        mock_dt.now.return_value = datetime(2026, 5, 19, 10, 0)
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        result = _fmt_date("2026-05-20 08:00")
        assert "Tomorrow" in result

    @patch("services.tasks.datetime")
    def test_this_year(self, mock_dt):
        mock_dt.now.return_value = datetime(2026, 5, 19, 10, 0)
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        result = _fmt_date("2026-06-01 08:00")
        assert "Jun" in result
        assert "2026" not in result

    @patch("services.tasks.datetime")
    def test_other_year(self, mock_dt):
        mock_dt.now.return_value = datetime(2026, 5, 19, 10, 0)
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        result = _fmt_date("2027-01-01 08:00")
        assert "2027" in result


class TestFmtProgress:
    def test_done(self):
        t = {"status": "done"}
        assert "100%" in _fmt_progress(t)

    def test_cancelled(self):
        t = {"status": "cancelled"}
        assert "cancelled" in _fmt_progress(t)

    def test_no_deadline(self):
        t = {"status": "pending", "deadline": None}
        assert "0%" in _fmt_progress(t)

    def test_overdue(self):
        t = {"status": "pending", "deadline": "2020-01-01 00:00"}
        assert "OVERDUE" in _fmt_progress(t)

    @patch("services.tasks.datetime")
    def test_weeks_away(self, mock_dt):
        mock_dt.now.return_value = datetime(2026, 5, 19, 10, 0)
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        t = {"status": "pending", "deadline": "2026-06-01 00:00"}
        result = _fmt_progress(t)
        assert "d left" in result


# ── CRUD tests ──

_UID = 42


class TestAddTask:
    def test_basic(self):
        tid = add_task(_UID, "Test task")
        t = get_task(tid, _UID)
        assert t is not None
        assert t["title"] == "Test task"
        assert t["status"] == "pending"
        assert t["priority"] == "medium"

    def test_with_all_options(self):
        tid = add_task(
            _UID, "Full task",
            description="A description",
            deadline="2026-06-15",
            priority="high",
            reminder_minutes=30,
        )
        t = get_task(tid, _UID)
        assert t["title"] == "Full task"
        assert t["description"] == "A description"
        assert t["deadline"] == "2026-06-15"
        assert t["priority"] == "high"

    def test_empty_title_raises(self):
        with pytest.raises(TaskValidationError, match="Title is required"):
            add_task(_UID, "")
        with pytest.raises(TaskValidationError):
            add_task(_UID, "   ")

    def test_title_too_long(self):
        with pytest.raises(TaskValidationError):
            add_task(_UID, "x" * 201)

    def test_whitespace_stripped(self):
        tid = add_task(_UID, "  spaced  ")
        t = get_task(tid, _UID)
        assert t["title"] == "spaced"

    def test_multiple_tasks_unique_ids(self):
        t1 = add_task(_UID, "First")
        t2 = add_task(_UID, "Second")
        assert t1 != t2


class TestGetTask:
    def test_not_found(self):
        assert get_task(99999, _UID) is None

    def test_wrong_user(self):
        tid = add_task(_UID, "Mine")
        assert get_task(tid, 999) is None

    def test_without_user_id(self):
        tid = add_task(_UID, "Any user sees this")
        t = get_task(tid)
        assert t is not None
        assert t["title"] == "Any user sees this"


class TestUpdateTask:
    def test_update_title(self):
        tid = add_task(_UID, "Old title")
        update_task(tid, user_id=_UID, title="New title")
        assert get_task(tid, _UID)["title"] == "New title"

    def test_update_status(self):
        tid = add_task(_UID, "Do this")
        update_task(tid, user_id=_UID, status="done")
        assert get_task(tid, _UID)["status"] == "done"

    def test_update_deadline(self):
        tid = add_task(_UID, "Timed")
        update_task(tid, user_id=_UID, deadline="2026-12-31")
        assert get_task(tid, _UID)["deadline"] == "2026-12-31"

    def test_update_priority_validation(self):
        tid = add_task(_UID, "Prioritized")
        update_task(tid, user_id=_UID, priority="invalid")
        assert get_task(tid, _UID)["priority"] == "medium"

    def test_ownership_error(self):
        tid = add_task(_UID, "Not yours")
        with pytest.raises(TaskOwnershipError):
            update_task(tid, user_id=999, status="done")

    def test_not_found_raises(self):
        with pytest.raises(TaskNotFoundError):
            update_task(99999, user_id=_UID, status="done")

    def test_no_changes(self):
        tid = add_task(_UID, "Static")
        result = update_task(tid, user_id=_UID)
        assert result is False


class TestDeleteTask:
    def test_delete_success(self):
        tid = add_task(_UID, "Delete me")
        delete_task(tid, _UID)
        assert get_task(tid, _UID) is None

    def test_delete_ownership_error(self):
        tid = add_task(_UID, "Not yours")
        with pytest.raises(TaskOwnershipError):
            delete_task(tid, user_id=999)

    def test_delete_not_found(self):
        with pytest.raises(TaskNotFoundError):
            delete_task(99999, user_id=_UID)

    def test_delete_without_user_id(self):
        tid = add_task(_UID, "Admin delete")
        delete_task(tid)
        assert get_task(tid) is None


class TestListTasks:
    def test_empty(self):
        items, total = list_tasks(user_id=_UID)
        assert items == []
        assert total == 0

    def test_lists_user_tasks_only(self):
        add_task(_UID, "Mine")
        add_task(99, "Not mine")
        items, total = list_tasks(user_id=_UID)
        assert total == 1
        assert items[0]["title"] == "Mine"

    def test_filter_by_status(self):
        t1 = add_task(_UID, "Pending")
        t2 = add_task(_UID, "To do later")
        update_task(t2, user_id=_UID, status="done")
        items, total = list_tasks(user_id=_UID, status="done")
        assert total == 1
        assert items[0]["title"] == "To do later"

    def test_filter_by_priority(self):
        add_task(_UID, "Normal")
        tid = add_task(_UID, "Critical")
        update_task(tid, user_id=_UID, priority="critical")
        items, total = list_tasks(user_id=_UID, priority="critical")
        assert total == 1
        assert items[0]["title"] == "Critical"

    def test_search(self):
        add_task(_UID, "Buy milk")
        add_task(_UID, "Walk dog")
        items, total = list_tasks(user_id=_UID, search="milk")
        assert total == 1

    def test_pagination(self):
        for i in range(5):
            add_task(_UID, f"Task {i}")
        items, total = list_tasks(user_id=_UID, page=0, page_size=2)
        assert len(items) == 2
        assert total == 5
        items2, _ = list_tasks(user_id=_UID, page=1, page_size=2)
        assert len(items2) == 2

    def test_order_done_last(self):
        t1 = add_task(_UID, "A - pending")
        t2 = add_task(_UID, "B - done")
        update_task(t2, user_id=_UID, status="done")
        items, _ = list_tasks(user_id=_UID)
        titles = [t["title"] for t in items]
        assert titles == ["A - pending", "B - done"]


class TestTasksForDate:
    def test_empty_day(self):
        items, total = tasks_for_date(_UID, "2026-05-19")
        assert total == 0

    def test_tasks_on_date(self):
        add_task(_UID, "Due today", deadline="2026-05-19 10:00")
        add_task(_UID, "Due tomorrow", deadline="2026-05-20 10:00")
        items, total = tasks_for_date(_UID, "2026-05-19")
        assert total == 1
        assert items[0]["title"] == "Due today"


class TestTasksOverdue:
    def test_no_overdue(self):
        items, total = tasks_overdue(_UID)
        assert total == 0

    def test_past_deadline(self):
        add_task(_UID, "Late", deadline="2020-01-01")
        items, total = tasks_overdue(_UID)
        assert total == 1
        assert items[0]["title"] == "Late"

    def test_done_not_overdue(self):
        tid = add_task(_UID, "Done late", deadline="2020-01-01")
        update_task(tid, user_id=_UID, status="done")
        items, total = tasks_overdue(_UID)
        assert total == 0


class TestTasksThisWeek:
    def test_empty(self):
        items, total = tasks_this_week(_UID)
        assert total == 0

    def test_upcoming(self):
        future = (datetime.now() + timedelta(days=3)).strftime("%Y-%m-%d")
        add_task(_UID, "Soon", deadline=future)
        items, total = tasks_this_week(_UID)
        assert total == 1


class TestTasksWithDeadlinesInMonth:
    def test_no_tasks(self):
        result = tasks_with_deadlines_in_month(_UID, 2026, 5)
        assert result == []

    def test_active_tasks_only(self):
        add_task(_UID, "Active", deadline="2026-05-15")
        tid = add_task(_UID, "Done", deadline="2026-05-20")
        update_task(tid, user_id=_UID, status="done")
        result = tasks_with_deadlines_in_month(_UID, 2026, 5)
        assert 15 in result
        assert 20 not in result

    def test_different_month(self):
        add_task(_UID, "June task", deadline="2026-06-10")
        may = tasks_with_deadlines_in_month(_UID, 2026, 5)
        june = tasks_with_deadlines_in_month(_UID, 2026, 6)
        assert 10 not in may
        assert 10 in june


class TestTaskCounts:
    def test_all_zero(self):
        c = task_counts(_UID)
        assert c["total"] == 0
        assert c["overdue"] == 0

    def test_counts(self):
        add_task(_UID, "P1")
        add_task(_UID, "P2")
        t = add_task(_UID, "D1")
        update_task(t, user_id=_UID, status="done")
        c = task_counts(_UID)
        assert c["total"] == 3
        assert c["pending"] == 2
        assert c["done"] == 1
        assert c["overdue"] == 0


class TestNotifySchedulerChange:
    def test_does_not_raise(self):
        notify_scheduler_change()  # smoke test


# ── Formatting tests ──


class TestFormatTask:
    def _make(self, **overrides):
        task = {
            "id": 1,
            "title": "Test",
            "priority": "medium",
            "status": "pending",
            "reminder_minutes": 60,
            "deadline": None,
            "description": "",
            "created": "2026-05-19 10:00",
        }
        task.update(overrides)
        return task

    def test_title_and_id(self):
        result = format_task(self._make())
        assert "#1" in result
        assert "Test" in result

    def test_priority_emoji(self):
        result = format_task(self._make(priority="critical"))
        assert "🔴" in result

    def test_with_deadline(self):
        result = format_task(self._make(deadline="2026-06-01 08:00"))
        assert "Deadline" in result

    def test_with_description(self):
        result = format_task(self._make(description="Details here"))
        assert "Details" in result


class TestFormatTaskList:
    def test_empty(self):
        result = format_task_list([], 0)
        assert "No tasks found" in result

    def test_with_tasks(self):
        tasks = [{"id": 1, "title": "A", "priority": "low", "status": "pending", "deadline": None}]
        result = format_task_list(tasks, 1, header="My List")
        assert "My List" in result
        assert "A" in result

    def test_done_marker(self):
        tasks = [{"id": 1, "title": "Done", "priority": "low", "status": "done", "deadline": None}]
        result = format_task_list(tasks, 1)
        assert "✅" in result

    @patch("services.tasks.datetime")
    def test_overdue_marker(self, mock_dt):
        mock_dt.now.return_value = datetime(2026, 5, 19, 10, 0)
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        tasks = [{"id": 1, "title": "Late", "priority": "medium", "status": "pending", "deadline": "2020-01-01"}]
        result = format_task_list(tasks, 1)
        assert "OVERDUE" in result


class TestFormatTaskCounts:
    def test_all_counts(self):
        counts = {"total": 10, "pending": 4, "in_progress": 2, "done": 3, "cancelled": 1, "overdue": 2}
        result = format_task_counts(counts)
        assert "10" in result
        assert "4" in result
        assert "2" in result


# ── Calendar tests ──


class TestBuildCalendarData:
    def test_structure(self):
        cal = build_calendar_data(2026, 5)
        assert isinstance(cal, CalendarData)
        assert cal.year == 2026
        assert cal.month == 5
        assert cal.month_name == "May"
        assert len(cal.weeks) >= 4
        # All weeks have 7 entries (some may be 0 for padding)
        for week in cal.weeks:
            assert len(week) == 7


class TestCalendarData:
    def test_fields(self):
        c = CalendarData(year=2026, month=5, month_name="May", weeks=[[1, 2, 3]])
        assert c.year == 2026
        assert c.month == 5
        assert c.month_name == "May"
        assert c.weeks == [[1, 2, 3]]
