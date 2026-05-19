"""Tests for services/database.py — all CRUD operations."""
import sqlite3
from unittest.mock import patch

import pytest

from services.database import (
    _safe_commit,
    close_db,
    delete_user,
    fim_upsert,
    get_alerts,
    get_history,
    get_setting,
    get_user,
    list_users,
    push_alert,
    record_command,
    set_setting,
    set_user,
)


class TestPushAlert:
    def test_push_and_get(self):
        push_alert("2026-05-19 10:00", "Alert line 1")
        push_alert("2026-05-19 10:05", "Alert line 2")
        alerts = get_alerts(limit=10)
        assert len(alerts) == 2
        assert alerts[0]["line"] == "Alert line 2"
        assert alerts[1]["line"] == "Alert line 1"

    def test_limit(self):
        for i in range(5):
            push_alert("now", f"Alert {i}")
        alerts = get_alerts(limit=3)
        assert len(alerts) == 3

    def test_trim_to_200(self):
        for i in range(250):
            push_alert("now", f"Alert {i}")
        alerts = get_alerts(limit=500)
        assert len(alerts) <= 200


class TestRecordCommand:
    def test_record_and_get(self):
        record_command(42, "user42", "/test", "arg1 arg2")
        history = get_history(limit=10)
        assert len(history) == 1
        entry = history[0]
        assert entry["user_id"] == 42
        assert entry["username"] == "user42"
        assert entry["cmd"] == "/test"

    def test_none_user(self):
        record_command(None, None, "/anon", "")
        history = get_history(limit=10)
        assert len(history) == 1
        assert history[0]["username"] == "unknown"

    def test_trim_to_100(self):
        for i in range(150):
            record_command(1, "u", "/cmd", "")
        history = get_history(limit=500)
        assert len(history) <= 100


class TestUsers:
    def test_set_and_get(self):
        set_user(42, "trez0", role="admin")
        user = get_user(42)
        assert user is not None
        assert user["username"] == "trez0"
        assert user["role"] == "admin"

    def test_get_not_found(self):
        assert get_user(99999) is None

    def test_list_users(self):
        set_user(1, "alpha")
        set_user(2, "beta", role="user")
        users = list_users()
        assert len(users) == 2
        usernames = [u["username"] for u in users]
        assert "alpha" in usernames
        assert "beta" in usernames

    def test_delete_user(self):
        set_user(42, "deletable")
        delete_user(42)
        assert get_user(42) is None


class TestSettings:
    def test_set_and_get(self):
        set_setting("theme", "dark")
        assert get_setting("theme") == "dark"

    def test_default(self):
        assert get_setting("nonexistent", default="default_val") == "default_val"

    def test_overwrite(self):
        set_setting("key", "value1")
        set_setting("key", "value2")
        assert get_setting("key") == "value2"


class TestFimUpsert:
    def test_insert(self):
        fim_upsert("/etc/hosts", "abc123", "2026-05-19")
        from services.database import fim_load
        data = fim_load()
        assert "/etc/hosts" in data
        assert data["/etc/hosts"]["hash"] == "abc123"

    def test_update(self):
        fim_upsert("/etc/hosts", "oldhash", "2026-05-19")
        fim_upsert("/etc/hosts", "newhash", "2026-05-19")
        from services.database import fim_load
        data = fim_load()
        assert data["/etc/hosts"]["hash"] == "newhash"


class TestSafeCommit:
    def test_commit_success(self):
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE t (x TEXT)")
        _safe_commit(db)
        db.close()

    def test_commit_failure_does_not_raise(self):
        db = sqlite3.connect(":memory:")
        _safe_commit(db)
        db.close()


class TestCloseDb:
    def test_close_twice_does_not_raise(self):
        close_db()
        close_db()
