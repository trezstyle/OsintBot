"""Tests for watchers — shared state, thread safety, invariants."""
from datetime import datetime
import threading

import watchers
from watchers import (
    ALERT_CHAT_ID_LOCK,
    ALERT_CHAT_ID_SET,
    _failed_attempts_lock,
    _get_alert_chat_id,
    _set_alert_chat_id,
    failed_attempts,
)


def _reset_state():
    ALERT_CHAT_ID_SET.clear()
    with ALERT_CHAT_ID_LOCK:
        watchers._alert_chat_id = None
    with _failed_attempts_lock:
        failed_attempts.clear()


def setup_function():
    _reset_state()


def teardown_function():
    _reset_state()


# ── Alert chat ID ──


def test_default_none():
    assert _get_alert_chat_id() is None
    assert not ALERT_CHAT_ID_SET.is_set()


def test_set_and_get():
    _set_alert_chat_id(12345)
    assert _get_alert_chat_id() == 12345
    assert ALERT_CHAT_ID_SET.is_set()


def test_overwrite():
    _set_alert_chat_id(111)
    _set_alert_chat_id(222)
    assert _get_alert_chat_id() == 222


def test_set_negative_chat_id():
    _set_alert_chat_id(-1001234567890)
    assert _get_alert_chat_id() == -1001234567890


def test_thread_safety_set():
    """Multiple threads setting chat_id concurrently should not lose updates."""
    results = []
    errors = []

    def setter(cid):
        try:
            _set_alert_chat_id(cid)
            results.append(_get_alert_chat_id())
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=setter, args=(i,)) for i in range(1, 51)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Errors: {errors}"
    final = _get_alert_chat_id()
    assert final in range(1, 51), f"Unexpected final chat_id: {final}"


def test_event_stays_set():
    _set_alert_chat_id(1)
    assert ALERT_CHAT_ID_SET.is_set()
    _set_alert_chat_id(2)
    assert ALERT_CHAT_ID_SET.is_set()  # stays set after overwrite


# ── Failed attempts lock ──


def test_lock_exists():
    assert isinstance(_failed_attempts_lock, threading.Lock)


def test_concurrent_failed_attempts():
    """Simulate concurrent failed_attempts mutations under lock."""

    def worker(ip_base, count):
        for i in range(count):
            with _failed_attempts_lock:
                failed_attempts[f"10.0.0.{ip_base}"].append(datetime.now())

    threads = [threading.Thread(target=worker, args=(i, 100)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with _failed_attempts_lock:
        total = sum(len(v) for v in failed_attempts.values())
    assert total == 1000, f"Expected 1000 entries, got {total}"
