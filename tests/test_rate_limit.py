"""Tests for the rate limiter."""
import threading
import time

import pytest

from services.rate_limit import RateLimiter


class TestRateLimiter:
    def test_allows_within_limit(self):
        rl = RateLimiter(max_calls=3, window_seconds=60)
        assert rl.is_allowed(1)
        assert rl.is_allowed(1)
        assert rl.is_allowed(1)
        assert not rl.is_allowed(1)

    def test_different_users_independent(self):
        rl = RateLimiter(max_calls=2, window_seconds=60)
        assert rl.is_allowed(1)
        assert rl.is_allowed(1)
        assert not rl.is_allowed(1)
        assert rl.is_allowed(2)  # different user

    def test_window_expires(self):
        rl = RateLimiter(max_calls=1, window_seconds=0.1)
        assert rl.is_allowed(1)
        assert not rl.is_allowed(1)
        time.sleep(0.15)
        assert rl.is_allowed(1)  # window has expired

    def test_remaining(self):
        rl = RateLimiter(max_calls=5, window_seconds=60)
        assert rl.remaining(1) == 5
        rl.is_allowed(1)
        assert rl.remaining(1) == 4
        for _ in range(4):
            rl.is_allowed(1)
        assert rl.remaining(1) == 0

    def test_reset(self):
        rl = RateLimiter(max_calls=2, window_seconds=60)
        assert rl.is_allowed(1)
        assert rl.is_allowed(1)
        assert not rl.is_allowed(1)
        rl.reset(1)
        assert rl.is_allowed(1)  # allowed after reset

    def test_reset_all(self):
        rl = RateLimiter(max_calls=1, window_seconds=60)
        rl.is_allowed(1)
        rl.is_allowed(2)
        assert not rl.is_allowed(1)
        rl.reset_all()
        assert rl.is_allowed(1)
        assert rl.is_allowed(2)

    def test_negative_user_id(self):
        rl = RateLimiter(max_calls=2, window_seconds=60)
        assert rl.is_allowed(-100)
        assert rl.is_allowed(-100)
        assert not rl.is_allowed(-100)

    def test_thread_safety(self):
        rl = RateLimiter(max_calls=100, window_seconds=60)
        allowed = 0
        lock = threading.Lock()

        def worker():
            nonlocal allowed
            if rl.is_allowed(42):
                with lock:
                    allowed += 1

        threads = [threading.Thread(target=worker) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert allowed == 100, f"Expected 100 allowed, got {allowed}"

    def test_exact_boundary(self):
        rl = RateLimiter(max_calls=0, window_seconds=60)
        assert not rl.is_allowed(1)
