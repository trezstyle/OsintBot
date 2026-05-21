"""Simple in-memory rate limiter for Telegram handlers."""
import asyncio
import logging
import threading
import time
from collections import defaultdict
from functools import wraps

from services.i18n import t
from services.notifier import send_message_sync

log = logging.getLogger("cyber_volt.rate_limit")


class RateLimiter:
    """Sliding-window rate limiter keyed by user/chat ID.

    Thread-safe. Uses in-memory storage only.
    """

    def __init__(self, max_calls: int = 10, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._buckets: dict[int, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, user_id: int) -> bool:
        """Check and record a call. Returns True if within limit."""
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._buckets[user_id]
            bucket[:] = [t for t in bucket if t > cutoff]
            if len(bucket) >= self.max_calls:
                return False
            bucket.append(now)
            return True

    def remaining(self, user_id: int) -> int:
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._buckets[user_id]
            bucket[:] = [t for t in bucket if t > cutoff]
            return max(0, self.max_calls - len(bucket))

    def reset(self, user_id: int) -> None:
        with self._lock:
            self._buckets.pop(user_id, None)

    def reset_all(self) -> None:
        with self._lock:
            self._buckets.clear()


# Default limits
DEFAULT_MAX_CALLS = 6
DEFAULT_WINDOW = 60

# Heavy commands (scan, report, etc.) get stricter limits
HEAVY_MAX_CALLS = 2
HEAVY_WINDOW = 300  # 5 minutes

# Shared instances
_heavy = RateLimiter(HEAVY_MAX_CALLS, HEAVY_WINDOW)
_commands: dict[str, RateLimiter] = {}


def _limiter_for(cmd: str) -> RateLimiter:
    if cmd not in _commands:
        _commands[cmd] = RateLimiter(DEFAULT_MAX_CALLS, DEFAULT_WINDOW)
    return _commands[cmd]


def _get_user_id(obj) -> int | None:
    """Extract user_id from a Message or CallbackQuery."""
    user = getattr(obj, "from_user", None)
    if user:
        return user.id
    return None


def _get_chat_id(obj) -> int | None:
    """Extract chat_id from a Message or CallbackQuery."""
    chat = getattr(obj, "chat", None)
    if chat:
        return chat.id
    msg = getattr(obj, "message", None)
    if msg:
        return getattr(msg, "chat_id", None)
    return None


def rate_limit(cmd: str = "", heavy: bool = False):
    """Decorator for Telegram handlers that rate-limits by user_id.

    Args:
        cmd: Command name for per-command limit. If empty, uses function name.
        heavy: If True, use stricter heavy limits (2 calls per 5 min).

    Usage:
        @rate_limit("scan", heavy=True)
        async def cmd_scan(m): ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(obj, *args, **kwargs):
            uid = _get_user_id(obj)
            if uid is None:
                return await func(obj, *args, **kwargs)

            limiter = _heavy if heavy else _limiter_for(cmd or func.__name__)
            if not limiter.is_allowed(uid):
                cid = _get_chat_id(obj)
                if cid:
                    send_message_sync(
                        cid,
                        t("rate_limit"),
                        parse_mode="Markdown",
                    )
                return
            return await func(obj, *args, **kwargs)
        return wrapper
    return decorator
