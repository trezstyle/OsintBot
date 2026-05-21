import asyncio
import logging
import threading
from typing import Optional

from aiogram import Bot

log = logging.getLogger("cyber_volt.notifier")

_bot: Optional[Bot] = None
_LOOPS_MAX = 50
_loops: dict[int, asyncio.AbstractEventLoop] = {}
_loops_lock = threading.Lock()


def _get_loop() -> asyncio.AbstractEventLoop:
    tid = threading.get_ident()
    with _loops_lock:
        loop = _loops.get(tid)
        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            _loops[tid] = loop
        return loop


def _cleanup_stale_loops() -> None:
    with _loops_lock:
        # Remove closed loops and loops from dead threads
        alive_tids = {t.ident for t in threading.enumerate() if t.ident is not None}
        dead = [tid for tid, loop in _loops.items()
                if loop.is_closed() or tid not in alive_tids]
        for tid in dead:
            loop = _loops.pop(tid)
            if not loop.is_closed():
                loop.close()


def init_bot(bot_instance: Bot) -> None:
    global _bot
    _bot = bot_instance


async def send_message(
    chat_id: int,
    text: str,
    parse_mode: Optional[str] = None,
    reply_markup=None,
) -> None:
    if _bot is None:
        log.warning("Bot not initialized, cannot send message")
        return
    try:
        await _bot.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup)
    except Exception:
        log.exception("Failed to send message to chat %d", chat_id)


def send_message_sync(
    chat_id: int,
    text: str,
    parse_mode: Optional[str] = None,
    reply_markup=None,
) -> None:
    if _bot is None:
        log.warning("Bot not initialized, cannot send message")
        return
    try:
        _cleanup_stale_loops()
        loop = _get_loop()
        loop.run_until_complete(
            _bot.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup)
        )
    except Exception:
        log.exception("Failed to send message to chat %d", chat_id)
