"""Async notification service for background watchers."""
import asyncio
import logging
import threading
from typing import Optional

from aiogram import Bot

log = logging.getLogger("cyber_volt.notifier")

_bot: Optional[Bot] = None
_loops: dict[int, asyncio.AbstractEventLoop] = {}


def _get_loop() -> asyncio.AbstractEventLoop:
    """Return or create a dedicated event loop for the current thread."""
    tid = threading.get_ident()
    loop = _loops.get(tid)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _loops[tid] = loop
    return loop


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
        log.exception(f"Failed to send message to chat {chat_id}")


def send_message_sync(
    chat_id: int,
    text: str,
    parse_mode: Optional[str] = None,
    reply_markup=None,
) -> None:
    """Synchronous wrapper for use in background threads."""
    if _bot is None:
        log.warning("Bot not initialized, cannot send message")
        return
    try:
        loop = _get_loop()
        loop.run_until_complete(
            _bot.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup)
        )
    except Exception:
        log.exception(f"Failed to send message to chat {chat_id}")
