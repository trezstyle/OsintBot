"""Async notification service for background watchers."""
import asyncio
import logging
from typing import Optional

from aiogram import Bot

log = logging.getLogger("cyber_volt.notifier")

_bot: Optional[Bot] = None

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
        asyncio.run(_bot.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup))
    except Exception:
        log.exception(f"Failed to send message to chat {chat_id}")
