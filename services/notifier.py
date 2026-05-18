"""Notification service for background watchers.
Breaks the cyclic dependency watchers <-> ui.handlers."""
import logging
from typing import Optional

import telebot

log = logging.getLogger("cyber_volt.notifier")

_bot: Optional[telebot.TeleBot] = None


def init_bot(bot_instance: telebot.TeleBot) -> None:
    global _bot
    _bot = bot_instance


def send_message(
    chat_id: int,
    text: str,
    parse_mode: Optional[str] = None,
    reply_markup=None,
) -> None:
    if _bot is None:
        log.warning("Bot not initialized, cannot send message")
        return
    try:
        _bot.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup)
    except Exception:
        log.exception(f"Failed to send message to chat {chat_id}")
