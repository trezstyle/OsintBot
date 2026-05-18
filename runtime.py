"""Polling runtime for the Telegram bot (aiogram 3.x)."""
import logging

from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage

log = logging.getLogger("cyber_volt")

storage = MemoryStorage()


def create_dispatcher(bot: Bot) -> Dispatcher:
    dp = Dispatcher(storage=storage)
    from ui.handlers import router
    dp.include_router(router)
    return dp
