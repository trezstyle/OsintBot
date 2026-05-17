"""Polling runtime for the Telegram bot."""
import logging
import time

import telebot

log = logging.getLogger("cyber_volt")


def dispatch_message(bot, msg):
    handled = False
    for handler in bot.next_step_backend.get_handlers(msg.chat.id) or []:
        try:
            log.info(f"Next-step handler: {handler['callback'].__name__}")
            handler["callback"](msg, *handler["args"], **handler["kwargs"])
            handled = True
        except Exception as e:
            log.error(f"next_step handler error: {e}")
    if handled:
        return
    for handler in bot.message_handlers:
        try:
            if bot._test_message_handler(handler, msg):
                handler["function"](msg)
                return
        except Exception as e:
            log.error(f"msg handler error: {e}")
    log.debug(f"Unhandled message: {msg.text[:50] if msg.text else '(no text)'}")


def dispatch_callback(bot, cq):
    log.info(f"CALLBACK: data={cq.data!r}, from={cq.from_user.id}")
    for handler in bot.callback_query_handlers:
        try:
            if bot._test_message_handler(handler, cq):
                log.info(f"Handler matched: {handler['function'].__name__}")
                handler["function"](cq)
                return
        except Exception as e:
            log.error(f"callback handler error: {e}")
    log.warning(f"Unhandled callback: {cq.data!r}")
    try:
        bot.answer_callback_query(cq.id, text="❌ Function temporarily unavailable")
    except Exception:
        pass


def polling_loop(bot):
    offset = 0
    while True:
        try:
            updates = bot.get_updates(
                offset=offset,
                timeout=30,
                allowed_updates=["message", "callback_query", "edited_message"],
            )
            for update in updates:
                offset = update.update_id + 1
                if update.message:
                    dispatch_message(bot, update.message)
                if update.callback_query:
                    dispatch_callback(bot, update.callback_query)
        except telebot.apihelper.ApiTelegramException as e:
            if "409" in str(e) or "429" in str(e):
                log.warning(f"{e} — retrying in 30s")
                time.sleep(30)
            else:
                log.error(f"API error: {e}")
                time.sleep(10)
        except Exception as e:
            log.error(f"Polling error: {type(e).__name__}: {e}")
            time.sleep(10)
