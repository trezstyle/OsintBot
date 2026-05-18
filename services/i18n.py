"""Simple i18n message catalog."""
from typing import Literal

Locale = Literal["en", "ru"]

_DEFAULT_LOCALE: Locale = "en"

_catalog: dict[str, dict[Locale, str]] = {
    "unauthorized": {
        "en": "❌ Unauthorized. Contact bot admin to add your ID to ALLOWED_USERS.",
        "ru": "❌ Нет доступа. Свяжитесь с администратором бота.",
    },
    "rate_limit": {
        "en": "⚠️ *Rate limit reached.* This command can be used once every 5 minutes.",
        "ru": "⚠️ *Лимит запросов.* Команду можно использовать раз в 5 минут.",
    },
    "job_usage": {
        "en": "ℹ️ Usage: `/job <id>` — check the status of a running job.",
        "ru": "ℹ️ Использование: `/job <id>` — статус выполняемой задачи.",
    },
    "no_alerts": {
        "en": "📋 *Alert History*\nNo alerts recorded yet.",
        "ru": "📋 *История алертов*\nПока нет записанных алертов.",
    },
    "no_history": {
        "en": "📋 *Command History*\nNo commands recorded yet.",
        "ru": "📋 *История команд*\nПока нет записанных команд.",
    },
}


def set_locale(locale: Locale) -> None:
    global _DEFAULT_LOCALE
    _DEFAULT_LOCALE = locale


def t(key: str, locale: Locale | None = None) -> str:
    return _catalog.get(key, {}).get(locale or _DEFAULT_LOCALE, key)
