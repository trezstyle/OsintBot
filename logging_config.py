"""Production logging helpers for Cyber-Volt SOC Bot."""
from __future__ import annotations

import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


class JsonFormatter(logging.Formatter):
    """Small JSON formatter for structured container logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def configure_logging(
    log_file: str | Path | None = None,
    logger_name: str = "cyber_volt",
) -> logging.Logger:
    """Configure text or JSON logging with optional file rotation."""
    logger = logging.getLogger(logger_name)

    if not _truthy(os.getenv("LOG_ENABLED", "true")):
        logger.disabled = True
        return logger

    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False

    log_format = os.getenv("LOG_FORMAT", "text").strip().lower()
    if log_format == "json":
        formatter: logging.Formatter = JsonFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    target = Path(log_file or os.getenv("BOT_LOG_FILE", "bot.log"))
    if target:
        target.parent.mkdir(parents=True, exist_ok=True)
        max_bytes = int(os.getenv("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
        backup_count = int(os.getenv("LOG_BACKUP_COUNT", "3"))
        file_handler = RotatingFileHandler(
            target,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
