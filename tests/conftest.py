"""Pytest configuration: sets required env vars before any module import."""
import os

os.environ.setdefault("TELEGRAM_TOKEN", "0000000000:test-token-for-pytest")
os.environ.setdefault("ALLOWED_USERS", "12345")
os.environ.setdefault("FIM_ALLOWED_PREFIXES", "/etc,/tmp")
