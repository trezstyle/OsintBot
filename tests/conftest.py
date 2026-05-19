"""Pytest configuration: env vars, test DB, shared fixtures."""
import os
import tempfile
from pathlib import Path

os.environ.setdefault("TELEGRAM_TOKEN", "0000000000:test-token-for-pytest")
os.environ.setdefault("ALLOWED_USERS", "12345")
os.environ.setdefault("FIM_ALLOWED_PREFIXES", "/etc,/tmp")

import services.database as _db

_test_db_path = Path(tempfile.mktemp(suffix=".db"))
_db._DB_PATH = _test_db_path
_db.init_db()


def _clean_tables():
    db = _db.get_db()
    for table in ("fim", "alerts", "history", "users", "settings", "tasks"):
        db.execute(f"DELETE FROM {table}")
    db.commit()


import pytest


@pytest.fixture(autouse=True)
def clean_db():
    _clean_tables()
    yield
    _clean_tables()
