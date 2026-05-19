"""Tests for FIM service."""
import hashlib
import os
import tempfile

import pytest

from services.fim import _hash_file_stream, _hash_directory
from services.database import fim_load, fim_save_all


class TestHashFileStream:
    def test_small_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello world")
            tmp = f.name
        try:
            expected = hashlib.sha256(b"hello world").hexdigest()
            assert _hash_file_stream(tmp) == expected
        finally:
            os.unlink(tmp)

    def test_large_file(self):
        data = b"x" * 200000
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            tmp = f.name
        try:
            expected = hashlib.sha256(data).hexdigest()
            assert _hash_file_stream(tmp) == expected
        finally:
            os.unlink(tmp)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp = f.name
        try:
            expected = hashlib.sha256(b"").hexdigest()
            assert _hash_file_stream(tmp) == expected
        finally:
            os.unlink(tmp)

    def test_binary_file(self):
        data = bytes(range(256))
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            tmp = f.name
        try:
            expected = hashlib.sha256(data).hexdigest()
            assert _hash_file_stream(tmp) == expected
        finally:
            os.unlink(tmp)


class TestLoadSaveFim:
    def test_save_and_load_roundtrip(self):
        db = {"/etc/passwd": {"hash": "abc123", "added": "now", "type": "file"}}
        try:
            fim_save_all(db)
            loaded = fim_load()
            assert loaded == db
        finally:
            fim_save_all({})
