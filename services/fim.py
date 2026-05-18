"""File Integrity Monitoring service (SQLite-backed)."""
import hashlib
import logging
import os
import stat
from datetime import datetime

from config import settings
from security import validate_fim_path
from services.database import fim_upsert, fim_load

log = logging.getLogger("cyber_volt")


def fim_allowed_prefixes():
    return [str(p) for p in settings.paths.fim_allowed_prefixes]


def _hash_file_stream(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _hash_directory(path: str) -> str:
    entries = []
    for root, dirs, files in os.walk(path):
        for f in sorted(files):
            fp = os.path.join(root, f)
            try:
                st = os.stat(fp)
                entries.append(f"{fp}|{st.st_mtime}|{st.st_size}")
            except OSError:
                entries.append(fp)
        for d in sorted(dirs):
            dp = os.path.join(root, d)
            try:
                st = os.stat(dp)
                entries.append(f"{dp}|{st.st_mtime}")
            except OSError:
                entries.append(dp)
    return hashlib.sha256("\n".join(entries).encode()).hexdigest()


def fim_add(path):
    path = validate_fim_path(path)
    if not path:
        allowed = ", ".join(fim_allowed_prefixes())
        return f"❌ Invalid or unauthorized path. Allowed prefixes: `{allowed}`"
    if not os.path.exists(path):
        return f"❌ File not found: {path}"
    try:
        if os.path.isfile(path) and not stat.S_ISREG(os.stat(path).st_mode):
            return f"❌ Not a regular file (device/special): `{path}`"
    except OSError as e:
        return f"❌ Cannot stat: {e}"

    if os.path.isdir(path):
        try:
            h = _hash_directory(path)
        except Exception as e:
            return f"❌ Error reading directory: {e}"
        fim_upsert(path, h, str(datetime.now()), "directory")
        return f"✅ *FIM Added (dir)*\n`{path}`\nSHA256: `{h[:16]}...`"

    try:
        h = _hash_file_stream(path)
    except Exception as e:
        return f"❌ Error reading file: {e}"
    fim_upsert(path, h, str(datetime.now()), "file")
    return f"✅ *FIM Added*\n`{path}`\nSHA256: `{h[:16]}...`"


def fim_check():
    db = fim_load()
    if not db:
        return "📋 *FIM Database*\nNo files monitored.\nUse `/fim add <path>`"
    out = []
    for path, data in db.items():
        if not os.path.exists(path):
            out.append(f"⚠ DELETED: `{path}`")
            continue
        if data.get("type") == "directory":
            try:
                h = _hash_directory(path)
                out.append(f"{'✅' if h == data['hash'] else '❌ CHANGED'}: `{path}` (dir)")
            except Exception as e:
                out.append(f"⚠ ERROR: `{path}` — {e}")
        else:
            try:
                h = _hash_file_stream(path)
                out.append(f"{'✅' if h == data['hash'] else '❌ CHANGED'}: `{path}`")
            except Exception as e:
                out.append(f"⚠ ERROR: `{path}` — {e}")
    return "📋 *FIM Check*\n" + "\n".join(out)
