"""File Integrity Monitoring service."""
import hashlib
import json
import logging
import os
import stat
import tempfile
from datetime import datetime

from config import settings
from security import validate_fim_path

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


def load_fim():
    if os.path.exists(settings.paths.fim_file):
        try:
            with open(settings.paths.fim_file) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            log.error(f"Corrupt FIM database: {e}")
            return {}
    return {}


def save_fim(db):
    tmp = tempfile.NamedTemporaryFile(
        mode="w", dir=os.path.dirname(settings.paths.fim_file),
        delete=False, suffix=".tmp"
    )
    try:
        json.dump(db, tmp, indent=2)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp.close()
        os.replace(tmp.name, settings.paths.fim_file)
    except Exception:
        os.unlink(tmp.name)
        raise


def fim_add(path):
    path = validate_fim_path(path)
    if not path:
        allowed = ", ".join(fim_allowed_prefixes())
        return f"❌ Invalid or unauthorized path. Allowed prefixes: `{allowed}`"
    if not os.path.exists(path): return f"❌ File not found: {path}"
    try:
        if os.path.isfile(path) and not stat.S_ISREG(os.stat(path).st_mode):
            return f"❌ Not a regular file (device/special): `{path}`"
    except OSError as e:
        return f"❌ Cannot stat: {e}"
    db = load_fim()
    if os.path.isdir(path):
        try:
            h = _hash_directory(path)
        except Exception as e:
            return f"❌ Error reading directory: {e}"
        db[path] = {"hash": h, "added": str(datetime.now()), "type": "directory"}
        save_fim(db)
        return f"✅ *FIM Added (dir)*\n`{path}`\nSHA256: `{h[:16]}...`"
    try:
        h = _hash_file_stream(path)
    except Exception as e:
        return f"❌ Error reading file: {e}"
    db[path] = {"hash": h, "added": str(datetime.now()), "type": "file"}
    save_fim(db)
    return f"✅ *FIM Added*\n`{path}`\nSHA256: `{h[:16]}...`"


def fim_check():
    db = load_fim()
    if not db: return "📋 *FIM Database*\nNo files monitored.\nUse `/fim add <path>`"
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
