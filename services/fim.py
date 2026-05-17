"""File Integrity Monitoring service."""
import hashlib
import json
import os
from datetime import datetime

from config import settings
from security import validate_fim_path


def fim_allowed_prefixes():
    return [str(p) for p in settings.paths.fim_allowed_prefixes]

def load_fim():
    if os.path.exists(settings.paths.fim_file):
        try: return json.load(open(settings.paths.fim_file))
        except: return {}
    return {}
def save_fim(db):
    json.dump(db, open(settings.paths.fim_file, "w"), indent=2)
def fim_add(path):
    path = validate_fim_path(path)
    if not path:
        allowed = ", ".join(fim_allowed_prefixes())
        return f"❌ Invalid or unauthorized path. Allowed prefixes: `{allowed}`"
    if not os.path.exists(path): return f"❌ File not found: {path}"
    db = load_fim()
    if os.path.isdir(path):
        entries = []
        try:
            for root, dirs, files in os.walk(path):
                for f in sorted(files):
                    fp = os.path.join(root, f)
                    try:
                        st = os.stat(fp)
                        entries.append(f"{fp}|{st.st_mtime}|{st.st_size}")
                    except: entries.append(fp)
                for d in sorted(dirs):
                    dp = os.path.join(root, d)
                    try:
                        st = os.stat(dp)
                        entries.append(f"{dp}|{st.st_mtime}")
                    except: entries.append(dp)
        except Exception as e:
            return f"❌ Error reading directory: {e}"
        h = hashlib.sha256("\n".join(entries).encode()).hexdigest()
        db[path] = {"hash": h, "added": str(datetime.now()), "type": "directory"}
        save_fim(db)
        return f"✅ *FIM Added (dir)*\n`{path}`\n{len(entries)} entries monitored\nSHA256: `{h[:16]}...`"
    h = hashlib.sha256(open(path, "rb").read()).hexdigest()
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
            # Hash directory listing (names + mtimes)
            entries = []
            try:
                for root, dirs, files in os.walk(path):
                    for f in sorted(files):
                        fp = os.path.join(root, f)
                        try:
                            st = os.stat(fp)
                            entries.append(f"{fp}|{st.st_mtime}|{st.st_size}")
                        except: entries.append(fp)
                    for d in sorted(dirs):
                        dp = os.path.join(root, d)
                        try:
                            st = os.stat(dp)
                            entries.append(f"{dp}|{st.st_mtime}")
                        except: entries.append(dp)
            except Exception as e:
                out.append(f"⚠ ERROR: `{path}` — {e}")
                continue
            h = hashlib.sha256("\n".join(entries).encode()).hexdigest()
            out.append(f"{'✅' if h == data['hash'] else '❌ CHANGED'}: `{path}` (dir)")
        else:
            # Regular file
            try:
                h = hashlib.sha256(open(path, "rb").read()).hexdigest()
                out.append(f"{'✅' if h == data['hash'] else '❌ CHANGED'}: `{path}`")
            except Exception as e:
                out.append(f"⚠ ERROR: `{path}` — {e}")
    return "📋 *FIM Check*\n" + "\n".join(out)
