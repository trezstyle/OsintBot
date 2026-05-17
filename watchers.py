"""Background alert watchers."""
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import os
import re
import threading
import time

from config import settings
from services.system import recent_failed_logins
from services.threat_intel import get_abuseipdb_report, get_geoip, get_vt_report

log = logging.getLogger("cyber_volt")

failed_attempts = defaultdict(list)

def alert_watcher():
    """Monitor auth.log for brute force attacks."""
    from ui import handlers
    last_size = 0
    seen_lines = set()
    while True:
        time.sleep(30)
        if not handlers.ALERT_CHAT_ID: continue
        try:
            path = str(settings.paths.auth_log_file)
            if not os.path.exists(path): continue
            size = os.path.getsize(path)
            if size == last_size and seen_lines: continue
            if size < last_size: seen_lines.clear()
            last_size = size
            out = recent_failed_logins(20)
            now = datetime.now()
            for line in out.strip().split("\n"):
                if not line: continue
                lk = line[:80]
                if lk in seen_lines: continue
                seen_lines.add(lk)
                if len(seen_lines) > 500: seen_lines.clear()
                m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    ip = m.group(1)
                    t = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                    if t:
                        try:
                            if (now - datetime.fromisoformat(t.group(1))) > timedelta(minutes=10): continue
                        except: pass
                    failed_attempts[ip].append(now)
            for ip, times in list(failed_attempts.items()):
                times[:] = [t for t in times if now - t < timedelta(minutes=5)]
                if len(times) >= 5:
                    try:
                        handlers.bot.send_message(handlers.ALERT_CHAT_ID,
                            f"🚨 *Brute Force Alert!*\nIP: `{ip}`\nAttempts: {len(times)} in 5min",
                            parse_mode="Markdown")
                    except: pass
                    failed_attempts[ip] = []
        except: pass

# Suricata alert buffer — last N alerts
suricata_alerts = []
suricata_lock = threading.Lock()

def suricata_watcher():
    """Monitor Suricata fast.log for IDS alerts."""
    from ui import handlers
    path = str(settings.paths.suricata_fast_log_file)
    seen = set()
    while True:
        time.sleep(15)
        try:
            if not os.path.exists(path):
                continue
            with open(path, "r", errors="ignore") as f:
                out = "\n".join(f.read().splitlines()[-20:])
            now = datetime.now()
            for line in out.strip().split("\n"):
                if not line: continue
                sig = line.strip()
                if sig in seen: continue
                seen.add(sig)
                if len(seen) > 1000: seen.clear()

                with suricata_lock:
                    suricata_alerts.append({"time": now, "line": sig})
                    if len(suricata_alerts) > 50:
                        suricata_alerts.pop(0)

                # Extract IPs from alert line
                ips = re.findall(r"\d+\.\d+\.\d+\.\d+", sig)

                # Send alert if urgent signatures
                urgent_keywords = ["ET MALWARE", "ET TROJAN", "ET EXPLOIT", "ET CNC",
                                   "MALWARE", "TROJAN", "CVE-", "SHELLCODE",
                                   "ET CNC", "DNS TUNNEL", "MYSQL", "RCE"]
                if any(k.lower() in sig.lower() for k in urgent_keywords):
                    if handlers.ALERT_CHAT_ID:
                        try:
                            msg = f"🚨 *Suricata IDS Alert!*\n```\n{sig[:200]}\n```"
                            if ips:
                                msg += f"\nSource IP: `{ips[0]}`"
                            if len(ips) > 1:
                                msg += f" → Target: `{ips[1]}`"
                            handlers.bot.send_message(handlers.ALERT_CHAT_ID, msg, parse_mode="Markdown")
                        except:
                            pass

                    # Auto-run threat hunt on malicious IP
                    if ips:
                        try:
                            vt = get_vt_report(ips[0])
                            abuse = get_abuseipdb_report(ips[0])
                            geo = get_geoip(ips[0])
                            report = f"🎯 *Auto Threat Hunt: `{ips[0]}`*\n\n{vt}\n\n{abuse}\n\n{geo}"
                            handlers.bot.send_message(handlers.ALERT_CHAT_ID, report, parse_mode="Markdown")
                        except:
                            pass
        except FileNotFoundError:
            pass
        except Exception as e:
            log.debug(f"suricata_watcher: {e}")
