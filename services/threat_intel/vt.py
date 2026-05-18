"""VirusTotal API operations."""
from datetime import datetime
import logging
import re
import time

import requests

from config import settings

log = logging.getLogger("cyber_volt")


def get_vt_report(ip):
    key = settings.api.vt_api_key
    if not key:
        return "VT: No API key"
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json()["data"]["attributes"]
            stats = d.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            country = d.get("country", "N/A")
            owner = d.get("as_owner", "N/A")
            emoji = "🔴" if mal > 0 else "🟢"
            return (
                f"{emoji} *VirusTotal*\n"
                f"Malicious: `{mal}` | Suspicious: `{sus}`\n"
                f"Country: `{country}`\nISP: `{owner}`"
            )
        return f"VT: HTTP {r.status_code}"
    except Exception as e:
        return f"VT: {e}"


def check_hash(hash_val: str) -> str:
    hash_val = hash_val.strip().lower()
    if not re.match(r'^[0-9a-f]{32}$', hash_val) and not re.match(r'^[0-9a-f]{40}$', hash_val) and not re.match(r'^[0-9a-f]{64}$', hash_val):
        return "❌ Invalid hash format. Must be MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex)."
    key = settings.api.vt_api_key
    if not key:
        return "⚠ VT: No API key configured. Set VT_API_KEY in .env"
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_val}",
            headers={"x-apikey": key},
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json()["data"]["attributes"]
            stats = d.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            harm = stats.get("harmless", 0)
            file_name = d.get("meaningful_name", d.get("type_description", "N/A"))
            file_type = d.get("type_description", "N/A")
            size = d.get("size", "N/A")
            first_sub = d.get("first_submission_date", None)
            last_sub = d.get("last_submission_date", None)
            if isinstance(size, int):
                size = f"{size:,} bytes"
            if first_sub:
                first_sub = datetime.fromtimestamp(first_sub).strftime("%Y-%m-%d %H:%M:%S")
            if last_sub:
                last_sub = datetime.fromtimestamp(last_sub).strftime("%Y-%m-%d %H:%M:%S")
            results = d.get("last_analysis_results", {})
            detections = []
            for engine, result in results.items():
                if result.get("category") == "malicious":
                    detections.append(engine)
                    if len(detections) >= 5:
                        break
            emoji = "🔴" if mal > 0 else "🟢"
            det_str = ", ".join(detections) if detections else "None"
            return (
                f"{emoji} *VT Hash Check: `{hash_val}`*\n"
                f"File: `{file_name}`\n"
                f"Type: `{file_type}`\n"
                f"Size: `{size}`\n"
                f"Malicious: `{mal}` | Suspicious: `{sus}` | Harmless: `{harm}`\n"
                f"First seen: `{first_sub or 'N/A'}`\n"
                f"Last seen: `{last_sub or 'N/A'}`\n"
                f"Top engines: `{det_str}`"
            )
        elif r.status_code == 404:
            return "🟢 Clean — no VT results"
        return f"VT Hash: HTTP {r.status_code}"
    except Exception as e:
        return f"VT Hash check failed: {e}"


def check_urlscan(url: str) -> str:
    url = url.strip()
    key = settings.api.vt_api_key
    if not key:
        return "⚠ VT: No API key configured"
    try:
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": key},
            data={"url": url},
            timeout=10,
        )
        if r.status_code != 200:
            return f"VT URL submission failed: HTTP {r.status_code}"
        analysis_id = r.json()["data"]["id"]
        time.sleep(3)
        r2 = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": key},
            timeout=10,
        )
        if r2.status_code != 200:
            return f"VT URL analysis failed: HTTP {r2.status_code}"
        data = r2.json()["data"]["attributes"]
        status = data.get("status", "")
        if status in ("queued", "pending"):
            return "⏳ Analysis in progress..."
        stats = data.get("stats", {})
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)
        results = data.get("results", {})
        detections = []
        for engine, result in results.items():
            if result.get("category") == "malicious":
                detections.append(engine)
                if len(detections) >= 5:
                    break
        emoji = "🔴" if mal > 0 else "🟢"
        det_str = ", ".join(detections) if detections else "None"
        return (
            f"{emoji} *VT URL Scan*\n"
            f"URL: `{url}`\n"
            f"Malicious: `{mal}` | Suspicious: `{sus}` | Harmless: `{harm}`\n"
            f"Detecting engines: `{det_str}`"
        )
    except Exception as e:
        return f"VT URL scan failed: {e}"
