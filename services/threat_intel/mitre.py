"""MITRE ATT&CK technique lookup and attack simulation."""
import json
import logging
import os
import time
from pathlib import Path

import requests

from config import settings
from services.threat_intel.reputation import _strip_html

log = logging.getLogger("cyber_volt")

MITRE_CACHE = (
    os.path.join(os.path.dirname(settings.paths.base_dir), "mitre_cache.json")
    if hasattr(settings.paths, 'base_dir')
    else "mitre_cache.json"
)
MITRE_TTL = 86400


def _load_mitre():
    cache = Path(MITRE_CACHE)
    if cache.exists() and time.time() - cache.stat().st_mtime < MITRE_TTL:
        try:
            return json.loads(cache.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            timeout=30,
        )
        if r.status_code == 200:
            data = r.json()
            try:
                cache.write_text(json.dumps(data))
            except OSError as e:
                log.warning("Failed to write MITRE cache: %s", e)
            return data
    except requests.RequestException as e:
        log.warning("Failed to download MITRE CTI: %s", e)
    if cache.exists():
        try:
            return json.loads(cache.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"objects": []}


def mitre_lookup(tid):
    tid = tid.upper()
    if not tid.startswith("T"):
        tid = "T" + tid
    try:
        data = _load_mitre()
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            refs = obj.get("external_references", [])
            if any(tid == ref.get("external_id", "") for ref in refs):
                name = obj.get("name", "N/A")
                desc = _strip_html(obj.get("description", "N/A"))[:500]
                tactics = ", ".join(p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])) or "N/A"
                return f"🧠 *MITRE ATT&CK: {tid}*\n**Name:** `{name}`\n**Tactic:** `{tactics}`\n\n{desc}"
        return f"Technique `{tid}` not found."
    except Exception as e:
        return f"MITRE lookup failed: {e}"


def attack_simulation(technique_id: str) -> str:
    tid = technique_id.upper().strip()
    if not tid.startswith("T"):
        tid = "T" + tid
    try:
        data = _load_mitre()
        technique = None
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            refs = obj.get("external_references", [])
            if any(tid == ref.get("external_id", "") for ref in refs):
                technique = obj
                break
        if not technique:
            return f"🔴 Technique `{tid}` not found in MITRE ATT&CK"
        name = technique.get("name", "N/A")
        desc = _strip_html(technique.get("description", "N/A"))[:500]
        tactics = ", ".join(p.get("phase_name", "") for p in technique.get("kill_chain_phases", [])) or "N/A"
        platforms = ", ".join(technique.get("x_mitre_platforms", [])) or "N/A"
        permissions = ", ".join(technique.get("x_mitre_permissions_required", [])) or "N/A"
        detection = _strip_html(technique.get("x_mitre_detection", ""))[:300] or "Not specified"
        procedures = ""
        examples = technique.get("x_mitre_examples", [])
        if not examples:
            for ref in technique.get("external_references", []):
                if ref.get("source_name") in ("mitre-attack",) and ref.get("external_id") == tid:
                    continue
            data_sources = technique.get("x_mitre_data_sources", [])
            if data_sources:
                procedures = f"Data Sources: {', '.join(data_sources)}"
        else:
            ex = _strip_html(examples[0].get("description", ""))[:300] if isinstance(examples[0], dict) else str(examples[0])[:300]
            if ex:
                procedures = ex
        mitigations = []
        for obj in data.get("objects", []):
            if obj.get("type") != "course-of-action":
                continue
            refs = obj.get("external_references", [])
            if any(tid == ref.get("external_id", "") for ref in refs):
                mitigations.append(obj)
        mitigation_text = "Not specified"
        if mitigations:
            m_name = mitigations[0].get("name", "N/A")
            m_desc = _strip_html(mitigations[0].get("description", ""))[:200] or "N/A"
            mitigation_text = f"`{m_name}` — {m_desc}"
        return (
            f"🧬 *Attack Simulation: {tid}*\n\n"
            f"📌 *Technique:* `{name}`\n"
            f"🎯 *Tactic:* `{tactics}`\n"
            f"💻 *Platforms:* `{platforms}`\n"
            f"🔑 *Permissions:* `{permissions}`\n\n"
            f"📝 *Description:*\n{desc}\n\n"
            f"🔍 *Detection:*\n{detection}\n\n"
            f"🛡 *Mitigation:*\n{mitigation_text}\n\n"
            f"📋 *Procedure Example:*\n{procedures or 'No example available'}"
        )
    except Exception as e:
        return f"Attack simulation failed: {e}"
