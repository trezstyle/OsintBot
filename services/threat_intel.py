"""Threat intelligence and external lookup services."""
from datetime import datetime
import logging

import requests
import whois

from config import settings

log = logging.getLogger("cyber_volt")


def save_to_log(target, report):
    try:
        with open(settings.paths.threat_intel_log_file, "a") as f:
            f.write(f"\n--- [{datetime.now()}] ---\nTarget: {target}\n{report}\n")
    except Exception:
        pass

def get_vt_report(ip):
    key = settings.api.vt_api_key
    if not key: return "VT: No API key"
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey": key}, timeout=10)
        if r.status_code == 200:
            d = r.json()["data"]["attributes"]
            stats = d["last_analysis_stats"]
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            country = d.get("country", "N/A")
            owner = d.get("as_owner", "N/A")
            emoji = "🔴" if mal > 0 else "🟢"
            return f"{emoji} *VirusTotal*\nMalicious: `{mal}` | Suspicious: `{sus}`\nCountry: `{country}`\nISP: `{owner}`"
        return f"VT: HTTP {r.status_code}"
    except Exception as e:
        return f"VT: {e}"
def get_abuseipdb_report(ip):
    key = settings.api.abuse_api_key
    if not key: return "AbuseIPDB: No API key"
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": key, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}, timeout=10)
        if r.status_code == 200:
            d = r.json()["data"]
            score = d.get("abuseConfidenceScore", 0)
            usage = d.get("usageType", "N/A")
            reports = d.get("totalReports", 0)
            emoji = "🔴" if score > 50 else "🟡" if score > 0 else "🟢"
            return f"{emoji} *AbuseIPDB*\nConfidence: `{score}%`\nUsage: `{usage}`\nReports: `{reports}`"
        return f"AbuseIPDB: HTTP {r.status_code}"
    except Exception as e:
        return f"AbuseIPDB: {e}"
def get_geoip(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            d = r.json()
            return (f"📍 *GeoIP*\nCity: `{d.get('city', 'N/A')}`\n"
                    f"Region: `{d.get('region', 'N/A')}`\n"
                    f"Country: `{d.get('country', 'N/A')}`\n"
                    f"ISP: `{d.get('org', 'N/A')}`")
        return "GeoIP: N/A"
    except:
        return "GeoIP: N/A"
def get_whois(domain):
    try:
        w = whois.whois(domain)
        return (f"🏢 *WHOIS for {domain}*\n"
                f"Registrar: `{w.registrar}`\n"
                f"Created: `{w.creation_date}`\n"
                f"Organization: `{w.org}`")
    except:
        return "Whois: Failed"
def get_subdomains(domain):
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json",
                         headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        if r.status_code == 200:
            subs = sorted(list(set(e["common_name"] for e in r.json() if domain in e["common_name"])))[:10]
            return "\n".join(subs) if subs else "None found"
        return f"crt.sh: HTTP {r.status_code}"
    except Exception as e:
        return f"crt.sh: {e}"
def threat_hunt_ip(ip):
    vt = get_vt_report(ip)
    abuse = get_abuseipdb_report(ip)
    geo = get_geoip(ip)
    report = f"🎯 *Threat Hunt: `{ip}`*\n\n{vt}\n\n{abuse}\n\n{geo}"
    save_to_log(ip, report)
    return report
def threat_hunt_domain(domain):
    whois_data = get_whois(domain)
    subs = get_subdomains(domain)
    report = f"🌐 *Domain Recon: `{domain}`*\n\n{whois_data}\n\n📡 *Subdomains (crt.sh):*\n`{subs}`"
    save_to_log(domain, report)
    return report
def fmt_pwn(n):
    return f"{n:,}" if n is not None else "N/A"
def fmt_data(classes):
    if not classes: return "N/A"
    return ", ".join(classes)
def check_hibp(query):
    try:
        hibp_key = settings.api.hibp_api_key
        if query.lower().startswith("name:"):
            name = query.split(":", 1)[1].strip()
            r = requests.get(f"https://haveibeenpwned.com/api/v3/breach/{name}",
                             headers={"hibp-api-key": hibp_key}, timeout=10)
            if r.status_code == 200:
                b = r.json()
                return (f"🔐 *HIBP: {b.get('Name', name)}*\n"
                        f"Title: `{b.get('Title', 'N/A')}`\n"
                        f"Domain: `{b.get('Domain', 'N/A')}`\n"
                        f"Date: {b.get('BreachDate', 'N/A')}\n"
                        f"👥 Accounts: {fmt_pwn(b.get('PwnCount'))}\n"
                        f"📦 Data: {fmt_data(b.get('DataClasses'))}\n"
                        f"Verified: {'✅ Yes' if b.get('IsVerified') else '❌ No'}\n"
                        f"Spam list: {'⚠ Yes' if b.get('IsSpamList') else 'No'}\n"
                        f"📝 {b.get('Description', '')[:400]}")
            elif r.status_code == 404:
                return f"🔐 *HIBP*\nBreach `{name}` not found."
            return f"⚠ HIBP: HTTP {r.status_code}"

        domain = query.split("@")[-1] if "@" in query else query
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
                         headers={"hibp-api-key": hibp_key}, timeout=10)
        if r.status_code == 200:
            breaches = r.json()
            header = (f"🔐 *HIBP Check: {query}*\n"
                      f"Domain: `{domain}`\n"
                      f"⚠ Free-tier: searching by domain (not email)\n"
                      f"An API key is needed for email lookup\n"
                      f"Use `name:BreachName` for details\n\n")
            if not breaches:
                return header + "🟢 No breaches for this domain."
            result = header + f"🔴 Found {len(breaches)} breaches:\n\n"
            for b in breaches[:5]:
                result += (f"▫️ *{b.get('Name', 'N/A')}*\n"
                           f"  📅 {b.get('BreachDate', 'N/A')} | 👥 {fmt_pwn(b.get('PwnCount'))}\n"
                           f"  📦 {fmt_data(b.get('DataClasses'))}\n"
                           f"  {b.get('Description', '')[:200]}\n\n")
            if len(breaches) > 5:
                result += f"... and {len(breaches) - 5} more breaches"
            return result
        elif r.status_code == 404:
            return f"🔐 *HIBP Check: {query}*\nNo breaches found."
        return f"⚠ HIBP: HTTP {r.status_code}"
    except Exception as e:
        return f"HIBP check failed: {e}"
def mitre_lookup(tid):
    tid = tid.upper()
    if not tid.startswith("T"): tid = "T" + tid
    try:
        r = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", timeout=15)
        if r.status_code == 200:
            for obj in r.json().get("objects", []):
                if obj.get("type") == "attack-pattern" and tid in obj.get("external_references", [{}])[0].get("external_id", ""):
                    name = obj.get("name", "N/A")
                    desc = obj.get("description", "N/A")[:500]
                    tactics = ", ".join(p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])) or "N/A"
                    return f"🧠 *MITRE ATT&CK: {tid}*\n**Name:** `{name}`\n**Tactic:** `{tactics}`\n\n{desc}"
            return f"Technique `{tid}` not found."
        return f"MITRE CTI: HTTP {r.status_code}"
    except Exception as e:
        return f"MITRE lookup failed: {e}"
