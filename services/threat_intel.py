"""Threat intelligence and external lookup services."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import time
from urllib.parse import quote_plus
from pathlib import Path

import requests
import whois

try:
    import dns.resolver
except ImportError:
    dns = None

from config import settings

log = logging.getLogger("cyber_volt")

# ── Optional caching for external API calls ──
try:
    import requests_cache
    requests_cache.install_cache(
        "api_cache", backend="sqlite", expire_after=300,
        allowable_methods=("GET", "HEAD"),
    )
except ImportError:
    pass


def _strip_html(value: str) -> str:
    value = re.sub(r"<script\b[^>]*>.*?</script>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<style\b[^>]*>.*?</style>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"&quot;|&#34;", '"', value)
    value = re.sub(r"&amp;", "&", value)
    value = re.sub(r"&nbsp;|&#160;", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def _is_ipv4(ip: str) -> bool:
    parts = ip.strip().split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def save_to_log(target, report):
    try:
        with open(settings.paths.threat_intel_log_file, "a") as f:
            f.write(f"\n--- [{datetime.now()}] ---\nTarget: {target}\n{report}\n")
    except Exception as e:
        log.error(f"Failed to write threat intel log: {e}")


def get_vt_report(ip):
    key = settings.api.vt_api_key
    if not key: return "VT: No API key"
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey": key}, timeout=10)
        if r.status_code == 200:
            d = r.json()["data"]["attributes"]
            stats = d.get("last_analysis_stats", {})
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
    with ThreadPoolExecutor(max_workers=3) as pool:
        vt_fut = pool.submit(get_vt_report, ip)
        abuse_fut = pool.submit(get_abuseipdb_report, ip)
        geo_fut = pool.submit(get_geoip, ip)
        vt = vt_fut.result()
        abuse = abuse_fut.result()
        geo = geo_fut.result()
    report = f"🎯 *Threat Hunt: `{ip}`*\n\n{vt}\n\n{abuse}\n\n{geo}"
    save_to_log(ip, report)
    return report


def threat_hunt_domain(domain):
    with ThreadPoolExecutor(max_workers=2) as pool:
        whois_fut = pool.submit(get_whois, domain)
        subs_fut = pool.submit(get_subdomains, domain)
        whois_data = whois_fut.result()
        subs = subs_fut.result()
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
        if not hibp_key:
            return "⚠ HIBP: No API key configured. Set HIBP_API_KEY in .env"

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
                        f"📝 {_strip_html(b.get('Description', ''))[:400]}")
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
                           f"  {_strip_html(b.get('Description', ''))[:200]}\n\n")
            if len(breaches) > 5:
                result += f"... and {len(breaches) - 5} more breaches"
            return result
        elif r.status_code == 404:
            return f"🔐 *HIBP Check: {query}*\nNo breaches found."
        return f"⚠ HIBP: HTTP {r.status_code}"
    except Exception as e:
        return f"HIBP check failed: {e}"


# ── MITRE CTI cache ──
MITRE_CACHE = os.path.join(os.path.dirname(settings.paths.base_dir), "mitre_cache.json") if hasattr(settings.paths, 'base_dir') else "mitre_cache.json"
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
                log.warning(f"Failed to write MITRE cache: {e}")
            return data
    except requests.RequestException as e:
        log.warning(f"Failed to download MITRE CTI: {e}")
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


def check_ssl(domain: str) -> str:
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()

        def cert_name(items):
            for group in items or []:
                for key, value in group:
                    if key == "commonName":
                        return value
            return "N/A"

        subject = cert_name(cert.get("subject"))
        issuer = cert_name(cert.get("issuer"))
        valid_from = cert.get("notBefore", "N/A")
        valid_to = cert.get("notAfter", "N/A")
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        expiry = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry - datetime.utcnow()).days
        status = "Valid" if days_remaining >= 0 else "Expired"
        emoji = "🟢" if days_remaining > 14 else "🟡" if days_remaining >= 0 else "🔴"

        return (
            f"{emoji} *SSL Check: `{domain}`*\n"
            f"Status: `{status}`\n"
            f"Days remaining: `{days_remaining}`\n"
            f"Valid from: `{valid_from}`\n"
            f"Valid to: `{valid_to}`\n"
            f"Issuer: `{issuer}`\n"
            f"Subject: `{subject}`\n"
            f"SANs: `{len(sans)}`"
        )
    except (ConnectionError, socket.timeout, ssl.SSLError, OSError) as e:
        log.error(f"check_ssl({domain}) error: {e}")
        return f"🔴 *SSL Check: `{domain}`*\nFailed: `{e}`"
    except Exception as e:
        log.error(f"check_ssl({domain}) error: {e}")
        return f"SSL check failed: {e}"


def check_http_headers(url: str) -> str:
    target = url.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        r = requests.get(f"https://{target}", timeout=10, allow_redirects=True)
        headers = r.headers

        hsts = headers.get("Strict-Transport-Security", "")
        hsts_match = re.search(r"max-age=(\d+)", hsts.lower())
        hsts_ok = bool(hsts_match and int(hsts_match.group(1)) > 0)
        csp_ok = bool(headers.get("Content-Security-Policy"))
        xfo = headers.get("X-Frame-Options", "").upper()
        xfo_ok = xfo in ("DENY", "SAMEORIGIN")
        xcto_ok = headers.get("X-Content-Type-Options", "").lower() == "nosniff"
        ref_ok = bool(headers.get("Referrer-Policy"))
        perm_ok = bool(headers.get("Permissions-Policy"))
        xss_present = bool(headers.get("X-XSS-Protection"))

        checks = [
            ("Strict-Transport-Security", hsts_ok, "max-age present"),
            ("Content-Security-Policy", csp_ok, "present"),
            ("X-Frame-Options", xfo_ok, "DENY or SAMEORIGIN"),
            ("X-Content-Type-Options", xcto_ok, "nosniff"),
            ("Referrer-Policy", ref_ok, "present"),
            ("Permissions-Policy", perm_ok, "present"),
        ]
        passed = sum(1 for _, ok, _ in checks if ok) + (0 if xss_present else 1)
        grade = "A" if passed >= 6 else "B" if passed == 5 else "C" if passed >= 3 else "F"
        grade_emoji = "🟢" if grade == "A" else "🟡" if grade in ("B", "C") else "🔴"

        lines = [
            f"{grade_emoji} *HTTP Security Headers: `{target}`*",
            f"Final URL: `{r.url}`",
            f"Status: `{r.status_code}`",
            f"Grade: `{grade}` ({passed}/7)\n",
        ]
        for name, ok, expected in checks:
            lines.append(f"{'✅' if ok else '❌'} `{name}` — {expected}")
        lines.append(f"{'⚠️' if xss_present else '🟢'} `X-XSS-Protection` — obsolete{'; present' if xss_present else '; not present'}")
        return "\n".join(lines)
    except requests.RequestException as e:
        log.error(f"check_http_headers({target}) error: {e}")
        return f"🔴 *HTTP Security Headers: `{target}`*\nFailed: `{e}`"
    except Exception as e:
        log.error(f"check_http_headers({target}) error: {e}")
        return f"HTTP header check failed: {e}"


def check_blacklist(ip: str) -> str:
    dnsbls = [
        ("zen.spamhaus.org", "Spamhaus ZEN"),
        ("b.barracudacentral.org", "Barracuda"),
        ("bl.spamcop.net", "SpamCop"),
        ("dnsbl.sorbs.net", "SORBS"),
        ("cbl.abuseat.org", "AbuseAT CBL"),
    ]
    ip = ip.strip()
    try:
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return f"❌ Invalid IP address: `{ip}`"

        reversed_ip = ".".join(reversed(parts))
        lines = [f"⚫ *DNSBL Blacklist Check: `{ip}`*"]
        for zone, name in dnsbls:
            query = f"{reversed_ip}.{zone}"
            try:
                socket.gethostbyname(query)
                lines.append(f"✅ *{name}*: Listed")
            except socket.gaierror:
                lines.append(f"🟢 *{name}*: Clean")
            except Exception as e:
                log.error(f"check_blacklist({ip}) {name} error: {e}")
                lines.append(f"⚠ *{name}*: Error `{e}`")
        return "\n".join(lines)
    except Exception as e:
        log.error(f"check_blacklist({ip}) error: {e}")
        return f"Blacklist check failed: {e}"


def _dig_txt(name):
    if dns is not None:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=10)
            return " ".join(str(r) for r in answers)
        except Exception as e:
            log.debug(f"dns TXT lookup failed for {name}: {e}")
            return ""
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", name],
            capture_output=True, text=True, timeout=10, check=False
        )
        return " ".join(line.strip().strip('"') for line in result.stdout.splitlines() if line.strip())
    except Exception as e:
        log.error(f"_dig_txt({name}) error: {e}")
        return ""


def _has_mx(domain):
    if dns is not None:
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=10)
            return True, str(answers[0].exchange)
        except Exception as e:
            log.debug(f"dns MX lookup failed for {domain}: {e}")
            return False, "not found"
    try:
        result = subprocess.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=10, check=False
        )
        if result.stdout.strip():
            return True, result.stdout.strip().splitlines()[0]
    except Exception as e:
        log.error(f"MX dig failed for {domain}: {e}")
    try:
        socket.getaddrinfo(domain, 25)
        return True, "domain resolves"
    except Exception as e:
        log.error(f"MX fallback failed for {domain}: {e}")
        return False, "not found"


def check_email(email: str) -> str:
    email = email.strip()
    try:
        if not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email):
            return f"❌ Invalid email address: `{email}`"

        domain = email.rsplit("@", 1)[1].lower()
        mx_ok, mx_info = _has_mx(domain)
        gravatar_hash = hashlib.md5(email.lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/{gravatar_hash}.json?d=404"
        gravatar = requests.get(gravatar_url, timeout=10)
        gravatar_ok = gravatar.status_code == 200

        spf_txt = _dig_txt(domain)
        spf_alt = _dig_txt(f"_spf.{domain}")
        spf_ok = "v=spf1" in f"{spf_txt} {spf_alt}".lower()
        dmarc_txt = _dig_txt(f"_dmarc.{domain}")
        dmarc_ok = "v=dmarc1" in dmarc_txt.lower()
        hibp = check_hibp(email)

        lines = [
            f"📧 *Email OSINT: `{email}`*",
            f"Domain: `{domain}`",
            f"{'✅' if mx_ok else '❌'} MX: `{mx_info}`",
            f"{'✅' if gravatar_ok else '🟢'} Gravatar: {'Profile found' if gravatar_ok else 'No public profile'}",
            f"{'✅' if spf_ok else '❌'} SPF: {'Found' if spf_ok else 'Not found'}",
            f"{'✅' if dmarc_ok else '❌'} DMARC: {'Found' if dmarc_ok else 'Not found'}",
            "",
            hibp,
        ]
        return "\n".join(lines)
    except requests.RequestException as e:
        log.error(f"check_email({email}) error: {e}")
        return f"Email OSINT failed: {e}"
    except Exception as e:
        log.error(f"check_email({email}) error: {e}")
        return f"Email OSINT failed: {e}"


def check_tor(ip: str) -> str:
    ip = ip.strip()
    try:
        if not _is_ipv4(ip):
            return f"❌ Invalid IP address: `{ip}`"

        listed_ports = []
        reversed_ip = ".".join(reversed(ip.split(".")))
        for port in [80, 443]:
            query = f"{reversed_ip}.{port}.ip-port.exitlist.torproject.org"
            try:
                socket.gethostbyname(query)
                listed_ports.append(str(port))
            except socket.gaierror:
                pass
            except Exception as e:
                log.error(f"check_tor({ip}) DNS port {port} error: {e}")

        bulk_match = False
        if not listed_ports:
            try:
                r = requests.get("https://check.torproject.org/torbulkexitlist", timeout=10)
                if r.status_code == 200:
                    bulk_match = ip in r.text.splitlines()
            except requests.RequestException as e:
                log.error(f"check_tor({ip}) bulk list error: {e}")

        url = "https://check.torproject.org/"
        if listed_ports:
            return (
                f"🔴 *Tor Check: `{ip}`*\n"
                f"Listed as Tor exit node on ports `{', '.join(listed_ports)}`\n"
                f"Source: {url}"
            )
        if bulk_match:
            return (
                f"🔴 *Tor Check: `{ip}`*\n"
                f"Listed in Tor bulk exit node list\n"
                f"Source: {url}"
            )
        return (
            f"🟢 *Tor Check: `{ip}`*\n"
            f"Not found in Tor exit nodes.\n"
            f"Source: {url}"
        )
    except Exception as e:
        log.error(f"check_tor({ip}) error: {e}")
        return f"Tor check failed: {e}"


def check_proxy(ip: str) -> str:
    ip = ip.strip()
    try:
        if not _is_ipv4(ip):
            return f"❌ Invalid IP address: `{ip}`"

        fields = "status,message,country,regionName,city,isp,org,as,proxy,hosting,query,countryCode"
        r = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=10)
        data = r.json()
        if data.get("status") != "success":
            return f"🌐 *Proxy Check: `{ip}`*\nLookup failed: `{data.get('message', 'unknown error')}`"

        proxy = bool(data.get("proxy"))
        hosting = bool(data.get("hosting"))
        return (
            f"🌐 *Proxy Check: `{data.get('query', ip)}`*\n"
            f"Country: `{data.get('countryCode', 'N/A')}` ({data.get('country', 'N/A')})\n"
            f"Region: `{data.get('regionName', 'N/A')}`\n"
            f"City: `{data.get('city', 'N/A')}`\n"
            f"ISP: `{data.get('isp', 'N/A')}`\n"
            f"Org: `{data.get('org', 'N/A')}`\n"
            f"Proxy/VPN: {'✅ DETECTED' if proxy else '🟢 Not detected'}\n"
            f"Hosting: {'✅ Yes' if hosting else '🟢 No'}\n"
            f"ASN: `{data.get('as', 'N/A')}`"
        )
    except Exception as e:
        log.error(f"check_proxy({ip}) error: {e}")
        return f"Proxy check failed: {e}"


def check_ctlogs(domain: str) -> str:
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        if not domain or "." not in domain:
            return f"❌ Invalid domain: `{domain}`"

        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=15,
        )
        if r.status_code != 200:
            return f"📜 *CT Logs: `{domain}`*\ncrt.sh HTTP `{r.status_code}`"

        certs = r.json()
        issuers = Counter()
        subdomains = set()
        expiry_dates = []
        age_30 = age_90 = age_old = 0
        now = datetime.utcnow()

        for cert in certs:
            common_name = str(cert.get("common_name", "")).lower()
            name_value = cert.get("name_value", "")
            names = {common_name}
            names.update(n.strip().lower().lstrip("*.") for n in str(name_value).splitlines() if n.strip())
            if not any(name.endswith(domain) or name == domain for name in names):
                continue
            subdomains.update(name for name in names if name.endswith(domain) or name == domain)

            issuer_raw = cert.get("issuer_name", "Unknown")
            issuer = issuer_raw.split("CN=")[-1].split(",")[0] if "CN=" in issuer_raw else "Unknown"
            issuers[issuer] += 1

            if cert.get("not_after"):
                try:
                    expiry_dates.append(datetime.strptime(cert["not_after"], "%Y-%m-%dT%H:%M:%S"))
                except Exception:
                    pass
            if cert.get("entry_timestamp"):
                try:
                    ts = datetime.strptime(cert["entry_timestamp"].split(".")[0], "%Y-%m-%dT%H:%M:%S")
                    age_days = (now - ts).days
                    if age_days <= 30:
                        age_30 += 1
                    elif age_days <= 90:
                        age_90 += 1
                    else:
                        age_old += 1
                except Exception:
                    pass

        total = sum(issuers.values())
        if total == 0:
            return f"📜 *CT Logs: `{domain}`*\nNo certificates found."

        top_issuers = ", ".join(f"{name} ({count})" for name, count in issuers.most_common(3)) or "N/A"
        expiry_range = "N/A"
        if expiry_dates:
            expiry_range = f"{min(expiry_dates).date()} / {max(expiry_dates).date()}"

        return (
            f"📜 *CT Logs: `{domain}`*\n"
            f"Total certs: `{total}`\n"
            f"Unique issuers: `{len(issuers)}`\n"
            f"Issuers: `{top_issuers}`\n"
            f"Unique subdomains: `{len(subdomains)}`\n"
            f"Expiry range: `{expiry_range}`\n"
            f"Age distribution: `last 30d={age_30}, 30-90d={age_90}, 90d+={age_old}`"
        )
    except Exception as e:
        log.error(f"check_ctlogs({domain}) error: {e}")
        return f"CT logs check failed: {e}"


def check_phone(phone: str) -> str:
    raw_phone = phone.strip()
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def check_telegram(plus_number: str, digits: str) -> str:
        return "⚠ Cannot verify via HTTP (t.me/+ links always work for any valid phone format — actual existence requires contacting)"

    def check_whatsapp(digits: str) -> str:
        return "⚠ Cannot verify via HTTP (wa.me always responds — WhatsApp requires sending a message to confirm)"

    def check_duckduckgo(plus_number: str, international: str) -> dict:
        queries = [plus_number, international]
        seen = set()
        matches = []
        result_count = 0

        for query in queries:
            quoted_query = quote_plus(f'"{query}"')
            url = f"https://html.duckduckgo.com/html/?q={quoted_query}"
            try:
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code in (403, 429):
                    return {"status": "blocked", "count": result_count, "matches": matches}
                if r.status_code != 200:
                    log.warning(f"check_phone DuckDuckGo HTTP {r.status_code} for {plus_number}")
                    continue

                result_count += len(re.findall(r'class="result__a"', r.text))
                result_blocks = re.findall(
                    r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?'
                    r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
                    r.text,
                    flags=re.I | re.S,
                )
                if not result_blocks:
                    result_blocks = re.findall(
                        r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                        r.text,
                        flags=re.I | re.S,
                    )

                for block in result_blocks:
                    href = block[0]
                    title = _strip_html(block[1])
                    snippet = _strip_html(block[2]) if len(block) > 2 else ""
                    key = (href, title)
                    if key in seen:
                        continue
                    seen.add(key)
                    matches.append({"url": href, "title": title, "snippet": snippet})
                    if len(matches) >= 3:
                        break
                if len(matches) >= 3:
                    break
            except Exception as e:
                log.warning(f"check_phone DuckDuckGo source failed for {plus_number}: {e}")

        return {"status": "ok", "count": result_count, "matches": matches}

    def check_breaches(digits: str) -> str:
        url = f"https://api.xposedornot.com/v1/phone/{digits}"
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 404:
                return "No public breach data found via XposedOrNot"
            if r.status_code in (401, 403):
                return "⚠ XposedOrNot phone lookup unavailable/blocked; most phone breach databases require paid API access"
            if r.status_code == 429:
                return "⚠ XposedOrNot rate-limited the lookup"
            if r.status_code != 200:
                log.warning(f"check_phone breach source HTTP {r.status_code} for {digits}")
                return "⚠ Breach lookup inconclusive; phone breach databases are limited"

            data = r.json()
            breaches = data.get("breaches") or data.get("Breaches") or data.get("exposed_breaches") or []
            if isinstance(breaches, dict):
                breaches = breaches.get("breaches_details") or breaches.get("details") or list(breaches.values())
            if breaches:
                names = []
                for item in breaches[:5]:
                    if isinstance(item, dict):
                        names.append(item.get("breach") or item.get("name") or item.get("title") or "Unknown breach")
                    else:
                        names.append(str(item))
                suffix = f" and {len(breaches) - 5} more" if len(breaches) > 5 else ""
                return f"⚠ Found in breach data: {', '.join(names)}{suffix}"
            return "No public breach data found via XposedOrNot"
        except Exception as e:
            log.warning(f"check_phone breach source failed for {digits}: {e}")
            return "⚠ Breach lookup failed; phone breach databases are limited and often require paid API access"

    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone

        try:
            num = phonenumbers.parse(raw_phone, None)
        except Exception:
            digits_only = re.sub(r"\D+", "", raw_phone)
            if not digits_only:
                raise
            num = phonenumbers.parse(f"+{digits_only}", None)

        possible = phonenumbers.is_possible_number(num)
        valid = phonenumbers.is_valid_number(num)
        international = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        national = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)
        plus_number = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        digits = re.sub(r"\D+", "", plus_number)

        if not possible:
            return f"📞 *Phone OSINT: `{raw_phone}`*\nInvalid number"

        country = geocoder.description_for_number(num, "en") or "N/A"
        carrier_name = carrier.name_for_number(num, "en") or "N/A"
        tz = ", ".join(timezone.time_zones_for_number(num)) or "N/A"

        telegram = check_telegram(plus_number, digits)
        whatsapp = check_whatsapp(digits)
        web = check_duckduckgo(plus_number, international)
        breaches = check_breaches(digits)

        result_count = web["count"]
        web_lines = ["🔎 Searching DuckDuckGo for this number..."]
        if web["status"] == "blocked":
            web_lines.append("• ⚠ DuckDuckGo blocked or rate-limited the request")
        elif result_count or web["matches"]:
            approx = f"~{result_count}" if result_count else f"{len(web['matches'])}+"
            web_lines.append(f"• Found `{approx}` results mentioning this number")
            for match in web["matches"][:3]:
                title = match["title"][:90] or "Untitled result"
                snippet = match["snippet"][:140]
                if snippet:
                    web_lines.append(f"• Top match: `{title}` — \"{snippet}\"")
                else:
                    web_lines.append(f"• Top match: `{title}` — {match['url']}")
        else:
            web_lines.append("• No indexed public mentions found in DuckDuckGo HTML results")

        return (
            f"📞 *Phone OSINT: {international}*\n"
            f"╔═══════════════════════════════════════╗\n\n"
            f"📋 *Basic Info*\n"
            f"• Valid: {'✅' if valid else '❌'}\n"
            f"• Country: `{country}`\n"
            f"• Carrier: `{carrier_name}`\n"
            f"• Timezone: `{tz}`\n"
            f"• National: `{national}`\n\n"
            f"🔗 *Messaging Platforms*\n"
            f"• Telegram: {telegram}\n"
            f"• WhatsApp: {whatsapp}\n"
            f"• Viber: ✅ Link available: viber://chat?number=%2B{digits}\n"
            f"• Signal: ✅ Link available: https://signal.me/#p/{plus_number}\n"
            f"• Snapchat: ❌ Not searchable by phone from public web\n"
            f"• TrueCaller: ⚠ Requires app/API access\n\n"
            f"🔎 *Known Platform Links*\n"
            f"• Telegram: https://t.me/{plus_number}\n"
            f"• WhatsApp: https://wa.me/{digits}\n"
            f"• Signal: https://signal.me/#p/{plus_number}\n"
            f"• Viber: viber://chat?number=%2B{digits}\n\n"
            f"🌐 *Web Presence*\n"
            f"{chr(10).join(web_lines)}\n\n"
            f"🔐 *Breach Data*\n"
            f"• {breaches}"
        )
    except Exception as e:
        log.error(f"check_phone({raw_phone}) error: {e}")
        return f"Phone OSINT failed: {e}"
