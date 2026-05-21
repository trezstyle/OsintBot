"""IP/domain reputation, network checks, and certificate transparency."""
from collections import Counter
from datetime import datetime
import logging
import os
import re
import socket
import ssl
import subprocess

import requests

import whois

from config import settings
from services.threat_intel import get_http
from services.threat_intel.utils import strip_html as _strip_html

try:
    import dns.resolver
except ImportError:
    dns = None

log = logging.getLogger("cyber_volt")


def _is_ipv4(ip: str) -> bool:
    parts = ip.strip().split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ── Logging ──


def save_to_log(target, report):
    try:
        with open(settings.paths.threat_intel_log_file, "a") as f:
            f.write(f"\n--- [{datetime.now()}] ---\nTarget: {target}\n{report}\n")
    except OSError as e:
        log.error("Failed to write threat intel log: %s", e)


# ── AbuseIPDB ──


def get_abuseipdb_report(ip):
    key = settings.api.abuse_api_key
    if not key:
        return "AbuseIPDB: No API key"
    try:
        r = get_http().get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            timeout=10,
        )
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


# ── GeoIP ──


def get_geoip(ip):
    try:
        r = get_http().get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            d = r.json()
            return (
                f"📍 *GeoIP*\nCity: `{d.get('city', 'N/A')}`\n"
                f"Region: `{d.get('region', 'N/A')}`\n"
                f"Country: `{d.get('country', 'N/A')}`\n"
                f"ISP: `{d.get('org', 'N/A')}`"
            )
        return "GeoIP: N/A"
    except Exception as exc:
        log.debug("get_geoip(%s) failed: %s", ip, exc)
        return "GeoIP: N/A"


# ── WHOIS ──


def _fmt_whois_date(val):
    if not val:
        return "N/A"
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, str):
        return val
    try:
        return val.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(val)


def _fmt_whois_list(val):
    if not val:
        return "N/A"
    if isinstance(val, list):
        return ", ".join(str(v) for v in val)
    return str(val)


def get_whois(domain):
    try:
        w = whois.whois(domain)
        return (
            f"🏢 *WHOIS for {domain}*\n"
            f"📅 Registrar: `{w.registrar or 'N/A'}`\n"
            f"📅 Created: `{_fmt_whois_date(w.creation_date)}`\n"
            f"📅 Expires: `{_fmt_whois_date(w.expiration_date)}`\n"
            f"📅 Updated: `{_fmt_whois_date(w.updated_date)}`\n"
            f"🏢 Organization: `{w.org or 'N/A'}`\n"
            f"👤 Registrant: `{w.name or 'N/A'}`\n"
            f"📧 Email: `{_fmt_whois_list(w.emails)}`\n"
            f"🌍 Country: `{w.country or 'N/A'}`\n"
            f"📡 Name Servers: `{_fmt_whois_list(w.name_servers)}`\n"
            f"🔖 Status: `{_fmt_whois_list(w.status)}`"
        )
    except Exception as e:
        return f"Whois failed: {e}"


# ── crt.sh subdomains ──


def get_subdomains(domain):
    try:
        r = get_http().get(
            f"https://crt.sh/?q={domain}&output=json",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
        )
        if r.status_code == 200:
            subs = sorted(list(set(e["common_name"] for e in r.json() if domain in e["common_name"])))[:10]
            return "\n".join(subs) if subs else "None found"
        return f"crt.sh: HTTP {r.status_code}"
    except Exception as e:
        return f"crt.sh: {e}"


# ── SSL Check ──


def check_ssl(domain: str) -> str:
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            protocol = s.version()
            cipher = s.cipher()[0]

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
        chain_status = "⚠ Self-signed/root" if subject == issuer else "✅ Valid"

        return (
            f"{emoji} *SSL Check: `{domain}`*\n"
            f"Status: `{status}` ({days_remaining}d)\n"
            f"From: `{valid_from}`\n"
            f"Till: `{valid_to}`\n"
            f"Issuer: `{issuer}`\n"
            f"Subject: `{subject}`\n"
            f"SANs: `{len(sans)}`\n"
            f"TLS: `{protocol}` | Cipher: `{cipher}`\n"
            f"Chain: {chain_status}"
        )
    except ssl.SSLCertVerificationError as e:
        return f"🔴 *SSL Check: `{domain}`*\nChain invalid: `{e}`"
    except (ConnectionError, socket.timeout, ssl.SSLError, OSError) as e:
        log.error("check_ssl(%s) error: %s", domain, e)
        return f"🔴 *SSL Check: `{domain}`*\nFailed: `{e}`"
    except Exception as e:
        log.error("check_ssl(%s) error: %s", domain, e)
        return f"SSL check failed: {e}"


# ── HTTP Headers ──


def check_http_headers(url: str) -> str:
    target = url.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        r = get_http().get(f"https://{target}", timeout=10, allow_redirects=True)
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
        lines.append(f"{'⚠️' if xss_present else '🟢'} `X-XSS-Protection` — obsolete{' present' if xss_present else '; not present'}")
        return "\n".join(lines)
    except requests.RequestException as e:
        log.error("check_http_headers(%s) error: %s", target, e)
        return f"🔴 *HTTP Security Headers: `{target}`*\nFailed: `{e}`"
    except Exception as e:
        log.error("check_http_headers(%s) error: %s", target, e)
        return f"HTTP header check failed: {e}"


# ── DNSBL Blacklist ──


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
                log.error("check_blacklist(%s) %s error: %s", ip, name, e)
                lines.append(f"⚠ *{name}*: Error `{e}`")
        return "\n".join(lines)
    except Exception as e:
        log.error("check_blacklist(%s) error: %s", ip, e)
        return f"Blacklist check failed: {e}"


# ── Tor Check ──


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
                log.error("check_tor(%s) DNS port %s error: %s", ip, port, e)

        bulk_match = False
        if not listed_ports:
            try:
                r = get_http().get("https://check.torproject.org/torbulkexitlist", timeout=10)
                if r.status_code == 200:
                    bulk_match = ip in r.text.splitlines()
            except requests.RequestException as e:
                log.error("check_tor(%s) bulk list error: %s", ip, e)

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
        log.error("check_tor(%s) error: %s", ip, e)
        return f"Tor check failed: {e}"


# ── Proxy Check ──


def check_proxy(ip: str) -> str:
    ip = ip.strip()
    try:
        if not _is_ipv4(ip):
            return f"❌ Invalid IP address: `{ip}`"

        fields = "status,message,country,regionName,city,isp,org,as,proxy,hosting,query,countryCode"
        r = get_http().get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=10)
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
        log.error("check_proxy(%s) error: %s", ip, e)
        return f"Proxy check failed: {e}"


# ── Certificate Transparency Logs ──


def check_ctlogs(domain: str) -> str:
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        if not domain or "." not in domain:
            return f"❌ Invalid domain: `{domain}`"

        r = get_http().get(
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
            names.update(
                n.strip().lower().lstrip("*.")
                for n in str(name_value).splitlines()
                if n.strip()
            )
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
        log.error("check_ctlogs(%s) error: %s", domain, e)
        return f"CT logs check failed: {e}"
