"""Threat intelligence and external lookup services."""
from collections import Counter
from datetime import datetime
import hashlib
import logging
import re
import socket
import ssl
import subprocess

import requests
import whois

from config import settings

log = logging.getLogger("cyber_volt")


def _is_ipv4(ip: str) -> bool:
    parts = ip.strip().split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


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
    phone = phone.strip()
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone

        num = phonenumbers.parse(phone, None)
        if not phonenumbers.is_possible_number(num):
            return f"📞 *Phone OSINT: `{phone}`*\nInvalid number"

        valid = phonenumbers.is_valid_number(num)
        country = geocoder.description_for_number(num, "en") or "N/A"
        carrier_name = carrier.name_for_number(num, "en") or "N/A"
        tz = ", ".join(timezone.time_zones_for_number(num)) or "N/A"
        national = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)
        international = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)

        return (
            f"📞 *Phone OSINT: `{international}`*\n"
            f"Valid: {'✅' if valid else '❌'}\n"
            f"Country: `{country}`\n"
            f"Carrier: `{carrier_name}`\n"
            f"Timezone: `{tz}`\n"
            f"National: `{national}`"
        )
    except Exception as e:
        log.error(f"check_phone({phone}) error: {e}")
        return f"Phone parse failed: {e}"
