"""Email, phone, and HIBP OSINT."""
import hashlib
import logging
import re
import socket
import subprocess
from urllib.parse import quote_plus

import requests
import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from config import settings
from services.threat_intel.reputation import _strip_html

try:
    import dns.resolver
except ImportError:
    dns = None

log = logging.getLogger("cyber_volt")


def _dig_txt(name):
    if dns is not None:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=10)
            return " ".join(str(r) for r in answers)
        except Exception as e:
            log.debug("dns TXT lookup failed for %s: %s", name, e)
            return ""
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", name],
            capture_output=True, text=True, timeout=10, check=False
        )
        return " ".join(line.strip().strip('"') for line in result.stdout.splitlines() if line.strip())
    except Exception as e:
        log.error("_dig_txt(%s) error: %s", name, e)
        return ""


def _has_mx(domain):
    if dns is not None:
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=10)
            return True, str(answers[0].exchange)
        except Exception as e:
            log.debug("dns MX lookup failed for %s: %s", domain, e)
            return False, "not found"
    try:
        result = subprocess.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=10, check=False
        )
        if result.stdout.strip():
            return True, result.stdout.strip().splitlines()[0]
    except Exception as e:
        log.error("MX dig failed for %s: %s", domain, e)
    try:
        socket.getaddrinfo(domain, 25)
        return True, "domain resolves"
    except Exception as e:
        log.error("MX fallback failed for %s: %s", domain, e)
        return False, "not found"


# ── HIBP ──


def fmt_pwn(n):
    return f"{n:,}" if n is not None else "N/A"


def fmt_data(classes):
    if not classes:
        return "N/A"
    return ", ".join(classes)


def check_hibp(query):
    try:
        hibp_key = settings.api.hibp_api_key
        if not hibp_key:
            return "⚠ HIBP: No API key configured. Set HIBP_API_KEY in .env"

        if query.lower().startswith("name:"):
            name = query.split(":", 1)[1].strip()
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breach/{name}",
                headers={"hibp-api-key": hibp_key},
                timeout=10,
            )
            if r.status_code == 200:
                b = r.json()
                return (
                    f"🔐 *HIBP: {b.get('Name', name)}*\n"
                    f"Title: `{b.get('Title', 'N/A')}`\n"
                    f"Domain: `{b.get('Domain', 'N/A')}`\n"
                    f"Date: {b.get('BreachDate', 'N/A')}\n"
                    f"👥 Accounts: {fmt_pwn(b.get('PwnCount'))}\n"
                    f"📦 Data: {fmt_data(b.get('DataClasses'))}\n"
                    f"Verified: {'✅ Yes' if b.get('IsVerified') else '❌ No'}\n"
                    f"Spam list: {'⚠ Yes' if b.get('IsSpamList') else 'No'}\n"
                    f"📝 {_strip_html(b.get('Description', ''))[:400]}"
                )
            elif r.status_code == 404:
                return f"🔐 *HIBP*\nBreach `{name}` not found."
            return f"⚠ HIBP: HTTP {r.status_code}"

        domain = query.split("@")[-1] if "@" in query else query
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
            headers={"hibp-api-key": hibp_key},
            timeout=10,
        )
        if r.status_code == 200:
            breaches = r.json()
            header = (
                f"🔐 *HIBP Check: {query}*\n"
                f"Domain: `{domain}`\n"
                f"⚠ Free-tier: searching by domain (not email)\n"
                f"An API key is needed for email lookup\n"
                f"Use `name:BreachName` for details\n\n"
            )
            if not breaches:
                return header + "🟢 No breaches for this domain."
            result = header + f"🔴 Found {len(breaches)} breaches:\n\n"
            for b in breaches[:5]:
                result += (
                    f"▫️ *{b.get('Name', 'N/A')}*\n"
                    f"  📅 {b.get('BreachDate', 'N/A')} | 👥 {fmt_pwn(b.get('PwnCount'))}\n"
                    f"  📦 {fmt_data(b.get('DataClasses'))}\n"
                    f"  {_strip_html(b.get('Description', ''))[:200]}\n\n"
                )
            if len(breaches) > 5:
                result += f"... and {len(breaches) - 5} more breaches"
            return result
        elif r.status_code == 404:
            return f"🔐 *HIBP Check: {query}*\nNo breaches found."
        return f"⚠ HIBP: HTTP {r.status_code}"
    except Exception as e:
        return f"HIBP check failed: {e}"


# ── Email OSINT ──


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
        log.error("check_email(%s) error: %s", email, e)
        return f"Email OSINT failed: {e}"
    except Exception as e:
        log.error("check_email(%s) error: %s", email, e)
        return f"Email OSINT failed: {e}"


# ── Phone OSINT ──


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

    def check_telegram(plus_number, digits):
        return "⚠ Cannot verify via HTTP (t.me/+ links always work for any valid phone format — actual existence requires contacting)"

    def check_whatsapp(digits):
        return "⚠ Cannot verify via HTTP (wa.me always responds — WhatsApp requires sending a message to confirm)"

    def check_duckduckgo(plus_number, international):
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
                    log.warning("check_phone DuckDuckGo HTTP %s for %s", r.status_code, plus_number)
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
                log.warning("check_phone DuckDuckGo source failed for %s: %s", plus_number, e)

        return {"status": "ok", "count": result_count, "matches": matches}

    def check_breaches(digits):
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
                log.warning("check_phone breach source HTTP %s for %s", r.status_code, digits)
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
            log.warning("check_phone breach source failed for %s: %s", digits, e)
            return "⚠ Breach lookup failed; phone breach databases are limited and often require paid API access"

    try:
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
        log.error("check_phone(%s) error: %s", raw_phone, e)
        return f"Phone OSINT failed: {e}"
