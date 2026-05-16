"""Cyber-Volt SOC Master Bot v3.0 — English version."""
import telebot, os, shutil, psutil, socket, subprocess, whois, requests, re, json, threading, time, hashlib, sys, logging
from datetime import datetime, timedelta
from collections import defaultdict
from dotenv import load_dotenv
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# ── Logging ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/root/cyber-volt/bot.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("cyber_volt")

# ── Config ──
load_dotenv("/root/cyber-volt/.env")
TOKEN = os.getenv("TELEGRAM_TOKEN")
PID_FILE = "/tmp/cyber_volt_bot.pid"
LOG_FILE = "/root/cyber-volt/threat_intel_log.md"
FIM_FILE = "/root/cyber-volt/fim_hashes.json"
ALERT_CHAT_ID = None
ALERT_LOCK = threading.Lock()

bot = telebot.TeleBot(TOKEN)

LOGO = """```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗
██║     ██║   ██║██████╔╝█████╗  ██████╔╝
██║     ╚██╗ ██╔╝██╔══██╗██╔══╝  ██╔══██╗
╚██████╗ ╚████╔╝ ██████╔╝███████╗██║  ██║
 ╚═════╝  ╚═══╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
```"""

def save_to_log(target, report):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"\n--- [{datetime.now()}] ---\nTarget: {target}\n{report}\n")
    except:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# KEYBOARDS
# ═══════════════════════════════════════════════════════════════════════════════

def help_keyboard():
    kb = InlineKeyboardMarkup(row_width=2)
    # Threat Intel
    kb.add(
        InlineKeyboardButton("🎯 IP Threat Hunt", callback_data="h_ip"),
        InlineKeyboardButton("🌐 Domain Recon", callback_data="h_domain"),
    )
    # Network
    kb.add(
        InlineKeyboardButton("⚡ Fast Scan", callback_data="h_scan_common"),
        InlineKeyboardButton("🔍 Full Scan", callback_data="h_scan_all"),
    )
    # Monitoring
    kb.add(
        InlineKeyboardButton("🖥 System Status", callback_data="h_status"),
        InlineKeyboardButton("📊 Top Processes", callback_data="h_top"),
    )
    kb.add(
        InlineKeyboardButton("📜 Logs [filter]", callback_data="h_logs_menu"),
    )
    # Security
    kb.add(
        InlineKeyboardButton("🛡 BSI Audit", callback_data="h_audit"),
        InlineKeyboardButton("📋 FIM Monitor", callback_data="h_fim"),
    )
    kb.add(
        InlineKeyboardButton("🧠 CVE Check", callback_data="h_cve"),
        InlineKeyboardButton("🔐 HIBP Check", callback_data="h_hibp"),
    )
    kb.add(
        InlineKeyboardButton("🧬 MITRE ATT&CK", callback_data="h_mitre"),
    )
    # Reports
    kb.add(
        InlineKeyboardButton("📄 PDF Report", callback_data="h_report"),
    )
    # Alerts
    kb.add(
        InlineKeyboardButton("🚨 Suricata Alerts", callback_data="h_alerts"),
    )
    # Navigation
    kb.add(
        InlineKeyboardButton("📖 Help", callback_data="h_help"),
    )
    return kb


def menu_text():
    return (
        "🤖 *Cyber-Volt SOC Master v3.0*\n\n"
        "Choose a category:\n\n"
        "🛡 *Threat Intel*   — IP / Domain reconnaissance\n"
        "🕸 *Network*        — Fast / Full nmap scan\n"
        "📊 *Monitoring*     — Status, Top, Logs\n"
        "🔐 *Security*       — Audit, FIM, CVE, HIBP, MITRE\n"
        "📄 *Reports*        — PDF report generator\n\n"
        "💡 *Tip:* just send an IP or domain\ninto the chat — the bot auto-hunts it!"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTEL
# ═══════════════════════════════════════════════════════════════════════════════

def get_vt_report(ip):
    key = os.getenv("VT_API_KEY")
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
    key = os.getenv("ABUSE_API_KEY")
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


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM / STATUS
# ═══════════════════════════════════════════════════════════════════════════════

def format_top():
    try:
        raw = subprocess.check_output(
            "ps -eo pid,pcpu,pmem,rss,args --sort=-pcpu --no-headers 2>/dev/null | head -8",
            shell=True, text=True, timeout=5
        ).strip().split("\n")

        total_cpu = psutil.cpu_percent(interval=0.3)
        mem = psutil.virtual_memory()
        load = os.getloadavg()

        def bar(v, w=6):
            filled = int(v / 100 * w)
            return "█" * filled + "░" * (w - filled)

        def fmt_rss(kb_str):
            try:
                kb = int(kb_str)
                if kb >= 1048576: return f"{kb/1048576:.1f}G"
                if kb >= 1024: return f"{kb/1024:.0f}M"
                return f"{kb}K"
            except:
                return kb_str

        header = (
            f"📊 *Top Processes*\n"
            f"CPU: {total_cpu:.1f}% {bar(total_cpu)}  "
            f"RAM: {mem.percent:.1f}% {bar(mem.percent)}  "
            f"Load: {load[0]:.2f}\n\n"
        )

        rows = []
        for i, line in enumerate(raw, 1):
            parts = line.split(maxsplit=4)
            if len(parts) >= 5:
                pid, cpu, mem_p, rss, cmd = parts
                rss_fmt = fmt_rss(rss)
                cmd_short = cmd[:35] + "…" if len(cmd) > 35 else cmd
                rows.append(
                    f"{i:<2} {pid:<6} {cpu:>4}% {mem_p:>4}% {rss_fmt:>5}  {cmd_short}"
                )

        return header + "```\n" + "\n".join(rows) + "\n```"
    except Exception as e:
        log.error(f"format_top error: {e}")
        return f"Top failed: {e}"

def format_status():
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        usage = shutil.disk_usage("/")
        disk_pct = (usage.used / usage.total) * 100
        load = os.getloadavg()
        net = psutil.net_io_counters()
        uptime_sec = time.time() - psutil.boot_time()
        uptime_str = str(timedelta(seconds=int(uptime_sec))).split(".")[0]
        procs = len(psutil.pids())
        swap = psutil.swap_memory()

        def bar(v, n=10):
            filled = int(v / 10)
            return "█" * filled + "░" * (n - filled)

        cpu_e = "🟢" if cpu < 50 else "🟡" if cpu < 80 else "🔴"
        mem_e = "🟢" if mem.percent < 50 else "🟡" if mem.percent < 80 else "🔴"
        disk_e = "🟢" if disk_pct < 50 else "🟡" if disk_pct < 80 else "🔴"

        lines = [
            "```",
            "╔══════════════════════════════════════╗",
            "║       📊  SYSTEM DASHBOARD           ║",
            "╠══════════════════════════════════════╣",
            f"║  ⏱ Uptime:  {uptime_str:<28s}║",
            f"║  ⚙ Processes: {procs:<4d}    CPU cores: {psutil.cpu_count():<2d}              ║",
            "╠══════════════════════════════════════╣",
            f"║  {cpu_e} CPU:  {bar(cpu)}  {cpu:>5.1f}%            ║",
            f"║  {mem_e} RAM:  {bar(mem.percent)}  {mem.percent:>5.1f}%           ║",
            f"║         Used: {mem.used//1024//1024}MB / Total: {mem.total//1024//1024}MB     ║",
            f"║  {disk_e} DISK: {bar(disk_pct)}  {disk_pct:>5.1f}%           ║",
            f"║         Used: {usage.used//1024//1024}MB / Total: {usage.total//1024//1024}MB  ║",
            "╠══════════════════════════════════════╣",
            f"║  📈 Load:   {load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}            ║",
            f"║  🧠 Swap:   {swap.percent:.1f}% ({swap.used//1024//1024}MB / {swap.total//1024//1024}MB)    ║",
            f"║  🌐 Net:    ↓{net.bytes_recv//1024//1024}MB / ↑{net.bytes_sent//1024//1024}MB          ║",
            "╚══════════════════════════════════════╝",
            "```",
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"Status failed: {e}"

def format_audit():
    try:
        checks = []
        if os.path.exists("/etc/ssh/sshd_config"):
            cfg = open("/etc/ssh/sshd_config").read()
            checks.append(("🔐 Root SSH", "✅ DISABLED" if "PermitRootLogin no" in cfg else "❌ ENABLED"))
        fw = os.system("ufw status | grep -q 'Status: active'") == 0
        checks.append(("🛡 Firewall", "✅ ACTIVE" if fw else "❌ INACTIVE"))
        try:
            ports = subprocess.check_output("ss -tlnp | grep LISTEN | awk '{print $4}' | grep -oP ':\\K\\d+' | sort -n | uniq | head -5", shell=True, text=True).strip()
            checks.append(("🔌 Open Ports", f"`{ports.replace(chr(10), ', ')}`" if ports else "None"))
        except:
            checks.append(("🔌 Open Ports", "N/A"))
        try:
            fails = subprocess.check_output("grep 'Failed password' /var/log/auth.log 2>/dev/null | wc -l", shell=True, text=True).strip()
            checks.append(("🚫 Failed Logins", f"{fails} total"))
        except:
            checks.append(("🚫 Failed Logins", "N/A"))
        uptime_str = subprocess.check_output("uptime -p", shell=True, text=True).strip().replace("up ", "")
        checks.append(("⏱ Uptime", uptime_str))
        u = shutil.disk_usage("/")
        checks.append(("💾 Disk Usage", f"{u.used/u.total*100:.1f}%"))
        m = psutil.virtual_memory()
        checks.append(("🧠 Memory", f"{m.percent:.1f}%"))
        load = os.getloadavg()
        checks.append(("📈 Load Avg", f"{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}"))
        try:
            failed = subprocess.check_output("systemctl --failed --no-legend | wc -l", shell=True, text=True).strip()
            checks.append(("⚙ Failed Svcs", failed))
        except:
            checks.append(("⚙ Failed Svcs", "N/A"))
        lines = ["🛡 *BSI Compliance Audit*\n"]
        lines += [f"• {icon}: {status}" for icon, status in checks]
        return "\n".join(lines)
    except Exception as e:
        return f"Audit failed: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# LOG ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_logs(filter_type):
    path = "/var/log/auth.log"
    if not os.path.exists(path):
        return "Log file not found."
    try:
        cmds = {
            "failed": ("grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -15", "🚫 *Failed Logins (last 15)*"),
            "sudo": ("grep 'sudo' /var/log/auth.log 2>/dev/null | tail -15", "👤 *Sudo Events (last 15)*"),
            "ssh": ("grep 'sshd' /var/log/auth.log 2>/dev/null | tail -15", "🔐 *SSH Events (last 15)*"),
            "attack": ("grep 'Failed password' /var/log/auth.log | grep -oP 'from \\K\\S+' | sort | uniq -c | sort -rn | head -10", "🛡 *Top Attackers (by failed logins)*"),
        }
        if filter_type not in cmds:
            return "Usage: /logs [failed|sudo|ssh|attack]"
        cmd, header = cmds[filter_type]
        out = subprocess.check_output(cmd, shell=True, text=True, timeout=5)
        if not out.strip():
            return f"{header}\nNo entries found."
        return f"{header}\n```\n{out.strip()}\n```"
    except Exception as e:
        return f"Log analysis failed: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def scan_network(target, all_ports=True):
    try:
        if not all_ports:
            COMMON = "22,80,443,21,25,53,110,143,993,995,8080,8443,3306,5432,6379,27017,3389,5900,9090,3000,5000,8000,9000"
            out = subprocess.check_output(f"nmap -T4 --open -p {COMMON} {target} 2>/dev/null", shell=True, text=True, timeout=180)
            hosts = parse_nmap_hosts(out)
            summary = ""
            for line in out.split("\n"):
                if "Nmap done" in line:
                    summary = line.strip()
                    break
            return format_scan(target, summary, hosts)
        # Full scan — single pass with all ports
        out = subprocess.check_output(
            f"nmap -Pn -T4 --open -p- {target} 2>/dev/null",
            shell=True, text=True, timeout=600
        )
        hosts = parse_nmap_hosts(out)
        summary = ""
        for line in out.split("\n"):
            if "Nmap done" in line:
                summary = line.strip()
                break
        if not hosts:
            return f"🌐 *Full Scan: {target}*\n❌ No open ports found."
        return format_scan(target, summary, hosts)
    except subprocess.TimeoutExpired:
        return "Scan timed out. Try a smaller range or use common ports."
    except Exception as e:
        return f"Scan failed: {e}"

def parse_nmap_hosts(out):
    hosts = []
    cur = None
    for line in out.split("\n"):
        if "Nmap scan report for" in line:
            if cur: hosts.append(cur)
            s = line.replace("Nmap scan report for", "").strip()
            m = re.match(r"(.+?) \((\d+\.\d+\.\d+\.\d+)\)", s)
            if m:
                cur = {"hostname": m.group(1), "ip": m.group(2), "ports": []}
            elif re.match(r"\d+\.\d+\.\d+\.\d+", s):
                cur = {"hostname": s, "ip": s, "ports": []}
            else:
                cur = {"hostname": s, "ip": s, "ports": []}
        elif cur and "open" in line and ("tcp" in line or "udp" in line):
            parts = line.strip().split()
            if len(parts) >= 2:
                cur["ports"].append({"port": parts[0], "service": parts[2] if len(parts) > 2 else "unknown", "version": " ".join(parts[3:])[:30] if len(parts) > 3 else ""})
    if cur: hosts.append(cur)
    return hosts

def format_scan(target, summary, hosts):
    if not hosts:
        return f"🌐 *Network Scan: {target}*\n📊 `{summary or 'No results'}`\n❌ No hosts found."
    result = f"🌐 *Network Scan: {target}*\n📊 `{summary}`\n\n"
    for h in hosts:
        hname = h["hostname"]
        hip = h["ip"]
        if hname == hip: hname = "—"
        icon = "🔴" if len(h["ports"]) > 10 else ("🟡" if h["ports"] else "🟢")
        result += f"{icon} *{hname}* (`{hip}`) — `{len(h['ports'])}` ports\n"
        if h["ports"]:
            result += "```\nPORT         SERVICE\n─────────── ──────────────\n"
            for p in h["ports"]:
                result += f"{p['port'].ljust(11)} {p['service'].ljust(14)}\n"
            result += "```\n"
    result += f"\n📡 Total: `{len(hosts)}` hosts up"
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# FIM
# ═══════════════════════════════════════════════════════════════════════════════

def load_fim():
    if os.path.exists(FIM_FILE):
        try: return json.load(open(FIM_FILE))
        except: return {}
    return {}

def save_fim(db):
    json.dump(db, open(FIM_FILE, "w"), indent=2)

def fim_add(path):
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


# ═══════════════════════════════════════════════════════════════════════════════
# CVE
# ═══════════════════════════════════════════════════════════════════════════════

def check_cve(pkg):
    try:
        ver = "unknown"
        try:
            ver = subprocess.check_output(f"dpkg -l {pkg} 2>/dev/null | tail -1 | awk '{{print $3}}'", shell=True, text=True, timeout=5).strip()
            if not ver:
                ver = subprocess.check_output(f"which {pkg} && {pkg} --version 2>/dev/null | head -1", shell=True, text=True, timeout=5).strip()
        except: pass
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={pkg}&resultsPerPage=5", timeout=15)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if not vulns:
                return f"🟢 *CVE Check: {pkg}*\nVersion: `{ver}`\nNo known CVEs."
            out = f"🔴 *CVE Check: {pkg}*\nVersion: `{ver}`\n"
            for v in vulns[:5]:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "N/A")
                desc = cve.get("descriptions", [{}])[0].get("value", "")[:100]
                score = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
                out += f"\n• `{cve_id}` (CVSS: {score})\n  {desc}\n"
            return out
        return f"⚠ NVD API: HTTP {r.status_code}"
    except Exception as e:
        return f"CVE check failed: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# HIBP
# ═══════════════════════════════════════════════════════════════════════════════

def fmt_pwn(n):
    return f"{n:,}" if n is not None else "N/A"

def fmt_data(classes):
    if not classes: return "N/A"
    return ", ".join(classes)

def check_hibp(query):
    try:
        if query.lower().startswith("name:"):
            name = query.split(":", 1)[1].strip()
            r = requests.get(f"https://haveibeenpwned.com/api/v3/breach/{name}",
                             headers={"hibp-api-key": ""}, timeout=10)
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
                         headers={"hibp-api-key": ""}, timeout=10)
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


# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK
# ═══════════════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════════════
# PDF REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def generate_report():
    try:
        path = "/tmp/cyber_volt_report.pdf"
        doc = SimpleDocTemplate(path, pagesize=A4)
        styles = getSampleStyleSheet()
        els = [Paragraph("Cyber-Volt SOC Report", styles["Title"]),
               Spacer(1, 12),
               Paragraph(f"Generated: {datetime.now()}", styles["Normal"]),
               Spacer(1, 12),
               Paragraph("System Status", styles["Heading2"]),
               Paragraph(f"CPU: {psutil.cpu_percent(interval=0.5)}% | RAM: {psutil.virtual_memory().percent}% | Disk: {shutil.disk_usage('/').used/shutil.disk_usage('/').total*100:.1f}%", styles["Normal"]),
               Spacer(1, 12),
               Paragraph("Top Processes", styles["Heading2"]),
               Paragraph(subprocess.check_output("ps -eo pid,pcpu,pmem,args --sort=-pcpu | head -6", shell=True, text=True).replace("\n", "<br/>"), styles["Normal"]),
               Spacer(1, 12),
               Paragraph("Recent Failed Logins", styles["Heading2"]),
               Paragraph((subprocess.check_output("grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -5", shell=True, text=True) or "None").replace("\n", "<br/>"), styles["Normal"]),
               Spacer(1, 12),
               Paragraph("Compliance Audit", styles["Heading2"]),
               Paragraph(format_audit().replace("\n", "<br/>"), styles["Normal"])]
        doc.build(els)
        return path
    except Exception as e:
        return f"Report failed: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# ALERT WATCHERS
# ═══════════════════════════════════════════════════════════════════════════════

failed_attempts = defaultdict(list)

def alert_watcher():
    """Monitor auth.log for brute force attacks."""
    global ALERT_CHAT_ID
    last_size = 0
    seen_lines = set()
    while True:
        time.sleep(30)
        if not ALERT_CHAT_ID: continue
        try:
            path = "/var/log/auth.log"
            if not os.path.exists(path): continue
            size = os.path.getsize(path)
            if size == last_size and seen_lines: continue
            if size < last_size: seen_lines.clear()
            last_size = size
            out = subprocess.check_output("grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20", shell=True, text=True, timeout=5)
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
                        bot.send_message(ALERT_CHAT_ID,
                            f"🚨 *Brute Force Alert!*\nIP: `{ip}`\nAttempts: {len(times)} in 5min",
                            parse_mode="Markdown")
                    except: pass
                    failed_attempts[ip] = []
        except: pass

threading.Thread(target=alert_watcher, daemon=True).start()

# Suricata alert buffer — last N alerts
suricata_alerts = []
suricata_lock = threading.Lock()

def suricata_watcher():
    """Monitor Suricata fast.log for IDS alerts."""
    global ALERT_CHAT_ID
    path = "/var/log/suricata/fast.log"
    seen = set()
    while True:
        time.sleep(15)
        try:
            if not os.path.exists(path):
                continue
            out = subprocess.check_output(
                "tail -20 /var/log/suricata/fast.log 2>/dev/null",
                shell=True, text=True, timeout=5
            )
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
                    if ALERT_CHAT_ID:
                        try:
                            msg = f"🚨 *Suricata IDS Alert!*\n```\n{sig[:200]}\n```"
                            if ips:
                                msg += f"\nSource IP: `{ips[0]}`"
                            if len(ips) > 1:
                                msg += f" → Target: `{ips[1]}`"
                            bot.send_message(ALERT_CHAT_ID, msg, parse_mode="Markdown")
                        except:
                            pass

                    # Auto-run threat hunt on malicious IP
                    if ips:
                        try:
                            vt = get_vt_report(ips[0])
                            abuse = get_abuseipdb_report(ips[0])
                            geo = get_geoip(ips[0])
                            report = f"🎯 *Auto Threat Hunt: `{ips[0]}`*\n\n{vt}\n\n{abuse}\n\n{geo}"
                            bot.send_message(ALERT_CHAT_ID, report, parse_mode="Markdown")
                        except:
                            pass
        except FileNotFoundError:
            pass
        except Exception as e:
            log.debug(f"suricata_watcher: {e}")

threading.Thread(target=suricata_watcher, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND HANDLERS (order matters: commands first, catch-all last)
# ═══════════════════════════════════════════════════════════════════════════════

@bot.message_handler(commands=["start"])
def cmd_start(m):
    global ALERT_CHAT_ID
    with ALERT_LOCK: ALERT_CHAT_ID = m.chat.id
    bot.reply_to(m, f"{LOGO}\n🤖 *Cyber-Volt SOC Master v3.0*\n\nFull-featured SOC platform in Telegram.\n\nUse /help to open the menu.", parse_mode="Markdown", reply_markup=help_keyboard())

@bot.message_handler(commands=["help"])
def cmd_help(m):
    global ALERT_CHAT_ID
    with ALERT_LOCK: ALERT_CHAT_ID = m.chat.id
    bot.reply_to(m, menu_text(), parse_mode="Markdown", reply_markup=help_keyboard())

@bot.message_handler(commands=["status", "top", "logs", "audit", "whois", "recon", "scan", "fim", "cve", "hibp", "mitre", "report", "alerts"])
def cmd_handler(m):
    global ALERT_CHAT_ID
    with ALERT_LOCK: ALERT_CHAT_ID = m.chat.id
    cmd = m.text.split()[0].replace("/", "")
    args = m.text.split()[1:]

    try:
        if cmd == "status": bot.reply_to(m, format_status(), parse_mode="Markdown")
        elif cmd == "top": bot.reply_to(m, format_top(), parse_mode="Markdown")
        elif cmd == "audit": bot.reply_to(m, format_audit(), parse_mode="Markdown")
        elif cmd == "logs":
            if args:
                bot.reply_to(m, analyze_logs(args[0]), parse_mode="Markdown")
            else:
                kb = InlineKeyboardMarkup(row_width=2)
                kb.add(InlineKeyboardButton("🚫 Failed", callback_data="h_logs_failed"), InlineKeyboardButton("👤 Sudo", callback_data="h_logs_sudo"))
                kb.add(InlineKeyboardButton("🔐 SSH", callback_data="h_logs_ssh"), InlineKeyboardButton("🛡 Attackers", callback_data="h_logs_attack"))
                kb.add(InlineKeyboardButton("🔙 Menu", callback_data="h_menu"))
                bot.reply_to(m, "📊 *Choose log filter:*", parse_mode="Markdown", reply_markup=kb)
        elif cmd == "whois":
            if args: bot.reply_to(m, get_whois(args[0]), parse_mode="Markdown")
            else: bot.register_next_step_handler(bot.reply_to(m, "🕵️ *Enter a domain for WHOIS:*", parse_mode="Markdown"), process_whois)
        elif cmd == "recon":
            if args: process_domain_hunt(m)
            else: bot.register_next_step_handler(bot.reply_to(m, "🌐 *Enter a domain or IP:*", parse_mode="Markdown"), process_domain_hunt)
        elif cmd == "scan":
            if args:
                fast = "fast" in args
                target = [a for a in args if a != "fast"][0] if fast else args[0]
                if fast:
                    bot.reply_to(m, f"⚡ *Fast scan `{target}`...*", parse_mode="Markdown")
                    bot.reply_to(m, scan_network(target, all_ports=False), parse_mode="Markdown")
                else:
                    bot.reply_to(m, f"🔍 *Full scan `{target}`...* ~5-10 min ⏳", parse_mode="Markdown")
                    bot.reply_to(m, scan_network(target, all_ports=True), parse_mode="Markdown")
            else:
                kb = InlineKeyboardMarkup(row_width=2)
                kb.add(InlineKeyboardButton("🔍 Full (65535 ports)", callback_data="h_scan_all"), InlineKeyboardButton("⚡ Fast (23 ports)", callback_data="h_scan_common"))
                kb.add(InlineKeyboardButton("🔙 Menu", callback_data="h_menu"))
                bot.reply_to(m, "🕸 *Choose scan mode:*", parse_mode="Markdown", reply_markup=kb)
        elif cmd == "fim":
            if len(args) >= 2 and args[0] == "add": bot.reply_to(m, fim_add(" ".join(args[1:])), parse_mode="Markdown")
            elif args and args[0] == "check": bot.reply_to(m, fim_check(), parse_mode="Markdown")
            else:
                kb = InlineKeyboardMarkup(row_width=2)
                kb.add(InlineKeyboardButton("➕ Add File", callback_data="h_fim_add"), InlineKeyboardButton("🔍 Check All", callback_data="h_fim_check"))
                kb.add(InlineKeyboardButton("🔙 Menu", callback_data="h_menu"))
                bot.reply_to(m, "📋 *File Integrity Monitor*", parse_mode="Markdown", reply_markup=kb)
        elif cmd == "cve":
            if args: bot.reply_to(m, check_cve(args[0]), parse_mode="Markdown")
            else: bot.register_next_step_handler(bot.reply_to(m, "🧠 *Enter package name:*\nExample: `openssl`", parse_mode="Markdown"), process_cve)
        elif cmd == "hibp":
            if args: bot.reply_to(m, check_hibp(args[0]), parse_mode="Markdown")
            else: bot.register_next_step_handler(bot.reply_to(m, "🔐 *Enter email or domain:*", parse_mode="Markdown"), process_hibp)
        elif cmd == "mitre":
            if args: bot.reply_to(m, mitre_lookup(args[0]), parse_mode="Markdown")
            else: bot.register_next_step_handler(bot.reply_to(m, "🧬 *Enter technique ID:*\nExample: `T1059`", parse_mode="Markdown"), process_mitre)
        elif cmd == "report":
            bot.reply_to(m, "📄 *Generating PDF report...*")
            result = generate_report()
            if isinstance(result, str) and result.startswith("/tmp"):
                with open(result, "rb") as f: bot.send_document(m.chat.id, f, caption="📄 Cyber-Volt SOC Report")
            else: bot.reply_to(m, f"❌ {result}")
        elif cmd == "alerts":
            with suricata_lock:
                if not suricata_alerts:
                    bot.reply_to(m, "📋 *Suricata Alerts*\nNo alerts recorded yet.\nMake sure Suricata is installed and logging to `/var/log/suricata/fast.log`", parse_mode="Markdown")
                else:
                    lines = ["📋 *Recent Suricata Alerts*", f"Total: {len(suricata_alerts)} alerts\n"]
                    for a in reversed(suricata_alerts[-10:]):
                        t = a["time"].strftime("%H:%M:%S")
                        lines.append(f"`{t}` {a['line'][:80]}")
                    bot.reply_to(m, "\n".join(lines), parse_mode="Markdown")
    except Exception as e:
        log.error(f"cmd_handler({cmd}): {e}")
        bot.reply_to(m, f"❌ Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# CATCH-ALL: auto-detect IP / domain
# ═══════════════════════════════════════════════════════════════════════════════

@bot.message_handler(func=lambda m: True, content_types=["text"])
def auto_threat_hunt(m):
    global ALERT_CHAT_ID
    with ALERT_LOCK: ALERT_CHAT_ID = m.chat.id
    text = m.text.strip()
    if text.startswith("/"): return

    ip_match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", text)
    if ip_match and all(0 <= int(g) <= 255 for g in ip_match.groups()):
        bot.reply_to(m, f"🎯 *IP detected:* `{text}`\nRunning threat hunt...", parse_mode="Markdown")
        bot.reply_to(m, threat_hunt_ip(text), parse_mode="Markdown")
        return

    if "." in text and not text.startswith(".") and not text.endswith(".") and " " not in text and len(text) > 3:
        bot.reply_to(m, f"🌐 *Domain detected:* `{text}`\nRunning recon...", parse_mode="Markdown")
        bot.reply_to(m, threat_hunt_domain(text), parse_mode="Markdown")
        return


# ═══════════════════════════════════════════════════════════════════════════════
# CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

@bot.callback_query_handler(func=lambda call: call.data.startswith("h_"))
def handle_callback(call):
    cmd = call.data[2:]
    cid = call.message.chat.id
    log.info(f"Callback: data={call.data!r}, cmd={cmd!r}")
    try:
        bot.answer_callback_query(call.id)
    except Exception as e:
        log.warning(f"answer_callback_query failed: {e}")

    try:
        # ── IP / Domain ──
        if cmd == "ip":
            msg = bot.send_message(cid, "🎯 *Enter an IP address:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_ip_hunt)
        elif cmd == "domain":
            msg = bot.send_message(cid, "🌐 *Enter a domain:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_domain_hunt)

        # ── Scan ──
        elif cmd == "scan_common":
            msg = bot.send_message(cid, "⚡ *Enter target:* (Fast — 23 ports)", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_scan_fast)
        elif cmd == "scan_all":
            msg = bot.send_message(cid, "🔍 *Enter target:* (Full — all ports, ~5-10 min)", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_scan_full)

        # ── Logs ──
        elif cmd == "logs_menu":
            kb = InlineKeyboardMarkup(row_width=2)
            kb.add(InlineKeyboardButton("🚫 Failed", callback_data="h_logs_failed"), InlineKeyboardButton("👤 Sudo", callback_data="h_logs_sudo"))
            kb.add(InlineKeyboardButton("🔐 SSH", callback_data="h_logs_ssh"), InlineKeyboardButton("🛡 Attackers", callback_data="h_logs_attack"))
            kb.add(InlineKeyboardButton("🔙 Menu", callback_data="h_menu"))
            bot.send_message(cid, "📊 *Choose log filter:*", parse_mode="Markdown", reply_markup=kb)
        elif cmd.startswith("logs_"):
            ftype = cmd.replace("logs_", "")
            bot.send_message(cid, analyze_logs(ftype), parse_mode="Markdown")

        # ── FIM ──
        elif cmd == "fim":
            kb = InlineKeyboardMarkup(row_width=2)
            kb.add(InlineKeyboardButton("➕ Add File", callback_data="h_fim_add"), InlineKeyboardButton("🔍 Check All", callback_data="h_fim_check"))
            kb.add(InlineKeyboardButton("🔙 Menu", callback_data="h_menu"))
            bot.send_message(cid, "📋 *File Integrity Monitor*", parse_mode="Markdown", reply_markup=kb)
        elif cmd == "fim_add":
            msg = bot.send_message(cid, "📋 *Enter file path:*\nExample: `/etc/passwd`", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_fim_add)
        elif cmd == "fim_check":
            bot.send_message(cid, fim_check(), parse_mode="Markdown")

        # ── Security checks ──
        elif cmd == "cve":
            msg = bot.send_message(cid, "🧠 *Enter package name:*\nExample: `openssl`", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_cve)
        elif cmd == "hibp":
            msg = bot.send_message(cid, "🔐 *Enter email or domain:*", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_hibp)
        elif cmd == "mitre":
            msg = bot.send_message(cid, "🧬 *Enter MITRE technique ID:*\nExample: `T1059`", parse_mode="Markdown")
            bot.register_next_step_handler(msg, process_mitre)

        # ── System ──
        elif cmd == "status": bot.send_message(cid, format_status(), parse_mode="Markdown")
        elif cmd == "top": bot.send_message(cid, format_top(), parse_mode="Markdown")
        elif cmd == "audit": bot.send_message(cid, format_audit(), parse_mode="Markdown")

        # ── Report / Alerts ──
        elif cmd == "report":
            bot.send_message(cid, "📄 *Generating PDF report...*")
            result = generate_report()
            if isinstance(result, str) and result.startswith("/tmp"):
                with open(result, "rb") as f: bot.send_document(cid, f, caption="📄 Cyber-Volt SOC Report")
            else: bot.send_message(cid, f"❌ {result}")
        elif cmd == "alerts":
            with suricata_lock:
                if not suricata_alerts:
                    bot.send_message(cid, "📋 *Suricata Alerts*\nNo alerts yet. Suricata must be installed first.", parse_mode="Markdown")
                else:
                    lines = ["📋 *Recent Suricata Alerts*\n"]
                    for a in reversed(suricata_alerts[-15:]):
                        t = a["time"].strftime("%H:%M:%S")
                        lines.append(f"`{t}` {a['line'][:100]}")
                    bot.send_message(cid, "\n".join(lines), parse_mode="Markdown")

        # ── Menu / Hello / Help ──
        elif cmd == "menu": bot.send_message(cid, menu_text(), parse_mode="Markdown", reply_markup=help_keyboard())
        elif cmd == "hello": cmd_hello(call.message)
        elif cmd == "help": cmd_help(call.message)

    except Exception as e:
        log.error(f"callback error ({cmd}): {e}")
        try: bot.send_message(cid, f"❌ Error: {e}")
        except: pass


# ═══════════════════════════════════════════════════════════════════════════════
# STEP HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

def process_ip_hunt(m):
    with ALERT_LOCK: global ALERT_CHAT_ID; ALERT_CHAT_ID = m.chat.id
    ip = m.text.strip()
    if not ip: bot.reply_to(m, "❌ No IP entered."); return
    bot.reply_to(m, f"🎯 *Threat Hunting `{ip}`...*", parse_mode="Markdown")
    bot.reply_to(m, threat_hunt_ip(ip), parse_mode="Markdown")

def process_domain_hunt(m):
    with ALERT_LOCK: global ALERT_CHAT_ID; ALERT_CHAT_ID = m.chat.id
    text = m.text.strip()
    if not text: bot.reply_to(m, "❌ Nothing entered."); return
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", text):
        bot.reply_to(m, f"🎯 *Threat Hunting `{text}`...*", parse_mode="Markdown")
        bot.reply_to(m, threat_hunt_ip(text), parse_mode="Markdown")
        return
    bot.reply_to(m, f"🌐 *Recon `{text}`...*", parse_mode="Markdown")
    bot.reply_to(m, threat_hunt_domain(text), parse_mode="Markdown")

def process_scan_fast(m):
    t = m.text.strip()
    if not t: bot.reply_to(m, "❌ No target entered."); return
    bot.reply_to(m, f"⚡ *Fast scan `{t}`...*", parse_mode="Markdown")
    bot.reply_to(m, scan_network(t, all_ports=False), parse_mode="Markdown")

def process_scan_full(m):
    t = m.text.strip()
    if not t: bot.reply_to(m, "❌ No target entered."); return
    bot.reply_to(m, f"🔍 *Full scan `{t}`...* ~5-10 min ⏳", parse_mode="Markdown")
    bot.reply_to(m, scan_network(t, all_ports=True), parse_mode="Markdown")

def process_fim_add(m):
    p = m.text.strip()
    if not p: bot.reply_to(m, "❌ No path entered."); return
    bot.reply_to(m, fim_add(p), parse_mode="Markdown")

def process_cve(m):
    p = m.text.strip()
    if not p: bot.reply_to(m, "❌ No package entered."); return
    bot.reply_to(m, f"🧠 *Checking CVE for `{p}`...*", parse_mode="Markdown")
    bot.reply_to(m, check_cve(p), parse_mode="Markdown")

def process_hibp(m):
    e = m.text.strip()
    if not e: bot.reply_to(m, "❌ No email entered."); return
    bot.reply_to(m, f"🔐 *Checking `{e}`...*\n💡 Tip: use `name:BreachName` for details", parse_mode="Markdown")
    bot.reply_to(m, check_hibp(e), parse_mode="Markdown")

def process_mitre(m):
    t = m.text.strip()
    if not t: bot.reply_to(m, "❌ No technique ID entered."); return
    bot.reply_to(m, f"🧬 *Looking up `{t}` in MITRE...*", parse_mode="Markdown")
    bot.reply_to(m, mitre_lookup(t), parse_mode="Markdown")

def process_whois(m):
    d = m.text.strip()
    if d: bot.reply_to(m, get_whois(d), parse_mode="Markdown")
    else: bot.reply_to(m, "❌ No domain entered.")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # ── PID guard ──
    try:
        with open(PID_FILE, "x") as f: f.write(str(os.getpid()))
    except FileExistsError:
        try:
            with open(PID_FILE) as f: old = int(f.read().strip())
            try:
                os.kill(old, 0)
                log.warning(f"Bot already running (PID {old}), exiting")
                sys.exit(0)
            except OSError: pass
            os.remove(PID_FILE)
            with open(PID_FILE, "w") as f: f.write(str(os.getpid()))
        except (ValueError, OSError): pass

    import atexit
    def cleanup():
        try:
            if os.path.exists(PID_FILE): os.remove(PID_FILE)
        except: pass
    atexit.register(cleanup)

    # ── Webhook cleanup ──
    log.info("Cleaning up stale sessions...")
    for attempt in range(5):
        try:
            bot.remove_webhook()
            log.info(f"Webhook removed (attempt {attempt+1})")
            break
        except Exception as e:
            log.warning(f"remove_webhook error: {e}")
            time.sleep(3)

    # ── Set BotFather commands ──
    try:
        from telebot.types import BotCommand
        cmds = [
            BotCommand("start", "🤖 Start the bot / greeting"),
            BotCommand("help", "📖 Open menu with all functions"),
            BotCommand("status", "🖥 System dashboard (CPU/RAM/Disk)"),
            BotCommand("top", "📊 Top processes by CPU/RAM"),
            BotCommand("logs", "📜 Log analysis (failed/sudo/ssh/attack)"),
            BotCommand("audit", "🛡 BSI Compliance Audit"),
            BotCommand("scan", "🕸 Network scan (fast / full)"),
            BotCommand("whois", "🏢 WHOIS lookup by domain"),
            BotCommand("recon", "🌐 Domain / IP reconnaissance"),
            BotCommand("fim", "📋 File Integrity Monitor (add/check)"),
            BotCommand("cve", "🧠 CVE vulnerability check for package"),
            BotCommand("hibp", "🔐 Breach search (email/domain)"),
            BotCommand("mitre", "🧬 MITRE ATT&CK technique search"),
            BotCommand("report", "📄 Generate PDF report"),
            BotCommand("alerts", "🚨 View Suricata IDS alerts"),
        ]
        bot.set_my_commands(cmds)
        log.info(f"Set {len(cmds)} BotFather commands")
    except Exception as e:
        log.warning(f"Failed to set BotFather commands: {e}")

    time.sleep(5)
    log.info("Starting custom polling loop")

    # ── Custom polling loop ──
    offset = 0
    while True:
        try:
            updates = bot.get_updates(
                offset=offset,
                timeout=30,
                allowed_updates=["message", "callback_query", "edited_message"],
            )
            for update in updates:
                offset = update.update_id + 1

                if update.message:
                    msg = update.message
                    handled = False

                    # Check next_step_handlers (FIM, CVE, HIBP prompts etc.)
                    handlers = bot.next_step_backend.get_handlers(msg.chat.id)
                    if handlers:
                        for handler in handlers:
                            try:
                                log.info(f"Next-step handler: {handler['callback'].__name__}")
                                handler['callback'](msg, *handler['args'], **handler['kwargs'])
                                handled = True
                            except Exception as e:
                                log.error(f"next_step handler error: {e}")

                    if not handled:
                        for handler in bot.message_handlers:
                            try:
                                if bot._test_message_handler(handler, msg):
                                    handler['function'](msg)
                                    handled = True
                                    break
                            except Exception as e:
                                log.error(f"msg handler error: {e}")
                    if not handled:
                        log.debug(f"Unhandled message: {msg.text[:50] if msg.text else '(no text)'}")

                if update.callback_query:
                    cq = update.callback_query
                    log.info(f"CALLBACK: data={cq.data!r}, from={cq.from_user.id}")
                    handled = False
                    for handler in bot.callback_query_handlers:
                        try:
                            if bot._test_message_handler(handler, cq):
                                log.info(f"Handler matched: {handler['function'].__name__}")
                                handler['function'](cq)
                                handled = True
                                break
                        except Exception as e:
                            log.error(f"callback handler error: {e}")
                    if not handled:
                        log.warning(f"Unhandled callback: {cq.data!r}")
                        try:
                            bot.answer_callback_query(cq.id, text="❌ Function temporarily unavailable")
                        except: pass

        except telebot.apihelper.ApiTelegramException as e:
            if "409" in str(e):
                log.warning("409 Conflict — retrying in 30s")
                time.sleep(30)
            elif "429" in str(e):
                log.warning("429 Rate limited — retrying in 30s")
                time.sleep(30)
            else:
                log.error(f"API error: {e}")
                time.sleep(10)
        except Exception as e:
            log.error(f"Polling error: {type(e).__name__}: {e}")
            time.sleep(10)
