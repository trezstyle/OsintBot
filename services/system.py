"""System status, audit, log-analysis, and CVE helpers."""
import os
import re
import shutil
import subprocess
import time
import logging
from collections import defaultdict
from datetime import timedelta

import psutil
import requests

from config import settings

log = logging.getLogger("cyber_volt")


def auth_log_lines():
    try:
        with open(settings.paths.auth_log_file, "r", errors="ignore") as f:
            return f.read().splitlines()
    except OSError:
        return []


def tail_auth_matches(pattern, limit):
    matches = [line for line in auth_log_lines() if pattern in line]
    return "\n".join(matches[-limit:])


def failed_login_count():
    return sum(1 for line in auth_log_lines() if "Failed password" in line)


def recent_failed_logins(limit):
    return tail_auth_matches("Failed password", limit)

def format_top():
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,pcpu,pmem,rss,args", "--sort=-pcpu", "--no-headers"],
            capture_output=True, text=True, timeout=5, check=False
        )
        raw = result.stdout.strip().split("\n")[:8]

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
        usage = shutil.disk_usage(settings.paths.root_path)
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
        if settings.paths.sshd_config_file.exists():
            cfg = settings.paths.sshd_config_file.read_text(errors="ignore")
            checks.append(("🔐 Root SSH", "✅ DISABLED" if "PermitRootLogin no" in cfg else "❌ ENABLED"))
        fw_status = subprocess.run(
            ["ufw", "status"], capture_output=True, text=True, timeout=5, check=False
        )
        fw = "Status: active" in fw_status.stdout
        checks.append(("🛡 Firewall", "✅ ACTIVE" if fw else "❌ INACTIVE"))
        try:
            ss = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=5, check=False
            ).stdout.splitlines()
            ports = sorted({
                m.group(1)
                for line in ss
                if "LISTEN" in line
                for m in [re.search(r":(\d+)\b", line.split()[3] if len(line.split()) > 3 else "")]
                if m
            }, key=lambda p: int(p))[:5]
            checks.append(("🔌 Open Ports", f"`{', '.join(ports)}`" if ports else "None"))
        except:
            checks.append(("🔌 Open Ports", "N/A"))
        try:
            checks.append(("🚫 Failed Logins", f"{failed_login_count()} total"))
        except:
            checks.append(("🚫 Failed Logins", "N/A"))
        uptime_str = subprocess.run(
            ["uptime", "-p"], capture_output=True, text=True, timeout=5, check=False
        ).stdout.strip().replace("up ", "")
        checks.append(("⏱ Uptime", uptime_str))
        u = shutil.disk_usage(settings.paths.root_path)
        checks.append(("💾 Disk Usage", f"{u.used/u.total*100:.1f}%"))
        m = psutil.virtual_memory()
        checks.append(("🧠 Memory", f"{m.percent:.1f}%"))
        load = os.getloadavg()
        checks.append(("📈 Load Avg", f"{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}"))
        try:
            failed_out = subprocess.run(
                ["systemctl", "--failed", "--no-legend"],
                capture_output=True, text=True, timeout=5, check=False
            ).stdout
            failed = len([line for line in failed_out.splitlines() if line.strip()])
            checks.append(("⚙ Failed Svcs", str(failed)))
        except:
            checks.append(("⚙ Failed Svcs", "N/A"))
        lines = ["🛡 *BSI Compliance Audit*\n"]
        lines += [f"• {icon}: {status}" for icon, status in checks]
        return "\n".join(lines)
    except Exception as e:
        return f"Audit failed: {e}"
def analyze_logs(filter_type):
    path = str(settings.paths.auth_log_file)
    if not os.path.exists(path):
        return "Log file not found."
    try:
        headers = {
            "failed": "🚫 *Failed Logins (last 15)*",
            "sudo": "👤 *Sudo Events (last 15)*",
            "ssh": "🔐 *SSH Events (last 15)*",
            "attack": "🛡 *Top Attackers (by failed logins)*",
        }
        if filter_type not in headers:
            return "Usage: /logs [failed|sudo|ssh|attack]"
        header = headers[filter_type]
        lines = auth_log_lines()
        if filter_type == "attack":
            counts = defaultdict(int)
            for line in lines:
                if "Failed password" not in line:
                    continue
                m = re.search(r"from (\S+)", line)
                if m:
                    counts[m.group(1)] += 1
            out = "\n".join(f"{count:7d} {ip}" for ip, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10])
        else:
            patterns = {"failed": "Failed password", "sudo": "sudo", "ssh": "sshd"}
            out = "\n".join([line for line in lines if patterns[filter_type] in line][-15:])
        if not out.strip():
            return f"{header}\nNo entries found."
        return f"{header}\n```\n{out.strip()}\n```"
    except Exception as e:
        return f"Log analysis failed: {e}"
def check_cve(pkg):
    """Check CVEs for a package. Package name is validated before shell access."""
    from security import validate_package_name

    safe_pkg = validate_package_name(pkg)
    if not safe_pkg:
        return f"❌ Invalid package name: `{pkg}`\nMust be a valid Debian package name."

    try:
        ver = "unknown"
        try:
            # Safe: subprocess with arg list, validated package name
            dpkg_out = subprocess.run(
                ["dpkg", "-l", safe_pkg],
                capture_output=True, text=True, timeout=5
            ).stdout.strip()
            lines = [l for l in dpkg_out.split("\n") if l.strip()]
            if lines:
                parts = lines[-1].split()
                if len(parts) >= 3:
                    ver = parts[2]
        except: pass

        if ver == "unknown":
            try:
                which_out = subprocess.run(
                    ["which", safe_pkg],
                    capture_output=True, text=True, timeout=3
                ).stdout.strip()
                if which_out:
                    ver_out = subprocess.run(
                        [safe_pkg, "--version"],
                        capture_output=True, text=True, timeout=5
                    ).stdout.strip().split("\n")[0]
                    if ver_out:
                        ver = ver_out.strip()
            except: pass

        # NVD API call - safe, URL params are validated package name
        import urllib.parse
        safe_query = urllib.parse.quote(safe_pkg)
        r = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={safe_query}&resultsPerPage=5",
            timeout=15
        )
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
