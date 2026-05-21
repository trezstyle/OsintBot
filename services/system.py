import os
from pathlib import Path
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
from services.rate_limit import RateLimiter

log = logging.getLogger("cyber_volt")

_TTL_CACHE_MAX = 256
_TTL_CACHE: dict[str, tuple[float, object]] = {}

_AUTH_LOG_CACHE: tuple[float, list[str]] | None = None
_AUTH_LOG_CACHE_TTL = 2.0


def _cached(key: str, ttl: float, fn):
    now = time.monotonic()
    if len(_TTL_CACHE) > _TTL_CACHE_MAX:
        expired = [k for k, (t, _) in _TTL_CACHE.items() if now - t >= ttl]
        if expired:
            for k in expired:
                del _TTL_CACHE[k]
        else:
            oldest = sorted(_TTL_CACHE.items(), key=lambda x: x[1][0])[:len(_TTL_CACHE) // 2]
            for k, _ in oldest:
                del _TTL_CACHE[k]
    entry = _TTL_CACHE.get(key)
    if entry and now - entry[0] < ttl:
        return entry[1]
    val = fn()
    _TTL_CACHE[key] = (now, val)
    return val


def _tail_file(path: str, n: int) -> list[str]:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return []
            chunk_size = min(size, 4096 * n)
            f.seek(-chunk_size, 2)
            data = f.read(chunk_size).decode(errors="ignore")
            lines = data.splitlines()
            if len(lines) > n:
                lines = lines[-n:]
            return lines
    except OSError as exc:
        log.debug("Cannot tail %s: %s", path, exc)
        return []


def auth_log_lines() -> list[str]:
    global _AUTH_LOG_CACHE
    now = time.monotonic()
    if _AUTH_LOG_CACHE and now - _AUTH_LOG_CACHE[0] < _AUTH_LOG_CACHE_TTL:
        return _AUTH_LOG_CACHE[1]
    try:
        with open(settings.paths.auth_log_file, "r", errors="ignore") as f:
            lines = f.read().splitlines()
        _AUTH_LOG_CACHE = (now, lines)
        return lines
    except OSError:
        return []


def tail_auth_matches(pattern, limit):
    lines = _tail_file(str(settings.paths.auth_log_file), limit * 10)
    matches = [line for line in lines if pattern in line]
    return "\n".join(matches[-limit:])


def failed_login_count():
    lines = _tail_file(str(settings.paths.auth_log_file), 5000)
    return sum(1 for line in lines if "Failed password" in line)


def recent_failed_logins(limit):
    return tail_auth_matches("Failed password", limit)


def _parse_processes(raw_lines, limit=12):
    parsed = []
    for line in raw_lines:
        parts = line.split(maxsplit=4)
        if len(parts) >= 5:
            pid, cpu, mem_p, rss, cmd = parts
            try:
                parsed.append({
                    "pid": int(pid),
                    "cpu": float(cpu),
                    "mem": float(mem_p),
                    "rss": int(rss),
                    "cmd": cmd.strip(),
                })
            except (ValueError, IndexError):
                continue
    return parsed[:limit]


def _score_emoji(pct):
    return "🔴" if pct >= 50 else "🟡" if pct >= 20 else "🟢"


def _bar(value, width=10):
    filled = int(value / 100 * width)
    return "█" * filled + "░" * (width - filled)


def _fmt_rss(kb):
    if kb >= 1048576:
        return f"{kb / 1048576:.1f}G"
    if kb >= 1024:
        return f"{kb / 1024:.0f}M"
    return f"{kb}K"


SORT_FIELDS = {
    "cpu": ("cpu", True),
    "ram": ("mem", True),
    "pid": ("pid", False),
    "name": ("cmd", False),
}


def format_top(sort_by="cpu"):
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,pcpu,pmem,rss,args", "--sort=-pcpu", "--no-headers"],
            capture_output=True, text=True, timeout=5, check=False
        )
        all_lines = result.stdout.strip().split("\n")
        parsed = _parse_processes(all_lines)

        total_cpu = psutil.cpu_percent(interval=0.3)
        mem = psutil.virtual_memory()
        load = os.getloadavg()
        total_procs = len(psutil.pids())

        key, reverse = SORT_FIELDS.get(sort_by, ("cpu", True))
        parsed.sort(key=lambda p: p[key], reverse=reverse)

        W = 36
        cpu_inner = f" CPU {_bar(total_cpu)}  {total_cpu:>5.1f}% "
        ram_inner = f" RAM {_bar(mem.percent)}  {mem.percent:>5.1f}% "
        load_inner = f" Load {load[0]:.2f} · Procs {total_procs} "
        header = (
            f"📊 *Top Processes*\n"
            f"┌{'─' * W}┐\n"
            f"│{cpu_inner:<{W}}│\n"
            f"│{ram_inner:<{W}}│\n"
            f"│{load_inner:<{W}}│\n"
            f"└{'─' * W}┘\n"
        )

        rows = []
        for p in parsed:
            emoji = _score_emoji(p["cpu"])
            rss_fmt = _fmt_rss(p["rss"])
            cmd = p["cmd"][:40]
            rows.append(
                f"{emoji} `{p['pid']:>6}`   {p['cpu']:>5.1f}%   {p['mem']:>5.1f}% "
                f"`{rss_fmt:>5}`  {cmd}"
            )

        sort_labels = {"cpu": "CPU ⬇", "ram": "RAM", "pid": "PID", "name": "Name"}
        sort_line = "Sort: " + " · ".join(
            f"*{label}*" if k == sort_by else label
            for k, label in sort_labels.items()
        )

        return header + "\n".join(rows) + "\n\n" + sort_line
    except Exception as e:
        log.error("format_top error: %s", e)
        return f"Top failed: {e}"


def format_status():
    return _cached("format_status", 2.0, _format_status_impl)


def _format_status_impl():
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        usage = shutil.disk_usage(settings.paths.root_path)
        disk_pct = (usage.used / usage.total) * 100 if usage.total else 0
        load = os.getloadavg()
        net = psutil.net_io_counters()
        uptime_sec = time.time() - psutil.boot_time()
        uptime_str = str(timedelta(seconds=int(uptime_sec))).split(".")[0]
        procs = len(psutil.pids())
        swap = psutil.swap_memory()

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
            f"║  {cpu_e} CPU:  {_bar(cpu)}  {cpu:>5.1f}%            ║",
            f"║  {mem_e} RAM:  {_bar(mem.percent)}  {mem.percent:>5.1f}%           ║",
            f"║         Used: {mem.used//1024//1024}MB / Total: {mem.total//1024//1024}MB     ║",
            f"║  {disk_e} DISK: {_bar(disk_pct)}  {disk_pct:>5.1f}%           ║",
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

        if filter_type == "attack":
            lines = _tail_file(path, 5000)
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
            lines = _tail_file(path, 200)
            out = "\n".join([line for line in lines if patterns[filter_type] in line][-15:])
        if not out.strip():
            return f"{header}\nNo entries found."
        return f"{header}\n```\n{out.strip()}\n```"
    except Exception as e:
        return f"Log analysis failed: {e}"


_nvd_limiter = RateLimiter(max_calls=5, window_seconds=60)


def check_cve(pkg):
    from security import validate_package_name

    safe_pkg = validate_package_name(pkg)
    if not safe_pkg:
        return f"❌ Invalid package name: `{pkg}`\nMust be a valid Debian package name."

    try:
        ver = "unknown"
        try:
            dpkg_out = subprocess.run(
                ["dpkg-query", "-W", "-f=${Version}", safe_pkg],
                capture_output=True, text=True, timeout=5
            ).stdout.strip()
            if dpkg_out:
                ver = dpkg_out
        except Exception:
            pass

        import urllib.parse
        if not _nvd_limiter.is_allowed(0):
            return "⚠ Rate limited: NVD API allows ~5 requests/min. Wait and retry."
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


def format_speed(bytes_per_sec):
    try:
        if bytes_per_sec >= 1024 * 1024:
            return f"{bytes_per_sec / 1024 / 1024:.2f} MB/s"
        return f"{bytes_per_sec / 1024:.1f} KB/s"
    except Exception:
        return "N/A"


def format_bandwidth():
    return _cached("format_bandwidth", 5.0, _format_bandwidth_impl)


def _format_bandwidth_impl():
    try:
        counters = psutil.net_io_counters(pernic=True)
        time.sleep(1)
        counters2 = psutil.net_io_counters(pernic=True)

        def total_fmt(value):
            if value >= 1024 * 1024 * 1024:
                return f"{value / 1024 / 1024 / 1024:.2f} GB"
            return f"{value / 1024 / 1024:.1f} MB"

        lines = ["🌐 *Network Bandwidth*"]
        for iface, before in counters.items():
            after = counters2.get(iface)
            if not after:
                continue
            rx_rate = after.bytes_recv - before.bytes_recv
            tx_rate = after.bytes_sent - before.bytes_sent
            if after.bytes_recv == 0 and after.bytes_sent == 0:
                continue
            if rx_rate == 0 and tx_rate == 0 and after.bytes_recv < 1024 and after.bytes_sent < 1024:
                continue
            lines.append(
                f"\n*{iface}*\n"
                f"↓ `{format_speed(rx_rate)}`  ↑ `{format_speed(tx_rate)}`\n"
                f"RX: `{total_fmt(after.bytes_recv)}`  TX: `{total_fmt(after.bytes_sent)}`"
            )
        if len(lines) == 1:
            lines.append("No active interfaces found.")
        return "\n".join(lines)
    except Exception as e:
        log.error("format_bandwidth error: %s", e)
        return f"Bandwidth check failed: {e}"


def _run_cmd(args, timeout=5):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def _ufw_installed() -> bool:
    return bool(shutil.which("ufw")) or any(Path(p).exists() for p in ("/usr/sbin/ufw", "/sbin/ufw"))


_VALID_UFW_ACTIONS = frozenset({"allow", "deny", "delete"})


def format_firewall(action: str = None, args: str = None) -> str:
    action = (action or "status").strip().lower()
    args = (args or "").strip()
    if not _ufw_installed():
        return "❌ UFW not found. Install with: `apt install ufw`"
    try:
        if action in ("", "status"):
            result = _run_cmd(["ufw", "status", "numbered"], timeout=5)
            output = (result.stdout or result.stderr or "No ufw output.").strip()
            return f"🛡 *Firewall Status*\n```\n{output}\n```"

        if action == "confirm":
            parts = args.split(maxsplit=1)
            if not parts:
                return "Usage: `/fw confirm allow 22/tcp` or `/fw confirm deny 1.2.3.4`"
            real_action = parts[0].lower()
            real_arg = parts[1].strip() if len(parts) > 1 else ""
            if real_action not in _VALID_UFW_ACTIONS or not real_arg:
                return "Usage: `/fw confirm [allow|deny|delete] <port|ip|rule>`"

            active_status = _run_cmd(["ufw", "status"], timeout=5)
            active = "Status: active" in active_status.stdout
            result = _run_cmd(["ufw", "--force", real_action, real_arg], timeout=10)
            output = (result.stdout or result.stderr or "No ufw output.").strip()
            prefix = "✅" if result.returncode == 0 else "🔴"
            inactive_note = "\n⚠️ UFW was not active before this command." if not active else ""
            return (
                f"{prefix} *Firewall command executed*\n"
                f"`ufw {real_action} {real_arg}`{inactive_note}\n"
                f"```\n{output}\n```"
            )

        if action in _VALID_UFW_ACTIONS:
            if not args:
                return f"Usage: `/fw {action} <port|ip|rule>`"
            return (
                "⚠️ *WARNING: Firewall modification requested*\n"
                f"`ufw {action} {args}`\n"
                f"To confirm, use: `/fw confirm {action} {args}`"
            )

        return "Usage: `/fw [status|allow|deny|delete|confirm] [args]`"
    except Exception as e:
        log.error("format_firewall(%s, %s) error: %s", action, args, e)
        return f"Firewall manager failed: {e}"


def _read_file(path):
    try:
        return Path(path).read_text(errors="ignore")
    except Exception:
        return ""


def _ssh_effective_value(config, key):
    value = None
    pattern = re.compile(rf"^\s*{re.escape(key)}\s+(\S+)", re.IGNORECASE)
    for line in config.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = pattern.match(line)
        if match:
            value = match.group(1)
    return value


def _compliance_status(ok, name, detail="", warn=False):
    if warn:
        return ("WARN", name, detail)
    return ("PASS" if ok else "FAIL", name, detail)


def format_compliance() -> str:
    try:
        checks = []
        ssh_cfg = _read_file(settings.paths.sshd_config_file)

        try:
            root_login = (_ssh_effective_value(ssh_cfg, "PermitRootLogin") or "").lower()
            checks.append(_compliance_status(root_login in ("no", "prohibit-password"), "Root SSH login", root_login or "default"))
        except Exception as e:
            checks.append(_compliance_status(False, "Root SSH login", str(e), warn=True))

        try:
            protocol = _ssh_effective_value(ssh_cfg, "Protocol")
            checks.append(_compliance_status(protocol in (None, "2"), "SSH protocol", protocol or "default 2"))
        except Exception as e:
            checks.append(_compliance_status(False, "SSH protocol", str(e), warn=True))

        try:
            login_defs = _read_file("/etc/login.defs")
            max_days = None
            for line in login_defs.splitlines():
                if line.strip().startswith("PASS_MAX_DAYS"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        max_days = int(parts[1])
            checks.append(_compliance_status(max_days is not None and max_days <= 90, "Password expiration", f"PASS_MAX_DAYS={max_days or 'unset'}"))
        except Exception as e:
            checks.append(_compliance_status(False, "Password expiration", str(e), warn=True))

        try:
            common_password = _read_file("/etc/pam.d/common-password")
            login_defs = _read_file("/etc/login.defs")
            minlen_values = [int(m.group(1)) for m in re.finditer(r"minlen=(\d+)", common_password)]
            pass_min_len = None
            for line in login_defs.splitlines():
                if line.strip().startswith("PASS_MIN_LEN"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        pass_min_len = int(parts[1])
            ok = any(v >= 8 for v in minlen_values) or pass_min_len is None or pass_min_len >= 8
            detail = f"minlen={max(minlen_values) if minlen_values else 'unset'}, PASS_MIN_LEN={pass_min_len or 'unset'}"
            checks.append(_compliance_status(ok, "Min password length", detail))
        except Exception as e:
            checks.append(_compliance_status(False, "Min password length", str(e), warn=True))

        try:
            ufw = _run_cmd(["ufw", "status"], timeout=5).stdout
            checks.append(_compliance_status("Status: active" in ufw, "UFW firewall", "active" if "Status: active" in ufw else "inactive"))
        except Exception as e:
            checks.append(_compliance_status(False, "UFW firewall", str(e), warn=True))

        try:
            expected_ports = {"22", "80", "443", "51820"}
            ss = _run_cmd(["ss", "-tuln"], timeout=5).stdout.splitlines()
            open_ports = set()
            for line in ss:
                if "LISTEN" not in line and "udp" not in line.lower():
                    continue
                parts = line.split()
                local = parts[4] if len(parts) > 4 else ""
                match = re.search(r":(\d+)$", local)
                if match:
                    open_ports.add(match.group(1))
            unexpected = sorted(open_ports - expected_ports, key=int)
            checks.append(_compliance_status(not unexpected, "Open ports", f"unexpected={', '.join(unexpected) if unexpected else 'none'}"))
        except Exception as e:
            checks.append(_compliance_status(False, "Open ports", str(e), warn=True))

        try:
            lines = _tail_file(str(settings.paths.auth_log_file), 500)
            failed = sum(1 for line in lines if "Failed password" in line)
            checks.append(_compliance_status(failed == 0, "Failed logins", f"{failed} in recent log entries", warn=failed > 0))
        except Exception as e:
            checks.append(_compliance_status(False, "Failed logins", str(e), warn=True))

        try:
            import resource
            limits = _read_file("/etc/security/limits.conf")
            core_soft, _ = resource.getrlimit(resource.RLIMIT_CORE)
            core_limit = "unlimited" if core_soft == resource.RLIM_INFINITY else str(core_soft)
            limits_ok = any(re.match(r"\*\s+hard\s+core\s+0\b", line.strip()) for line in limits.splitlines() if not line.strip().startswith("#"))
            checks.append(_compliance_status(limits_ok or core_limit == "0", "Core dumps", f"ulimit={core_limit or 'unknown'}"))
        except Exception as e:
            checks.append(_compliance_status(False, "Core dumps", str(e), warn=True))

        try:
            ip_forward = _run_cmd(["sysctl", "-n", "net.ipv4.ip_forward"], timeout=5).stdout.strip()
            checks.append(_compliance_status(ip_forward == "0", "IP forwarding disabled", f"net.ipv4.ip_forward={ip_forward or 'unknown'}"))
        except Exception as e:
            checks.append(_compliance_status(False, "IP forwarding disabled", str(e), warn=True))

        try:
            mounts = _read_file("/proc/mounts")
            tmp_line = next((line for line in mounts.splitlines() if " /tmp " in line), "")
            noexec = "noexec" in tmp_line.split()[3].split(",") if tmp_line else False
            checks.append(_compliance_status(noexec, "/tmp noexec", "noexec" if noexec else "not set"))
        except Exception as e:
            checks.append(_compliance_status(False, "/tmp noexec", str(e), warn=True))

        try:
            apparmor_enabled = _read_file("/sys/module/apparmor/parameters/enabled").strip().upper()
            if not apparmor_enabled:
                aa = _run_cmd(["aa-status"], timeout=5)
                apparmor_enabled = "Y" if aa.returncode == 0 else "N"
            checks.append(_compliance_status(apparmor_enabled.startswith("Y"), "AppArmor enabled", apparmor_enabled or "unknown"))
        except Exception as e:
            checks.append(_compliance_status(False, "AppArmor enabled", str(e), warn=True))

        try:
            active = _run_cmd(["systemctl", "is-active", "auditd"], timeout=5).stdout.strip()
            installed = shutil.which("auditd") or Path("/sbin/auditd").exists() or Path("/usr/sbin/auditd").exists()
            checks.append(_compliance_status(installed and active == "active", "Auditd installed and running", f"installed={bool(installed)}, active={active or 'unknown'}"))
        except Exception as e:
            checks.append(_compliance_status(False, "Auditd installed and running", str(e), warn=True))

        try:
            syncookies = _run_cmd(["sysctl", "-n", "net.ipv4.tcp_syncookies"], timeout=5).stdout.strip()
            checks.append(_compliance_status(syncookies == "1", "Kernel hardening", f"tcp_syncookies={syncookies or 'unknown'}"))
        except Exception as e:
            checks.append(_compliance_status(False, "Kernel hardening", str(e), warn=True))

        try:
            passwd = _read_file("/etc/passwd")
            risky = []
            for line in passwd.splitlines():
                parts = line.split(":")
                if len(parts) >= 7 and parts[0] in {"games", "nobody"}:
                    shell = parts[6]
                    if shell not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}:
                        risky.append(parts[0])
            checks.append(_compliance_status(not risky, "Unnecessary accounts", f"shell access={', '.join(risky) if risky else 'none'}"))
        except Exception as e:
            checks.append(_compliance_status(False, "Unnecessary accounts", str(e), warn=True))

        try:
            max_auth = _ssh_effective_value(ssh_cfg, "MaxAuthTries")
            max_auth_int = int(max_auth) if max_auth and max_auth.isdigit() else 6
            checks.append(_compliance_status(max_auth_int <= 4, "SSH max auth tries", f"MaxAuthTries={max_auth_int}"))
        except Exception as e:
            checks.append(_compliance_status(False, "SSH max auth tries", str(e), warn=True))

        passed = sum(1 for status, _, _ in checks if status == "PASS")
        total = len(checks)
        score = int((passed / total) * 100) if total else 0
        emoji = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}
        lines = [
            "🛡 *CIS Benchmark Compliance*",
            f"Score: `{score}%` ({passed}/{total})",
            "",
        ]
        lines.extend(f"{emoji[status]} {name}: `{status}` - {detail}" for status, name, detail in checks)
        return "\n".join(lines)
    except Exception as e:
        log.error("format_compliance error: %s", e)
        return f"Compliance check failed: {e}"
