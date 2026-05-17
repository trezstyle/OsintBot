"""Network scanning service."""
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError

from config import settings
from security import SafeCommandError, run_command, validate_hostname

log = logging.getLogger("cyber_volt")

_executor = ThreadPoolExecutor(max_workers=2)

def scan_network(target, all_ports=True):
    """Scan target with nmap. Target is validated before execution."""
    safe_target = validate_hostname(target)
    if not safe_target:
        return f"❌ Invalid target: `{target}`\nMust be a valid IP address or domain name."

    nmap_path = str(settings.paths.nmap_path)
    if not os.path.exists(nmap_path):
        return f"❌ nmap not found at {nmap_path}. Install with: apt install nmap"

    try:
        if not all_ports:
            COMMON = "22,80,443,21,25,53,110,143,993,995,8080,8443,3306,5432,6379,27017,3389,5900,9090,3000,5000,8000,9000"
            future = _executor.submit(run_command, [nmap_path, "-T4", "--open", "-p", COMMON, safe_target], 180)
            try:
                out = future.result(timeout=180)
            except TimeoutError:
                return f"❌ Fast scan timed out after 180s"
            hosts = parse_nmap_hosts(out)
            summary = ""
            for line in out.split("\n"):
                if "Nmap done" in line:
                    summary = line.strip()
                    break
            return format_scan(safe_target, summary, hosts)
        # Full scan — all ports
        future = _executor.submit(run_command, [nmap_path, "-Pn", "-T4", "--open", "-p-", safe_target], 600)
        try:
            out = future.result(timeout=600)
        except TimeoutError:
            return f"❌ Full scan timed out after 600s"
        hosts = parse_nmap_hosts(out)
        summary = ""
        for line in out.split("\n"):
            if "Nmap done" in line:
                summary = line.strip()
                break
        if not hosts:
            return f"🌐 *Full Scan: {safe_target}*\n❌ No open ports found."
        return format_scan(safe_target, summary, hosts)
    except SafeCommandError as e:
        return f"❌ Scan error: {e}"
    except Exception as e:
        log.error(f"scan_network error: {e}")
        return f"❌ Scan failed: {e}"
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
