"""Threat hunt orchestrators — combine multiple data sources."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from services.threat_intel.reputation import get_abuseipdb_report, get_geoip, get_subdomains, get_whois, save_to_log
from services.threat_intel.vt import get_vt_report

_HUNT_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="hunt")


def threat_hunt_ip(ip):
    results = {}
    with _HUNT_POOL as pool:
        futures = {
            pool.submit(get_vt_report, ip): "vt",
            pool.submit(get_abuseipdb_report, ip): "abuse",
            pool.submit(get_geoip, ip): "geo",
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = f"Error: {exc}"
    report = f"🎯 *Threat Hunt: `{ip}`*\n\n{results.get('vt', '')}\n\n{results.get('abuse', '')}\n\n{results.get('geo', '')}"
    save_to_log(ip, report)
    return report


def threat_hunt_domain(domain):
    results = {}
    with _HUNT_POOL as pool:
        futures = {
            pool.submit(get_whois, domain): "whois",
            pool.submit(get_subdomains, domain): "subs",
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = f"Error: {exc}"
    report = f"🌐 *Domain Recon: `{domain}`*\n\n{results.get('whois', '')}\n\n📡 *Subdomains (crt.sh):*\n`{results.get('subs', '')}`"
    save_to_log(domain, report)
    return report
