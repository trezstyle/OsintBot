"""Threat hunt orchestrators — combine multiple data sources."""
from concurrent.futures import ThreadPoolExecutor

from services.threat_intel.reputation import get_abuseipdb_report, get_geoip, get_subdomains, get_whois, save_to_log
from services.threat_intel.vt import get_vt_report

_HUNT_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="hunt")


def threat_hunt_ip(ip):
    vt_fut = _HUNT_POOL.submit(get_vt_report, ip)
    abuse_fut = _HUNT_POOL.submit(get_abuseipdb_report, ip)
    geo_fut = _HUNT_POOL.submit(get_geoip, ip)
    vt = vt_fut.result()
    abuse = abuse_fut.result()
    geo = geo_fut.result()
    report = f"🎯 *Threat Hunt: `{ip}`*\n\n{vt}\n\n{abuse}\n\n{geo}"
    save_to_log(ip, report)
    return report


def threat_hunt_domain(domain):
    whois_fut = _HUNT_POOL.submit(get_whois, domain)
    subs_fut = _HUNT_POOL.submit(get_subdomains, domain)
    whois_data = whois_fut.result()
    subs = subs_fut.result()
    report = f"🌐 *Domain Recon: `{domain}`*\n\n{whois_data}\n\n📡 *Subdomains (crt.sh):*\n`{subs}`"
    save_to_log(domain, report)
    return report
