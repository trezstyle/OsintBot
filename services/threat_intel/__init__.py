"""Threat intelligence package."""
import logging

log = logging.getLogger(__name__)

# Optional caching for external API calls (configured once at import time)
try:
    import requests_cache  # type: ignore
    requests_cache.install_cache(
        "api_cache", backend="sqlite", expire_after=300,
        allowable_methods=("GET", "HEAD"),
    )
except ImportError:
    log.debug("requests_cache not installed; API caching disabled")

# Re-export all public functions for backward compatibility.
# Each sub-module is focused on a specific category of checks.
from services.threat_intel.vt import check_hash, check_urlscan, get_vt_report
from services.threat_intel.reputation import (
    check_blacklist,
    check_ctlogs,
    check_http_headers,
    check_proxy,
    check_ssl,
    check_tor,
    get_abuseipdb_report,
    get_geoip,
    get_subdomains,
    get_whois,
    save_to_log,
)
from services.threat_intel.osint import check_email, check_hibp, check_phone
from services.threat_intel.mitre import attack_simulation, mitre_lookup
from services.threat_intel.hunt import threat_hunt_domain, threat_hunt_ip

__all__ = [
    "attack_simulation",
    "check_blacklist",
    "check_ctlogs",
    "check_email",
    "check_hash",
    "check_hibp",
    "check_http_headers",
    "check_phone",
    "check_proxy",
    "check_ssl",
    "check_tor",
    "check_urlscan",
    "get_abuseipdb_report",
    "get_geoip",
    "get_subdomains",
    "get_vt_report",
    "get_whois",
    "mitre_lookup",
    "save_to_log",
    "threat_hunt_domain",
    "threat_hunt_ip",
]
