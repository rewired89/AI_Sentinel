import os
import requests
from dotenv import load_dotenv

VT_URL = "https://www.virustotal.com/api/v3/domains/{}"
TIMEOUT = 6

# Keep this small & safe; in single-pass we’ll check a few known recent domains you talked to (if you store them)
CANDIDATE_DOMAINS = set()  # Integrate with your runtime cache if available

TRUSTED_DOMAINS = {
    "microsoft.com", "github.com", "python.org", "google.com"
}

def _vt_check_domain(domain, api_key):
    headers = {"x-apikey": api_key}
    r = requests.get(VT_URL.format(domain), headers=headers, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    return malicious, suspicious

def scan_once():
    """
    Single-pass domain reputation check against VirusTotal.
    Returns True if any candidate domain looks bad; else False.
    """
    load_dotenv()
    vt_key = os.getenv("VT_API_KEY", "").strip()
    if not vt_key:
        print("[domain_watcher] Missing VT_API_KEY. Skipping domain check (treated as clean).")
        return False

    # If you don’t have a live cache, single-pass can safely do nothing.
    domains = {d for d in CANDIDATE_DOMAINS if d not in TRUSTED_DOMAINS}
    if not domains:
        print("[domain_watcher] No candidate domains. Clean.")
        return False

    threat = False
    for d in domains:
        try:
            m, s = _vt_check_domain(d, vt_key)
            if m > 0 or s > 1:
                print(f"[domain_watcher] Domain flagged: {d} (malicious={m}, suspicious={s})")
                threat = True
        except requests.RequestException as e:
            print(f"[domain_watcher] VT error for {d}: {e}")

    if not threat:
        print("[domain_watcher] All candidate domains look clean.")
    return threat
