import os
import time
import json
import socket
import requests
from dotenv import load_dotenv

ABUSE_IPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 6

TRUSTED_IPS = {"127.0.0.1", "::1"}  # expand if needed

def _get_outbound_ip_candidates():
    # Quick heuristics: local default route target + DNS lookups currently open
    candidates = set()
    # Default route probe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        candidates.add(s.getsockname()[0])
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    # Add any user-known endpoints here if you keep a cache file, etc.
    return {ip for ip in candidates if ip not in TRUSTED_IPS}

def _check_abuseipdb(ip, api_key):
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
    r = requests.get(ABUSE_IPDB_URL, headers=headers, params=params, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    # AbuseIPDB score often exposed as "abuseConfidenceScore"
    return int(data.get("data", {}).get("abuseConfidenceScore", 0))

def scan_once():
    """
    Runs a single IP reputation pass.
    Returns True if any suspicious IPs are found (per score threshold), else False.
    """
    load_dotenv()
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        print("[ip_watcher] Missing ABUSEIPDB_API_KEY. Skipping IP check (treated as clean).")
        return False

    threat_found = False
    suspicious = []

    try:
        ips = _get_outbound_ip_candidates()
        if not ips:
            print("[ip_watcher] No outbound IP candidates. Clean.")
            return False

        for ip in ips:
            try:
                score = _check_abuseipdb(ip, api_key)
                if score >= 50:  # threshold—tune later
                    suspicious.append({"ip": ip, "score": score})
            except requests.RequestException as e:
                print(f"[ip_watcher] API error for {ip}: {e}")
                continue

        if suspicious:
            threat_found = True
            print("[ip_watcher] Suspicious IPs detected:", json.dumps(suspicious, indent=2))
        else:
            print("[ip_watcher] All checked IPs look clean.")

    except Exception as e:
        # Fail-safe: don’t block the app; treat as clean but log it
        print(f"[ip_watcher] Unexpected error: {e}. Treating as clean for single-pass.")

    return threat_found
