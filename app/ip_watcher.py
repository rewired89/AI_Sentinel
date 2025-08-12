# app/ip_watcher.py
import os
import json
import requests
import psutil
import ipaddress
from dotenv import load_dotenv

from app.tools.virustotal_client import lookup_ip, lookup_hash
from app.tools.process_control import kill_and_quarantine

ABUSE_IPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 6


def _get_active_remote_ips():
    """
    Return a set of current remote peer IPs from live TCP/UDP connections,
    excluding loopback and RFC1918 private ranges.
    """
    remotes = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            try:
                if not c.raddr:
                    continue
                ip = c.raddr.ip
                ipobj = ipaddress.ip_address(ip)
                if ipobj.is_loopback or ipobj.is_private:
                    continue
                remotes.add(ip)
            except Exception:
                continue
    except Exception as e:
        print(f"[ip_watcher] Could not enumerate connections: {e}")
    return remotes


def _check_abuseipdb(ip, api_key):
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
    r = requests.get(ABUSE_IPDB_URL, headers=headers, params=params, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    return int(data.get("data", {}).get("abuseConfidenceScore", 0))


def _vt_enrich_and_act(ips) -> bool:
    """
    For each remote IP, ask VirusTotal. If malicious/suspicious > 0:
      - Find local processes with active connections to that IP.
      - Kill + quarantine them and look up the quarantined file's hash on VT.
    Returns True if we acted on anything (so main will create a report).
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not vt_key:
        print("[ip_watcher] VIRUSTOTAL_API_KEY not set. Skipping VT enrichment.")
        return False

    acted = False
    max_checks = 4  # avoid rate limits
    checked = 0

    for ip in list(set(ips)):
        if checked >= max_checks:
            break
        checked += 1

        try:
            res = lookup_ip(ip)
            if not res.get("ok") or not res.get("reputation"):
                continue

            rep = res["reputation"]
            mal = int(rep.get("malicious", 0))
            sus = int(rep.get("suspicious", 0))
            print(
                f"[VT] {ip} -> malicious={mal} suspicious={sus} "
                f"harmless={rep.get('harmless', 0)} undetected={rep.get('undetected', 0)}"
            )

            if (mal + sus) > 0:
                # Identify local processes currently connected to this IP and neutralize them.
                owners = set()
                try:
                    for c in psutil.net_connections(kind="inet"):
                        try:
                            if not c.raddr or not c.pid:
                                continue
                            if c.raddr.ip == ip:
                                owners.add(c.pid)
                        except Exception:
                            continue
                except Exception as e:
                    print(f"[ip_watcher] Could not enumerate connections: {e}")

                if owners:
                    print(f"[ip_watcher] Malicious IP {ip} connected by PIDs: {sorted(owners)} — neutralizing.")
                    for pid in list(owners):
                        try:
                            proc = psutil.Process(pid)
                            info = kill_and_quarantine(proc)
                            print(
                                f"[ip_watcher] Quarantined PID {pid} -> {info.get('quarantine_path')} "
                                f"(SHA256 {info.get('sha256')})"
                            )

                            # VT file-hash verdict (if we got a hash)
                            sha = info.get("sha256")
                            if sha:
                                hres = lookup_hash(sha)
                                if hres.get("ok") and hres.get("reputation"):
                                    hrep = hres["reputation"]
                                    print(
                                        f"[VT:hash] {sha[:12]}… -> malicious={hrep.get('malicious',0)} "
                                        f"suspicious={hrep.get('suspicious',0)} harmless={hrep.get('harmless',0)} "
                                        f"undetected={hrep.get('undetected',0)}"
                                    )
                                else:
                                    err = hres.get("error", "no-rep")
                                    print(f"[VT:hash] lookup failed for {sha[:12]}… ({err})")

                            acted = True
                        except Exception as e:
                            print(f"[ip_watcher] Failed to neutralize PID {pid}: {e}")
                else:
                    print(f"[ip_watcher] No active owning process found for {ip} (may have closed).")
        except Exception as e:
            print(f"[VT] Error checking {ip}: {e}")

    return acted


def scan_once():
    """
    Runs a single IP reputation pass.
    Returns True if any suspicious IPs are found or any VT-driven actions were taken.
    """
    load_dotenv()
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    threat_found = False
    suspicious = []

    try:
        ips = _get_active_remote_ips()
        if not ips:
            print("[ip_watcher] No remote peers. Clean.")
            return False

        # 1) AbuseIPDB (informational)
        if abuse_key:
            for ip in ips:
                try:
                    score = _check_abuseipdb(ip, abuse_key)
                    if score >= 50:
                        suspicious.append({"ip": ip, "score": score})
                except requests.RequestException as e:
                    print(f"[ip_watcher] AbuseIPDB API error for {ip}: {e}")

        if suspicious:
            threat_found = True
            print("[ip_watcher] Suspicious IPs detected:", json.dumps(suspicious, indent=2))
        else:
            print("[ip_watcher] All checked IPs look clean.")

        # 2) VirusTotal enrichment + active defense
        vt_acted = _vt_enrich_and_act(ips)
        threat_found = threat_found or vt_acted

    except Exception as e:
        print(f"[ip_watcher] Unexpected error: {e}. Treating as clean for single-pass.")

    return threat_found
