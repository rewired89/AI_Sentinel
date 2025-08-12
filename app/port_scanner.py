# app/port_scanner.py
import os, json, psutil, ipaddress
from datetime import datetime
from pathlib import Path

# Allowlist / trust (fallbacks if not present)
try:
    from app.allowlist import WHITELIST_NAMES, SAFE_PATH_KEYWORDS
except Exception:
    WHITELIST_NAMES, SAFE_PATH_KEYWORDS = set(), []

try:
    from app.trust import is_signed_by_trusted_publisher
except Exception:
    def is_signed_by_trusted_publisher(_): return False

from app.tools.process_control import kill_and_quarantine

TEST_MODE = os.getenv("AIHUNTER_TEST_MODE", "0") == "1"

# -------------------------
# Risky ports commonly abused if exposed
# -------------------------
HIGH_RISK_PORTS = {
    21, 22, 23, 25, 80, 135, 139, 389, 445,
    512, 513, 514, 5800, 5900, 3306, 5432,
    6379, 11211, 27017, 3389
}

# -------------------------
# LAN-only allowlist (won’t trigger if bound to private IP + in this set)
# Add your dev ports here (e.g., React/Vite/Node/Python)
# -------------------------
SAFE_LAN_PORTS = {
    3000, 3001, 5173, 5174, 8000, 8001, 8080, 24800
}

# -------------------------
# Never touch these (Windows core services) — still reported
# -------------------------
SAFE_SERVICE_NAMES = {
    "system", "system idle process", "registry",
    "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "spoolsv.exe"
}
CRITICAL_PIDS = {0, 4}

# ---- Reporting log path (so this shows in incident packages)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = PROJECT_ROOT / "data" / "anomalies_log.json"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

def _append_log(entry: dict):
    try:
        data = []
        if LOG_FILE.exists():
            try:
                data = json.loads(LOG_FILE.read_text(encoding="utf-8") or "[]")
            except json.JSONDecodeError:
                data = []
        data.append(entry)
        LOG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def _is_exposed_ip(ip: str) -> bool:
    """
    Exposed if bound to 0.0.0.0/:: or any non-loopback address (LAN or WAN).
    We'll *later* exempt private IPs on SAFE_LAN_PORTS.
    """
    try:
        ipobj = ipaddress.ip_address(ip)
        if ipobj.is_unspecified:    # 0.0.0.0 or ::
            return True
        if ipobj.is_loopback or ipobj.is_link_local:
            return False
        return True  # non-loopback (LAN/WAN)
    except Exception:
        return False

def _is_proc_trusted(proc: psutil.Process | None) -> bool:
    if not proc:
        return False
    try:
        name = (proc.name() or "").lower()
        if name in {n.lower() for n in WHITELIST_NAMES}:
            return True
        exe = (proc.exe() or "")
        for kw in SAFE_PATH_KEYWORDS:
            if kw.lower() in exe.lower():
                return True
        if exe and is_signed_by_trusted_publisher(exe):
            return True
    except Exception:
        pass
    return False

def _collect_listeners():
    out, seen = [], set()
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        print(f"[port_scanner] Could not enumerate sockets: {e}")
        return out

    for c in conns:
        try:
            status = str(getattr(c, "status", "")).upper()
            if status != "LISTEN" and getattr(psutil, "CONN_LISTEN", None) and c.status != psutil.CONN_LISTEN:
                continue
            if not c.laddr:
                continue
            ip = getattr(c.laddr, "ip", None) or (c.laddr[0] if isinstance(c.laddr, tuple) else None)
            port = getattr(c.laddr, "port", None) or (c.laddr[1] if isinstance(c.laddr, tuple) else None)
            if ip is None or port is None:
                continue

            key = (ip, int(port), c.pid or 0)
            if key in seen:
                continue
            seen.add(key)

            proc = psutil.Process(c.pid) if c.pid else None
            name = (proc.name() if proc else "unknown").lower()
            exe  = (proc.exe()  if proc else "")

            out.append({
                "pid": c.pid,
                "name": name,
                "exe": exe,
                "ip": ip,
                "port": int(port),
                "family": "IPv6" if ":" in ip else "IPv4",
                "exposed": _is_exposed_ip(ip),
                "is_private": _is_private_ip(ip),
                "trusted": _is_proc_trusted(proc),
                "critical": bool((c.pid in CRITICAL_PIDS) or (name in SAFE_SERVICE_NAMES)),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue
    return out

def _should_flag(l: dict) -> bool:
    """
    Flag logic:
      - Must be exposed (0.0.0.0, private LAN, or public)
      - If bound to a private IP AND port is in SAFE_LAN_PORTS => do NOT flag
      - Otherwise flag if (high-risk port OR untrusted)
    """
    if not l["exposed"]:
        return False
    if l["is_private"] and l["port"] in SAFE_LAN_PORTS:
        return False
    if l["port"] in HIGH_RISK_PORTS:
        return True
    if not l["trusted"]:
        return True
    return False

def scan_once() -> bool:
    listeners = _collect_listeners()
    if not listeners:
        print("[port_scanner] No listening ports found.")
        return False

    brief = sorted({f"{it['ip']}:{it['port']} (pid {it['pid']} {it['name']})" for it in listeners})
    print(f"[port_scanner] Listeners: {brief[:12]}{' …' if len(brief) > 12 else ''}")

    suspicious = [it for it in listeners if _should_flag(it)]
    if not suspicious:
        print("[port_scanner] No suspicious listeners.")
        return False

    print("[port_scanner] ⚠️  Suspicious listeners:")
    acted = False
    for it in suspicious:
        print(f"  - {it['ip']}:{it['port']} ({it['family']}) pid={it['pid']} {it['name']} "
              f"trusted={it['trusted']} critical={it['critical']} private={it['is_private']} exe='{(it['exe'] or '')}'")

        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "port_listener",
            "ip": it["ip"], "port": it["port"], "family": it["family"],
            "pid": it["pid"], "name": it["name"], "exe": it["exe"],
            "trusted": it["trusted"], "critical": it["critical"],
            "is_private": it["is_private"],
        }

        # A) Core/critical Windows services: report-only
        if it["critical"]:
            _append_log(entry | {"action": "windows_service_skip"})
            continue

        # B) Trusted process: report-only
        if it["trusted"]:
            _append_log(entry | {"action": "trusted_skip"})
            continue

        # C) If it’s private + SAFE_LAN_PORTS, it wouldn’t be in suspicious (defense in depth):
        if it["is_private"] and it["port"] in SAFE_LAN_PORTS:
            _append_log(entry | {"action": "lan_whitelist_skip"})
            continue

        # D) Untrusted & exposed: quarantine owner
        try:
            if not it["pid"]:
                _append_log(entry | {"action": "no_pid_skip"})
                continue
            proc = psutil.Process(it["pid"])
            info = kill_and_quarantine(proc)
            acted = True
            _append_log(entry | {
                "action": "quarantined",
                "quarantine_path": info.get("quarantine_path"),
                "sha256": info.get("sha256"),
            })
            print(f"[port_scanner] ☠️  Quarantined PID {it['pid']} -> {info.get('quarantine_path')} "
                  f"(SHA256 {info.get('sha256')})")
        except Exception as e:
            _append_log(entry | {"action": "quarantine_failed", "error": str(e)})
            print(f"[port_scanner] Failed to neutralize PID {it['pid']}: {e}")

    # Final return: True if we quarantined anything OR found any untrusted, non-critical listener
    actionable = any((not it["critical"] and not it["trusted"]) for it in suspicious)
    return acted or actionable


if __name__ == "__main__":
    scan_once()
