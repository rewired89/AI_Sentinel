# app/radical_actions.py
import os
import json
import time
import psutil
import zipfile
import subprocess
from datetime import datetime

from allowlist import WHITELIST_NAMES, SAFE_PATH_KEYWORDS
from trust import is_signed_by_trusted_publisher

# ---- Config ----
STATE_FILE = "data/lockdown_state.json"
QUARANTINE_DIR = "data/quarantine"
RULE_PREFIX = "AIHunterLockdown_"

CRITICAL_PROCESSES = {
    "system idle process", "system", "registry",
    "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe"
}

def _ensure_dirs():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

def _toast(msg: str):
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast("AI Hunter – Radical Mode", msg, duration=5)
    except Exception:
        print(f"[Toast] {msg}")

# ---------------------------
# Network Lockdown (temporary)
# ---------------------------

def _fw(cmd_args):
    return subprocess.run(["netsh", "advfirewall"] + cmd_args, capture_output=True, text=True)

def network_lockdown_start(allow_programs=None, duration_minutes=15):
    """
    Sets outbound policy to BLOCK and adds minimal allow rules (DNS + allow_programs).
    Call network_lockdown_end() to revert. We also write a state file as a safety net.
    """
    _ensure_dirs()
    allow_programs = allow_programs or []

    # Set firewall policy to block outbound (all profiles)
    _fw(["set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])

    # Allow DNS (UDP/TCP 53)
    _fw(["firewall", "add", "rule", f"name={RULE_PREFIX}Allow_DNS_UDP", "dir=out", "action=allow",
         "protocol=UDP", "remoteport=53"])
    _fw(["firewall", "add", "rule", f"name={RULE_PREFIX}Allow_DNS_TCP", "dir=out", "action=allow",
         "protocol=TCP", "remoteport=53"])

    # Allow selected programs to keep user online (e.g., browsers)
    for path in allow_programs:
        if path and os.path.exists(path):
            rule_name = f"{RULE_PREFIX}Allow_{os.path.basename(path)}"
            _fw(["firewall", "add", "rule", f"name={rule_name}", "dir=out", "action=allow",
                 "program=" + path])

    # Write state so we can revert even if app dies
    state = {
        "started_at": datetime.now().isoformat(),
        "duration_minutes": duration_minutes,
        "allowed_programs": [p for p in allow_programs if p and os.path.exists(p)]
    }
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

    _toast(f"Network lockdown enabled for ~{duration_minutes} min")

def network_lockdown_end():
    """Reverts outbound policy to ALLOW and removes our lockdown rules."""
    # Restore default allow outbound
    _fw(["set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"])

    # Remove our rules
    try:
        out = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "Rule Name:" in line and RULE_PREFIX in line:
                name = line.split("Rule Name:")[1].strip()
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                               capture_output=True, text=True)
    except Exception:
        pass

    try:
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
    except Exception:
        pass

    _toast("Network lockdown disabled")

# -----------------------------------------
# Kill-tree for unsigned/untrusted processes
# -----------------------------------------

def _is_critical(proc_info) -> bool:
    base = os.path.basename((proc_info.get("exe") or proc_info.get("name") or "")).lower()
    return base in CRITICAL_PROCESSES

def _is_trusted(proc_info) -> bool:
    name = (proc_info.get("name") or "").lower()
    if name in WHITELIST_NAMES:
        return True
    exe = (proc_info.get("exe") or "").lower()
    if any(k.lower() in exe for k in SAFE_PATH_KEYWORDS):
        return True
    if exe and is_signed_by_trusted_publisher(exe):
        return True
    return False

def _quarantine_meta(proc, reason="radical_killtree"):
    try:
        pid = proc.pid
        name = proc.name()
        exe = ""
        try:
            exe = proc.exe()
        except Exception:
            exe = name
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.basename(exe or name)
        meta = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "username": proc.username() if hasattr(proc, "username") else "unknown",
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        }
        json_path = os.path.join(QUARANTINE_DIR, f"{base}_{pid}_{ts}.json")
        zip_path  = os.path.join(QUARANTINE_DIR, f"{base}_{pid}_{ts}.zip")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        with zipfile.ZipFile(zip_path, "w") as z:
            z.write(json_path, arcname=os.path.basename(json_path))
        try:
            os.remove(json_path)
        except Exception:
            pass
    except Exception:
        pass

def kill_tree_unsigned():
    """
    Finds suspicious roots (not trusted, not critical, unsigned) and kills
    the entire process tree (children recursive), quarantining metadata.
    """
    _ensure_dirs()
    killed = 0

    # Snapshot first to avoid racing lists
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            info = proc.info
            if _is_critical(info) or _is_trusted(info):
                continue
            exe = info.get("exe") or ""
            # Only target unsigned or unknown publisher
            if exe and is_signed_by_trusted_publisher(exe):
                continue

            # Suspend + collect tree
            try:
                proc.suspend()
            except Exception:
                pass

            children = proc.children(recursive=True)
            # Suspend children first
            for ch in children:
                try:
                    ch.suspend()
                except Exception:
                    pass

            # Quarantine metadata
            _quarantine_meta(proc)
            for ch in children:
                _quarantine_meta(ch)

            # Kill children then parent
            for ch in children:
                try:
                    ch.kill()
                except Exception:
                    pass
            try:
                proc.kill()
                killed += 1
                print(f"☠️  Kill-tree unsigned: {info.get('name')} (PID {info.get('pid')})")
            except Exception:
                pass

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    _toast(f"Kill-tree pass done. Targets: {killed}")
    return killed
