# app/behavior_watch.py
import os, time, psutil
from datetime import datetime

# Optional allowlist/trust checks
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

CRITICAL_PIDS = {0, 4}
CRITICAL_NAMES = {
    "system", "system idle process", "registry",
    "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe"
}

# “LOLbins”/script engines often abused by malware
SUSPICIOUS_CHILD_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "bitsadmin.exe",
    "installutil.exe", "msbuild.exe", "msiexec.exe", "rundll32.exe", "schtasks.exe"
}

# Parents that *shouldn’t* usually spawn the above
SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "7zfm.exe", "7z.exe", "explorer.exe"
}

# Quick trust helpers
def _is_critical(proc) -> bool:
    try:
        if proc.pid in CRITICAL_PIDS: return True
        nm = (proc.name() or "").lower()
        return nm in CRITICAL_NAMES
    except Exception:
        return False

def _is_trusted(proc) -> bool:
    try:
        nm = (proc.name() or "").lower()
        if nm in {n.lower() for n in WHITELIST_NAMES}:
            return True
        exe = (proc.exe() or "")
        if any(k.lower() in exe.lower() for k in SAFE_PATH_KEYWORDS):
            return True
        if exe and is_signed_by_trusted_publisher(exe):
            return True
    except Exception:
        pass
    return False

def _proc_info(proc):
    try:
        return {
            "pid": proc.pid,
            "name": (proc.name() or "").lower(),
            "exe": (proc.exe() or ""),
            "cmdline": " ".join(proc.cmdline() or []),
            "ppid": proc.ppid(),
        }
    except Exception:
        return {"pid": getattr(proc, "pid", None), "name": "unknown", "exe": "", "cmdline": "", "ppid": None}

def _looks_suspicious_child(proc, parent) -> bool:
    """Parent from user-facing app spawns LOLbin/script engine -> sus."""
    try:
        child_name = (proc.name() or "").lower()
        parent_name = (parent.name() or "").lower() if parent else ""
        if child_name in SUSPICIOUS_CHILD_NAMES and parent_name in SUSPICIOUS_PARENTS:
            return True
    except Exception:
        pass
    return False

def _looks_self_injection(proc) -> bool:
    """Crude heuristic: process spawns a same-named sibling with weird cmdline."""
    try:
        nm = (proc.name() or "").lower()
        cmd = " ".join(proc.cmdline() or []).lower()
        if nm and nm in cmd and any(t in cmd for t in (" -enc ", "-encodedcommand", "/c ", "/k ")):
            return True
    except Exception:
        pass
    return False

def _looks_temp_exec(proc) -> bool:
    """Executable running from Temp or user profile uncommon locations."""
    try:
        exe = (proc.exe() or "").lower()
        if not exe:
            return False
        bad_roots = (
            r"\\appdata\\local\\temp",
            r"\\users\\public\\",
            r"\\programdata\\",
            r"\\windows\\temp",
        )
        return any(br in exe for br in bad_roots) and exe.endswith(".exe")
    except Exception:
        return False


def scan_once(window_seconds: float = 5.0, poll_interval: float = 0.5) -> bool:
    """
    Observe for a short window; flag/kill on suspicious child spawns & temp executables.
    Returns True if anything suspicious was found (or acted on).
    """
    # Initial snapshot
    seen = set()
    try:
        for p in psutil.process_iter(["pid"]):
            seen.add(p.info["pid"])
    except Exception:
        pass

    acted = False
    suspicious_seen = False
    t0 = time.time()

    while time.time() - t0 < window_seconds:
        time.sleep(poll_interval)
        try:
            current_pids = set()
            for p in psutil.process_iter(["pid", "ppid", "name"]):
                pid = p.info["pid"]
                current_pids.add(pid)
                if pid in seen:
                    continue  # already known

                # New process appeared -> evaluate
                seen.add(pid)
                try:
                    parent = psutil.Process(p.info["ppid"]) if p.info.get("ppid") else None
                except Exception:
                    parent = None

                if _is_critical(p):
                    continue  # never touch system

                info = _proc_info(p)
                par_name = (parent.name() or "").lower() if parent else ""

                bad = (
                    _looks_suspicious_child(p, parent) or
                    _looks_self_injection(p) or
                    _looks_temp_exec(p)
                )

                if bad:
                    suspicious_seen = True
                    print(f"[behavior_watch] Suspicious spawn: {info['name']} (PID {info['pid']}) "
                          f"PPID={info['ppid']} ({par_name})")
                    if not _is_trusted(p):
                        # Try to quarantine
                        try:
                            kinfo = kill_and_quarantine(p)
                            print(f"[behavior_watch] ☠️  Quarantined PID {info['pid']} -> "
                                  f"{kinfo.get('quarantine_path')} (SHA256 {kinfo.get('sha256')})")
                            acted = True
                        except Exception as e:
                            print(f"[behavior_watch] Failed to quarantine PID {info['pid']}: {e}")
        except Exception:
            # Keep going even on intermittent access errors
            continue

    if suspicious_seen and not acted:
        print("[behavior_watch] Suspicious behavior observed (report-only this pass).")
    elif not suspicious_seen:
        print("[behavior_watch] No suspicious behaviors in window.")

    return acted or suspicious_seen
