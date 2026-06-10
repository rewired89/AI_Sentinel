# app/ai_hunter_main.py
import os
import time
import threading
from datetime import datetime
from pathlib import Path

# Scanners (package-relative)
from app.detect_anomalies import scan_once as malware_scan_once
from app.file_scanner import scan_directory as _scan_dir, FileScanResult
try:
    from app.detect_anomalies import list_suspects  # optional; may not exist
except Exception:
    list_suspects = None

from app.behavior_watch import scan_once as behavior_scan_once

from app.ip_watcher import scan_once as ip_scan_once
from app.otx_watcher import scan_once as otx_scan_once
from app.domain_watcher import scan_once as domain_scan_once
from app.port_scanner import scan_once as port_scan_once


# Radical actions
from app.net_actions import block_internet, restore_internet, force_shutdown, force_reboot

# Reporting
from app.reporting import save_incident_report

# Tools
from app.tools.process_control import kill_and_quarantine

# ------------------ Config via environment ------------------
TEST_MODE = os.getenv("AIHUNTER_TEST_MODE", "0") == "1"
AUTO_RESTORE = os.getenv("AIHUNTER_AUTORESTORE",
                         "1" if TEST_MODE else "0") in ("1", "true", "True", "YES", "yes")
try:
    AUTO_RESTORE_DELAY = int(os.getenv("AIHUNTER_AUTORESTORE_DELAY_SECONDS",
                                       "30" if TEST_MODE else "300"))
except ValueError:
    AUTO_RESTORE_DELAY = 30 if TEST_MODE else 300

def delayed_restore(delay_seconds: int):
    def _restore():
        time.sleep(delay_seconds)
        print(f"⏳ {delay_seconds} seconds passed — restoring internet (auto-restore).")
        restore_internet()
    threading.Thread(target=_restore, daemon=True).start()

# ------------------ Helpers: neutralization + soft offline prompt ------------------
def _prompt_yes_no(title: str, message: str) -> bool:
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk(); root.withdraw()
        res = messagebox.askyesno(title, message)
        root.destroy()
        return bool(res)
    except Exception:
        print(f"[AI Sentinel] {title}: {message} -> (no GUI; default NO)")
        return False

def neutralize_active_suspects() -> tuple[int, list]:
    """
    Try to kill + quarantine all currently suspected processes.
    Returns (killed_count, errors_list[(pid, 'error')...])
    """
    if not callable(list_suspects):
        return 0, []
    killed = 0
    errors = []
    try:
        suspects = list(list_suspects())  # iterable of psutil.Process or similar
    except Exception as e:
        print(f"[AI Sentinel] Could not list suspects: {e}")
        return 0, [(-1, f"list_suspects failed: {e}")]
    for proc in suspects:
        pid = getattr(proc, "pid", None)
        try:
            result = kill_and_quarantine(proc)
            print(f"🗂️  Quarantined PID {pid} at: {result['quarantine_path']} (SHA256: {result['sha256']})")
            killed += 1
        except Exception as e:
            errors.append((pid, str(e)))
            print(f"❗ Failed to neutralize PID {pid}: {e}")
    return killed, errors

def maybe_temp_offline_on_failure(has_failures: bool):
    """If any neutralization failed, offer ~30s offline with auto-restore."""
    if not has_failures:
        return
    title = "AI Sentinel – Extra Protection"
    msg = ("We couldn’t terminate at least one suspicious process.\n\n"
           "Recommended: temporarily go OFFLINE for about 30 seconds to protect you while we keep watching.\n\n"
           "Proceed?")
    if _prompt_yes_no(title, msg):
        print("⚠️ Applying temporary network block…")
        if block_internet():
            delay = max(30, AUTO_RESTORE_DELAY) if AUTO_RESTORE else 30
            print(f"🛡️  Offline now. Will auto-restore in ~{delay} seconds.")
            delayed_restore(delay)
        else:
            print("❌ Could not block internet (admin required or failure).")
    else:
        print("ℹ️  Staying online. Monitoring continues.")

# ------------------ Core ------------------
def _file_scan_pass() -> int:
    """
    Scan the quarantine directory and common high-risk locations for malicious files.
    Returns the count of suspicious/dangerous files found.
    """
    scan_targets: list[Path] = []

    # Always scan the quarantine directory
    quarantine = Path("data/quarantine")
    if quarantine.exists():
        scan_targets.append(quarantine)

    # Platform-specific high-risk paths
    home = Path.home()
    candidates = [
        home / "Downloads",
        Path(os.getenv("TEMP", "")) if os.name == "nt" else Path("/tmp"),
        Path(os.getenv("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ]
    for p in candidates:
        if p.exists() and p.is_dir():
            scan_targets.append(p)

    findings: list[FileScanResult] = []
    for target in scan_targets:
        try:
            findings.extend(_scan_dir(target))
        except Exception as e:
            print(f"[AI Sentinel] File scan error in {target}: {e}")

    for f in findings:
        level = "DANGEROUS" if f.risk == "dangerous" else "SUSPICIOUS"
        print(f"[File Scanner] {level}: {f.path}")
        for reason in f.reasons:
            print(f"  - {reason}")

    return len(findings)


def run_full_pass_counts() -> dict:
    counts = {"process": 0, "ip": 0, "otx": 0, "domain": 0, "ports": 0, "behavior": 0, "files": 0}
    counts["process"]  = int(malware_scan_once() or 0)
    counts["ip"]       = 1 if ip_scan_once() else 0
    counts["otx"]      = 1 if otx_scan_once() else 0
    counts["domain"]   = 1 if domain_scan_once() else 0
    counts["ports"]    = 1 if port_scan_once() else 0
    counts["behavior"] = 1 if behavior_scan_once() else 0
    counts["files"]    = _file_scan_pass()
    counts["total"]    = sum(v for k, v in counts.items() if k != "total")
    return counts


def maybe_make_report(trigger_time: datetime, counts: dict):
    """If anything was detected, silently save incident package to Desktop."""
    if counts.get("total", 0) > 0:
        incident_dir = save_incident_report(trigger_time, counts)
        print(f"📄 Incident report saved to: {incident_dir}")

def main():
    print("🚀 AI Sentinel – One-shot mode (two passes + optional radical)")

    # -------- Pass 1 --------
    t0 = datetime.now()
    counts1 = run_full_pass_counts()
    if counts1["total"] == 0:
        print("✅ System looks clean. Exiting.")
        return

    # Report for pass 1
    maybe_make_report(t0, counts1)

    # Neutralize immediately (if detector exposed suspects)
    killed, errors = neutralize_active_suspects()
    if killed > 0:
        print(f"🔧 Neutralized {killed} suspicious process(es).")
    maybe_temp_offline_on_failure(has_failures=bool(errors))

    # -------- Pass 2 (confirm) --------
    time.sleep(5)
    print("🔄 Re-scanning to confirm remediation…")
    t1 = datetime.now()
    counts2 = run_full_pass_counts()

    if counts2["total"] == 0:
        print("✅ All threats handled. Exiting.")
        return

    # Report for persistent issues
    maybe_make_report(t1, counts2)

    # ---- Radical prompt helpers ----
    def prompt_radical_action(count: int) -> bool:
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk(); root.withdraw()
            res = messagebox.askyesno(
                "AI Sentinel – Persistent Threats",
                f"AI Sentinel still found {count} issue(s) after remediation.\n\n"
                "We strongly recommend blocking all internet traffic now to stop any active threats.\n\n"
                "Yes = Block internet immediately.\n"
                "No  = Keep internet active (less safe)."
            )
            root.destroy()
            return bool(res)
        except Exception:
            print("ℹ️  GUI not available; skipping radical prompt.")
            return False

    def prompt_shutdown_choice() -> str:
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk(); root.withdraw()
            if messagebox.askyesno(
                "AI Sentinel – Kill-Switch Applied",
                "Internet access is now BLOCKED.\n\nDo you want to REBOOT now?\n"
                "Yes = Reboot immediately\nNo  = Choose another option"
            ):
                root.destroy()
                return "reboot"
            if messagebox.askyesno(
                "AI Sentinel – Optional Shutdown",
                "Do you want to SHUT DOWN instead?\n"
                "Yes = Shutdown immediately\nNo  = Keep system running"
            ):
                root.destroy()
                return "shutdown"
            root.destroy()
        except Exception:
            print("ℹ️  GUI not available; keeping system running.")
        return "none"

    # -------- Optional radical step --------
    if prompt_radical_action(counts2["total"]):
        print("⚠️ Applying network kill-switch… (Admin required)")
        if block_internet():
            print("🛡️  Kill-switch is ACTIVE.")
            if AUTO_RESTORE:
                print(f"⏱️  Auto-restore enabled. Will restore in {AUTO_RESTORE_DELAY} seconds.")
                delayed_restore(AUTO_RESTORE_DELAY)
            choice = prompt_shutdown_choice()
            if choice == "reboot":
                print("♻️  Rebooting now…"); force_reboot()
            elif choice == "shutdown":
                print("⏻  Shutting down now…"); force_shutdown()
            else:
                print("ℹ️  Keeping system running" + (" (auto-restore pending)" if AUTO_RESTORE else " with internet blocked."))
        else:
            print("❌ Could not apply network kill-switch (not elevated or failed).")
    else:
        print("ℹ️ User declined radical action. Internet remains active. Exiting.")

if __name__ == "__main__":
    main()
