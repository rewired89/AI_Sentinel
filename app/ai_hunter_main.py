# app/ai_hunter_main.py
import time
import os
import tkinter as tk
from tkinter import messagebox
import threading

# Scanners
from detect_anomalies import scan_once as malware_scan_once
from ip_watcher import scan_once as ip_scan_once
from otx_watcher import scan_once as otx_scan_once
from domain_watcher import scan_once as domain_scan_once

# Radical actions
from net_actions import block_internet, restore_internet, force_shutdown, force_reboot

# ------------------ Config via environment ------------------
TEST_MODE = os.getenv("AIHUNTER_TEST_MODE", "0") == "1"
# Auto-restore after blocking (1/0). Default: on in TEST_MODE, off otherwise.
AUTO_RESTORE = os.getenv("AIHUNTER_AUTORESTORE",
                         "1" if TEST_MODE else "0") in ("1", "true", "True", "YES", "yes")
# Delay seconds before restore (default 30 in TEST_MODE, 300 in normal if enabled)
try:
    AUTO_RESTORE_DELAY = int(os.getenv("AIHUNTER_AUTORESTORE_DELAY_SECONDS",
                                       "30" if TEST_MODE else "300"))
except ValueError:
    AUTO_RESTORE_DELAY = 30 if TEST_MODE else 300

# ------------------ UI Helpers ------------------
def prompt_radical_action(count: int) -> bool:
    """Ask the user if we should take a radical action when issues persist."""
    try:
        root = tk.Tk(); root.withdraw()
        res = messagebox.askyesno(
            "AI Hunter Sentinel – Persistent Threats",
            f"AI Hunter Sentinel still found {count} issue(s) after remediation.\n\n"
            "We *strongly recommend* blocking all internet traffic now to stop any active threats.\n\n"
            "Yes = Block internet immediately.\n"
            "No  = Keep internet active (less safe)."
        )
        root.destroy()
        return bool(res)
    except Exception:
        print("ℹ️  GUI not available; skipping radical prompt.")
        return False

def prompt_shutdown_choice() -> str:
    """Offer reboot/shutdown choice after kill-switch."""
    choice = "none"
    try:
        root = tk.Tk(); root.withdraw()
        if messagebox.askyesno(
            "AI Hunter Sentinel – Kill-Switch Applied",
            "Internet access is now BLOCKED.\n\nDo you want to REBOOT now?\n"
            "Yes = Reboot immediately\nNo  = Choose another option"
        ):
            choice = "reboot"
        else:
            if messagebox.askyesno(
                "AI Hunter Sentinel – Optional Shutdown",
                "Do you want to SHUT DOWN instead?\n"
                "Yes = Shutdown immediately\nNo  = Keep system running"
            ):
                choice = "shutdown"
        root.destroy()
    except Exception:
        print("ℹ️  GUI not available; keeping system running.")
    return choice

def delayed_restore(delay_seconds: int):
    """Restore internet after a delay (background thread)."""
    def _restore():
        time.sleep(delay_seconds)
        print(f"⏳ {delay_seconds} seconds passed — restoring internet (auto-restore).")
        restore_internet()
    threading.Thread(target=_restore, daemon=True).start()

# ------------------ Core ------------------
def run_full_pass() -> int:
    total = 0
    total += malware_scan_once()
    total += ip_scan_once()
    total += otx_scan_once()
    total += domain_scan_once()
    return total

def main():
    print("🚀 AI Hunter Sentinel – One-shot mode (two passes + optional radical)")

    # Pass 1
    issues = run_full_pass()
    if issues == 0:
        print("✅ System looks clean. Exiting.")
        return

    # Pass 2
    time.sleep(5)
    print("🔄 Re-scanning to confirm remediation…")
    issues2 = run_full_pass()
    if issues2 == 0:
        print("✅ All threats handled. Exiting.")
        return

    # Radical step
    if prompt_radical_action(issues2):
        print("⚠️ Applying network kill-switch… (Admin required)")
        if block_internet():
            print("🛡️  Kill-switch is ACTIVE.")

            # Auto-restore if enabled
            if AUTO_RESTORE:
                print(f"⏱️  Auto-restore enabled. Will restore in {AUTO_RESTORE_DELAY} seconds.")
                delayed_restore(AUTO_RESTORE_DELAY)

            choice = prompt_shutdown_choice()
            if choice == "reboot":
                print("♻️  Rebooting now…")
                force_reboot()
            elif choice == "shutdown":
                print("⏻  Shutting down now…")
                force_shutdown()
            else:
                print("ℹ️  Keeping system running" + (" (auto-restore pending)" if AUTO_RESTORE else " with internet blocked."))
        else:
            print("❌ Could not apply network kill-switch (not elevated or failed).")
    else:
        print("ℹ️ User declined radical action. Internet remains active. Exiting.")

if __name__ == "__main__":
    main()
