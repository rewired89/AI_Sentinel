# app/net_actions.py
import ctypes
import subprocess
import os
import time

RULE_NAME = "AIHunter_KillSwitch"

def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def block_internet() -> bool:
    """
    Create a Windows Defender Firewall rule that blocks ALL outbound traffic.
    Returns True if the block is (likely) active, False if we couldn't apply it.
    """
    if not _is_admin():
        print("❌ Network block requires Administrator privileges. Run as Admin.")
        return False

    cmds = [
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_NAME}"],
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={RULE_NAME}", "dir=out", "action=block", "enable=yes", "profile=any", "program=any", "protocol=any"],
    ]
    ok = True
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            ok = False

    if ok:
        print("🛡️  Internet BLOCKED via firewall rule.")
    else:
        print("⚠️  Could not ensure firewall rule. Trying adapter disable fallback...")
        ok = disable_adapters_fallback()

    return ok

def restore_internet() -> bool:
    """
    Remove the kill-switch firewall rule. If adapters were disabled, try to re-enable them.
    """
    if not _is_admin():
        print("❌ Restore requires Administrator privileges. Run as Admin.")
        return False

    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_NAME}"],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Firewall kill-switch rule removed.")
    except Exception:
        pass

    # best-effort re-enable of adapters
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-NetAdapter -Physical | Where-Object {$_.Status -ne 'Disabled'} | Out-Null"], check=False)
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Disabled'} | "
                        "Enable-NetAdapter -Confirm:$false | Out-Null"], check=False)
        print("✅ Network adapters re-enabled (if any were disabled).")
    except Exception:
        pass

    return True

def disable_adapters_fallback() -> bool:
    """
    Fallback if firewall call fails: disable all physical network adapters.
    WARNING: also needs Admin. User can restore with restore_internet().
    """
    if not _is_admin():
        print("❌ Adapter disable fallback also requires Administrator privileges.")
        return False
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-NetAdapter -Physical | Disable-NetAdapter -Confirm:$false"], check=True)
        print("🛑 Internet BLOCKED by disabling network adapters.")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to disable adapters.")
        return False

def force_shutdown():
    try:
        subprocess.run(["shutdown", "/s", "/t", "0"], check=False)
    except Exception:
        pass

def force_reboot():
    try:
        subprocess.run(["shutdown", "/r", "/t", "0"], check=False)
    except Exception:
        pass
