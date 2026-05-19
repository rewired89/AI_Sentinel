"""
Windows autostart and Defender exclusion setup for AI Sentinel.

Two things this handles:
  1. Defender exclusion — i2pd.exe is a legitimate anonymity tool but Windows
     Defender flags it as a trojan (false positive). Adding data/i2p/ to the
     exclusion list prevents it being quarantined on every download.
  2. Windows startup — registers AI Sentinel in the HKCU Run key so it starts
     automatically when the user logs in. No admin rights needed for this step.

The Defender exclusion requires Administrator. This module detects elevation,
performs the step if it has rights, and prints clear manual instructions if not.
"""
import ctypes
import os
import subprocess
import sys
from pathlib import Path

try:
    import winreg as _winreg
except ImportError:
    _winreg = None   # non-Windows — all ops become no-ops

ROOT       = Path(__file__).parent.parent
APP_NAME   = "AI-Sentinel-Privacy"
_RUN_KEY   = r"Software\Microsoft\Windows\CurrentVersion\Run"


# ---------------------------------------------------------------------------
# Elevation helpers
# ---------------------------------------------------------------------------

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin(extra_args: list[str]) -> None:
    """Re-launch this process with UAC elevation for Defender exclusion step."""
    params = " ".join([f'"{sys.argv[0]}"'] + extra_args)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", f'"{sys.executable}"', params, None, 1
    )


# ---------------------------------------------------------------------------
# Defender exclusion
# ---------------------------------------------------------------------------

def add_defender_exclusion(path: Path) -> bool:
    """
    Add path to Windows Defender exclusion list via PowerShell.
    Requires Administrator rights.
    Returns True on success, False otherwise (prints instructions).
    """
    if _winreg is None:
        print("[setup] Non-Windows — Defender exclusion not applicable.")
        return True

    if not _is_admin():
        print("[setup] Defender exclusion requires Administrator rights.")
        print("[setup] Run this once in an elevated PowerShell to add it manually:")
        print(f'         Add-MpPreference -ExclusionPath "{path}"')
        return False

    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f'Add-MpPreference -ExclusionPath "{path}"',
            ],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode == 0:
            print(f"[setup] Defender exclusion added: {path}")
            return True
        err = result.stderr.strip() or result.stdout.strip()
        print(f"[setup] Defender exclusion failed: {err}")
        return False
    except Exception as exc:
        print(f"[setup] Defender exclusion error: {exc}")
        return False


def remove_defender_exclusion(path: Path) -> None:
    if _winreg is None or not _is_admin():
        return
    try:
        subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f'Remove-MpPreference -ExclusionPath "{path}"',
            ],
            capture_output=True, timeout=20,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Startup registry key (HKCU — no admin needed)
# ---------------------------------------------------------------------------

def add_startup() -> bool:
    """
    Register AI Sentinel in HKCU\\...\\Run so it starts at login.
    Uses pythonw.exe (no console window) if available, otherwise python.exe.
    Returns True on success.
    """
    if _winreg is None:
        print("[setup] Non-Windows — startup registration not applicable.")
        return True

    python_exe = Path(sys.executable)
    # Prefer pythonw.exe — no terminal window when starting at login
    pythonw = python_exe.parent / "pythonw.exe"
    runner  = str(pythonw) if pythonw.exists() else str(python_exe)

    main_module = str(ROOT / "privacy" / "privacy_main.py")
    cmd = f'"{runner}" "{main_module}"'

    try:
        key = _winreg.OpenKey(
            _winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, _winreg.KEY_SET_VALUE
        )
        _winreg.SetValueEx(key, APP_NAME, 0, _winreg.REG_SZ, cmd)
        _winreg.CloseKey(key)
        print(f"[setup] Added to Windows startup ({APP_NAME}).")
        print(f"        Command: {cmd}")
        return True
    except Exception as exc:
        print(f"[setup] Failed to add startup entry: {exc}")
        return False


def remove_startup() -> None:
    if _winreg is None:
        return
    try:
        key = _winreg.OpenKey(
            _winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, _winreg.KEY_SET_VALUE
        )
        _winreg.DeleteValue(key, APP_NAME)
        _winreg.CloseKey(key)
        print("[setup] Removed from Windows startup.")
    except FileNotFoundError:
        print("[setup] Not in startup — nothing to remove.")
    except Exception as exc:
        print(f"[setup] Could not remove startup entry: {exc}")


def is_in_startup() -> bool:
    if _winreg is None:
        return False
    try:
        key = _winreg.OpenKey(
            _winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, _winreg.KEY_READ
        )
        _winreg.QueryValueEx(key, APP_NAME)
        _winreg.CloseKey(key)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Interactive setup wizard
# ---------------------------------------------------------------------------

def setup(interactive: bool = True) -> None:
    """
    Run the full setup wizard.
    interactive=True: prompt the user before each step.
    interactive=False: perform all steps without prompts (for scripted install).
    """
    i2p_dir = ROOT / "data" / "i2p"
    i2p_dir.mkdir(parents=True, exist_ok=True)

    print()
    print("=" * 56)
    print("  AI SENTINEL — FIRST-TIME SETUP")
    print("=" * 56)

    # ── Step 1: Defender exclusion ──────────────────────────────
    print("""
Step 1/2 — Windows Defender exclusion
  i2pd.exe is the I2P anonymity router AI Sentinel uses.
  Windows Defender sometimes flags it as a false positive
  (Trojan:Win32/Ravartar!rfn) because it creates encrypted
  network tunnels. It is the official open-source binary from
  github.com/PurpleI2P — not malware.

  Adding data/i2p/ to Defender's exclusion list prevents it
  being quarantined. This requires Administrator rights.
""")

    do_defender = True
    if interactive:
        ans = input("  Add Defender exclusion for data/i2p/? [Y/n] ").strip().lower()
        do_defender = ans in ("", "y", "yes")

    if do_defender:
        ok = add_defender_exclusion(i2p_dir)
        if not ok and interactive:
            print()
            print("  If you want to add it manually, open PowerShell as Administrator and run:")
            print(f'    Add-MpPreference -ExclusionPath "{i2p_dir}"')
    else:
        print("  Skipped. Re-run with --setup if Defender quarantines i2pd.exe.")

    # ── Step 2: Windows startup ─────────────────────────────────
    print("""
Step 2/2 — Windows startup
  Register AI Sentinel to start automatically when you log in.
  Uses pythonw.exe so no terminal window appears.
  You can remove it later with: python -m privacy.privacy_main --remove-startup
""")

    do_startup = True
    if interactive:
        ans = input("  Add AI Sentinel to Windows startup? [Y/n] ").strip().lower()
        do_startup = ans in ("", "y", "yes")

    if do_startup:
        add_startup()
    else:
        print("  Skipped. Run 'python -m privacy.privacy_main' manually to start.")

    print()
    print("=" * 56)
    print("  Setup complete. Run: python -m privacy.privacy_main")
    print("=" * 56)
    print()
