"""
Cross-platform autostart and AV-exclusion setup for AI Sentinel.

Windows:
  - Autostart via HKCU\\...\\Run registry key (no admin needed)
  - Defender exclusion via Add-MpPreference (requires admin; prints manual
    instructions if not elevated)

macOS:
  - Autostart via ~/Library/LaunchAgents/com.ai-sentinel.plist
  - No AV exclusion needed (Gatekeeper works differently; i2pd is unsigned
    but running it once and approving in System Settings is sufficient)
"""
import os
import platform
import plistlib
import subprocess
import sys
from pathlib import Path

_SYSTEM  = platform.system()
ROOT     = Path(__file__).parent.parent
APP_NAME = "AI-Sentinel-Privacy"

# Windows registry
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

# macOS LaunchAgent
_PLIST_LABEL = "com.ai-sentinel"
_PLIST_PATH  = Path.home() / "Library" / "LaunchAgents" / f"{_PLIST_LABEL}.plist"

try:
    import winreg as _winreg
except ImportError:
    _winreg = None


# ---------------------------------------------------------------------------
# Elevation helpers (Windows only)
# ---------------------------------------------------------------------------

def _is_admin() -> bool:
    if _SYSTEM != "Windows":
        return os.geteuid() == 0   # root check on Unix
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# AV / security exclusion
# ---------------------------------------------------------------------------

def add_defender_exclusion(path: Path) -> bool:
    """
    Windows: add path to Defender exclusion list (requires admin).
    macOS:   no-op — Gatekeeper doesn't need an exclusion list.
    Returns True if action succeeded or was not needed.
    """
    if _SYSTEM == "Darwin":
        print("[setup] macOS: no Defender exclusion needed.")
        print("[setup] If macOS blocks i2pd, open System Settings → Privacy & Security")
        print("        and click 'Allow Anyway' after the first blocked run.")
        return True

    if _SYSTEM != "Windows" or _winreg is None:
        print("[setup] AV exclusion not applicable on this platform.")
        return True

    if not _is_admin():
        print("[setup] Defender exclusion requires Administrator rights.")
        print("[setup] Run this once in an elevated PowerShell:")
        print(f'         Add-MpPreference -ExclusionPath "{path}"')
        return False

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f'Add-MpPreference -ExclusionPath "{path}"'],
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
    if _SYSTEM != "Windows" or _winreg is None or not _is_admin():
        return
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f'Remove-MpPreference -ExclusionPath "{path}"'],
            capture_output=True, timeout=20,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Startup registration
# ---------------------------------------------------------------------------

def add_startup() -> bool:
    """Register AI Sentinel to launch at login. No admin rights needed."""
    if _SYSTEM == "Windows":
        return _add_startup_windows()
    elif _SYSTEM == "Darwin":
        return _add_startup_macos()
    else:
        print("[setup] Autostart not implemented for Linux.")
        print("[setup] Add this to ~/.profile or a systemd user service:")
        print(f"        python3 -m privacy.privacy_main &")
        return False


def _add_startup_windows() -> bool:
    if _winreg is None:
        print("[setup] winreg not available.")
        return False

    python_exe = Path(sys.executable)
    pythonw    = python_exe.parent / "pythonw.exe"
    runner     = str(pythonw) if pythonw.exists() else str(python_exe)
    cmd        = f'"{runner}" "{ROOT / "privacy" / "privacy_main.py"}"'

    try:
        key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, _winreg.KEY_SET_VALUE)
        _winreg.SetValueEx(key, APP_NAME, 0, _winreg.REG_SZ, cmd)
        _winreg.CloseKey(key)
        print(f"[setup] Added to Windows startup ({APP_NAME}).")
        return True
    except Exception as exc:
        print(f"[setup] Failed to add startup entry: {exc}")
        return False


def _add_startup_macos() -> bool:
    _PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    plist = {
        "Label":            _PLIST_LABEL,
        "ProgramArguments": [sys.executable, "-m", "privacy.privacy_main"],
        "WorkingDirectory": str(ROOT),
        "RunAtLoad":        True,
        "KeepAlive":        False,
        "StandardOutPath":  str(ROOT / "data" / "sentinel_stdout.log"),
        "StandardErrorPath":str(ROOT / "data" / "sentinel_stderr.log"),
    }
    try:
        with open(_PLIST_PATH, "wb") as f:
            plistlib.dump(plist, f)
        subprocess.run(["launchctl", "load", str(_PLIST_PATH)],
                       capture_output=True)
        print(f"[setup] macOS LaunchAgent installed: {_PLIST_PATH}")
        print("[setup] AI Sentinel will start automatically at next login.")
        return True
    except Exception as exc:
        print(f"[setup] Failed to install LaunchAgent: {exc}")
        return False


def remove_startup() -> None:
    if _SYSTEM == "Windows":
        if _winreg is None:
            return
        try:
            key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, _winreg.KEY_SET_VALUE)
            _winreg.DeleteValue(key, APP_NAME)
            _winreg.CloseKey(key)
            print("[setup] Removed from Windows startup.")
        except FileNotFoundError:
            print("[setup] Not in startup — nothing to remove.")
        except Exception as exc:
            print(f"[setup] Could not remove startup entry: {exc}")

    elif _SYSTEM == "Darwin":
        if _PLIST_PATH.exists():
            subprocess.run(["launchctl", "unload", str(_PLIST_PATH)],
                           capture_output=True)
            _PLIST_PATH.unlink()
            print("[setup] macOS LaunchAgent removed.")
        else:
            print("[setup] Not in startup — nothing to remove.")


def is_in_startup() -> bool:
    if _SYSTEM == "Windows":
        if _winreg is None:
            return False
        try:
            key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, _winreg.KEY_READ)
            _winreg.QueryValueEx(key, APP_NAME)
            _winreg.CloseKey(key)
            return True
        except Exception:
            return False
    elif _SYSTEM == "Darwin":
        return _PLIST_PATH.exists()
    return False


# ---------------------------------------------------------------------------
# Interactive setup wizard
# ---------------------------------------------------------------------------

def setup(interactive: bool = True) -> None:
    i2p_dir = ROOT / "data" / "i2p"
    i2p_dir.mkdir(parents=True, exist_ok=True)

    print()
    print("=" * 56)
    print("  AI SENTINEL — FIRST-TIME SETUP")
    print("=" * 56)

    # ── Step 1: AV exclusion ────────────────────────────────────
    if _SYSTEM == "Windows":
        print("""
Step 1/2 — Windows Defender exclusion
  i2pd.exe is the I2P anonymity router AI Sentinel uses.
  Defender sometimes flags it as a false positive. Adding
  data/i2p/ to exclusions prevents quarantine.
  Requires Administrator rights.
""")
        do_defender = True
        if interactive:
            ans = input("  Add Defender exclusion for data/i2p/? [Y/n] ").strip().lower()
            do_defender = ans in ("", "y", "yes")
        if do_defender:
            ok = add_defender_exclusion(i2p_dir)
            if not ok and interactive:
                print(f'\n  Manual fix: Add-MpPreference -ExclusionPath "{i2p_dir}"')
        else:
            print("  Skipped.")

    elif _SYSTEM == "Darwin":
        print("""
Step 1/2 — macOS security note
  i2pd is an unsigned binary. The first time it runs, macOS
  may block it. If that happens:
    System Settings → Privacy & Security → click "Allow Anyway"
  You only need to do this once.
""")
        input("  Press Enter to continue...")

    # ── Step 2: Startup ─────────────────────────────────────────
    if _SYSTEM == "Windows":
        startup_desc = "Windows startup (HKCU Run key — no admin needed)"
    elif _SYSTEM == "Darwin":
        startup_desc = "macOS startup (LaunchAgent in ~/Library/LaunchAgents/)"
    else:
        startup_desc = "startup"

    print(f"""
Step 2/2 — {startup_desc}
  Register AI Sentinel to start automatically at login.
  Remove later with: python -m privacy.privacy_main --remove-startup
""")

    do_startup = True
    if interactive:
        ans = input("  Add AI Sentinel to startup? [Y/n] ").strip().lower()
        do_startup = ans in ("", "y", "yes")

    if do_startup:
        add_startup()
    else:
        print("  Skipped.")

    print()
    print("=" * 56)
    print("  Setup complete.")
    if _SYSTEM == "Darwin":
        print("  Run: python3 -m privacy.privacy_main")
    else:
        print("  Run: python -m privacy.privacy_main")
    print("=" * 56)
    print()
