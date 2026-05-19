"""
AI Sentinel system tray icon (Windows).

Shows a coloured shield icon in the system tray so the user can see
protection status at a glance without keeping a terminal open.

States:
  GREEN  — ACTIVE: scanning + I2P routing running
  YELLOW — SCANNING ONLY: proxy running but no anonymous routing
  RED    — THREAT: a threat was detected in the last 30 seconds
  GREY   — STARTING / STOPPED

Requires: pip install pystray pillow
"""
import sys
import time
import threading
import traceback
from pathlib import Path
from enum import Enum

ROOT    = Path(__file__).parent.parent
_LOG    = ROOT / "data" / "sentinel_startup.log"
sys.path.insert(0, str(ROOT))


class TrayState(Enum):
    STARTING = "starting"
    ACTIVE   = "active"
    SCANNING = "scanning"
    THREAT   = "threat"
    STOPPED  = "stopped"


_state      = TrayState.STARTING
_state_lock = threading.Lock()
_tray_icon  = None


def _tray_log(msg: str) -> None:
    _LOG.parent.mkdir(parents=True, exist_ok=True)
    from datetime import datetime
    line = f"[{datetime.now().strftime('%H:%M:%S')}] [tray] {msg}"
    print(line)
    try:
        with open(_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# State label (tooltip text)
# ---------------------------------------------------------------------------

_SUMMARY = (
    "Protecting against:\n"
    "  Malware & virus domains\n"
    "  Hacker C2 beacons\n"
    "  OTX threat intelligence\n"
    "  WebRTC IP leaks\n"
    "  Canvas fingerprinting\n"
    "  Browser tracking libraries\n"
    "  Plugin/font enumeration\n"
    "  External IP probes"
)


def _label() -> str:
    with _state_lock:
        s = _state
    # Keep tooltip short — Windows truncates long tray tooltips
    return {
        TrayState.STARTING: "AI Sentinel\nStarting...",
        TrayState.ACTIVE:   "AI Sentinel\nACTIVE — I2P + Scanning\nProtecting against 8 threat types",
        TrayState.SCANNING: "AI Sentinel\nScanning Only (no routing)\nProtecting against 8 threat types",
        TrayState.THREAT:   "AI Sentinel\n⚠ THREAT DETECTED\nCheck notification for details",
        TrayState.STOPPED:  "AI Sentinel\nStopped",
    }.get(s, "AI Sentinel")


# ---------------------------------------------------------------------------
# Icon drawing
# ---------------------------------------------------------------------------

def _make_icon(state: TrayState):
    from PIL import Image, ImageDraw

    _COLOURS = {
        TrayState.STARTING: "#6b7280",
        TrayState.ACTIVE:   "#22c55e",   # green
        TrayState.SCANNING: "#f59e0b",   # amber — bolder than yellow
        TrayState.THREAT:   "#ef4444",   # red
        TrayState.STOPPED:  "#6b7280",   # grey
    }
    colour = _COLOURS.get(state, "#6b7280")

    size = 64
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Dark pill background — makes icon pop on both light and dark taskbars
    draw.rounded_rectangle([2, 2, 62, 62], radius=12, fill="#0f172a")

    # Shield body — fills most of the dark background
    shield = [(32,6), (56,15), (56,38), (32,58), (8,38), (8,15)]
    draw.polygon(shield, fill=colour)

    # White "S" lettermark (bold rectangles, readable at 16 px)
    lx, rx = 21, 43
    draw.rectangle([lx, 14, rx, 22], fill="white")       # top bar
    draw.rectangle([lx, 14, lx+8, 34], fill="white")     # top-left stroke
    draw.rectangle([lx, 30, rx, 38], fill="white")       # mid bar
    draw.rectangle([rx-8, 34, rx, 52], fill="white")     # bottom-right stroke
    draw.rectangle([lx, 44, rx, 52], fill="white")       # bottom bar

    return img


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def set_state(state: TrayState, *, threat_host: str = "") -> None:
    global _state
    with _state_lock:
        _state = state
    if _tray_icon:
        try:
            _tray_icon.icon  = _make_icon(state)
            title = _label()
            if state == TrayState.THREAT and threat_host:
                title += f"\n{threat_host}"
            _tray_icon.title = title
        except Exception:
            pass


def _open_log() -> None:
    import subprocess
    log = ROOT / "data" / "privacy_threats.json"
    target = str(log) if log.exists() else str(ROOT / "data")
    subprocess.Popen(["explorer.exe", target])


def start(stop_callback) -> None:
    """
    Start the tray icon using pystray.run_detached() — non-blocking,
    pystray manages its own Win32 message pump thread internally.
    Falls back gracefully if pystray or Pillow are not installed.
    """
    global _tray_icon

    try:
        import pystray
    except ImportError:
        _tray_log("pystray not installed — run: pip install pystray pillow")
        return

    try:
        from PIL import Image
    except ImportError:
        _tray_log("Pillow not installed — run: pip install pillow")
        return

    try:
        icon_img = _make_icon(TrayState.STARTING)
    except Exception as exc:
        _tray_log(f"Icon draw failed: {exc} — using blank icon")
        icon_img = Image.new("RGB", (64, 64), color=(136, 136, 136))

    try:
        _tray_icon = pystray.Icon(
            name  = "ai-sentinel",
            icon  = icon_img,
            title = _label(),
            menu  = pystray.Menu(
                pystray.MenuItem(
                    text    = lambda item: _label(),
                    action  = lambda icon, item: None,
                    enabled = False,
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(
                    "Open threat log",
                    lambda icon, item: _open_log(),
                ),
                pystray.MenuItem(
                    "Stop AI Sentinel",
                    lambda icon, item: stop_callback(),
                ),
            ),
        )
        # run_detached() is non-blocking and manages its own Win32 thread —
        # more reliable than wrapping run() in our own daemon thread.
        _tray_icon.run_detached()
        _tray_log("Tray icon visible in system tray.")
    except Exception:
        _tray_log("Tray icon failed to start:\n" + traceback.format_exc())


def stop() -> None:
    global _tray_icon
    if _tray_icon:
        try:
            set_state(TrayState.STOPPED)
            time.sleep(0.3)
            _tray_icon.stop()
        except Exception:
            pass
        _tray_icon = None
