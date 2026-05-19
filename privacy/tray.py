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
If pystray is not installed the tray starts in no-op mode (no error).
"""
import sys
import time
import threading
from pathlib import Path
from enum import Enum

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


class TrayState(Enum):
    STARTING  = "starting"
    ACTIVE    = "active"       # proxy + routing
    SCANNING  = "scanning"     # proxy only, no routing
    THREAT    = "threat"       # threat detected recently
    STOPPED   = "stopped"


# Shared state — updated by privacy_main, read by tray thread
_state      = TrayState.STARTING
_state_lock = threading.Lock()
_tray_icon  = None   # pystray.Icon instance, set once tray starts


def _state_label() -> str:
    labels = {
        TrayState.STARTING: "AI Sentinel — Starting...",
        TrayState.ACTIVE:   "AI Sentinel — ACTIVE (I2P + Scanning)",
        TrayState.SCANNING: "AI Sentinel — Scanning Only",
        TrayState.THREAT:   "AI Sentinel — THREAT DETECTED",
        TrayState.STOPPED:  "AI Sentinel — Stopped",
    }
    return labels.get(_state, "AI Sentinel")


# ---------------------------------------------------------------------------
# Icon drawing (PIL — no external image files needed)
# ---------------------------------------------------------------------------

def _draw_icon(state: TrayState):
    """Draw a 64×64 shield icon in the colour matching the given state."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return None

    colours = {
        TrayState.STARTING: "#888888",
        TrayState.ACTIVE:   "#22c55e",   # green
        TrayState.SCANNING: "#eab308",   # yellow
        TrayState.THREAT:   "#ef4444",   # red
        TrayState.STOPPED:  "#6b7280",   # grey
    }
    colour = colours.get(state, "#888888")

    img  = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield outline: a pentagon-ish shape
    shield = [
        (32, 4), (58, 16), (58, 36),
        (32, 60), (6, 36), (6, 16),
    ]
    draw.polygon(shield, fill=colour)

    # White "S" lettermark in the centre
    draw.text((22, 20), "S", fill="white")

    return img


# ---------------------------------------------------------------------------
# Public API — called from privacy_main.py
# ---------------------------------------------------------------------------

def set_state(state: TrayState, *, threat_host: str = "") -> None:
    """Update tray icon state. Thread-safe."""
    global _state
    with _state_lock:
        _state = state
    if _tray_icon:
        try:
            _tray_icon.icon  = _draw_icon(state)
            _tray_icon.title = _state_label()
            if state == TrayState.THREAT and threat_host:
                _tray_icon.title += f"\n{threat_host}"
        except Exception:
            pass


def _build_menu(stop_callback):
    try:
        import pystray
        return pystray.Menu(
            pystray.MenuItem(_state_label, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open threat log", _open_log),
            pystray.MenuItem("Stop AI Sentinel", stop_callback),
        )
    except ImportError:
        return None


def _open_log():
    import subprocess
    log = ROOT / "data" / "privacy_threats.json"
    if log.exists():
        subprocess.Popen(["notepad.exe", str(log)])


def start(stop_callback) -> None:
    """
    Start the tray icon in a daemon thread.
    stop_callback() is called when the user clicks "Stop AI Sentinel".
    Returns immediately — tray runs in background.
    If pystray or Pillow are not installed, silently does nothing.
    """
    try:
        import pystray
        from PIL import Image
    except ImportError:
        print("[tray] pystray/Pillow not installed — no tray icon. "
              "Run: pip install pystray pillow")
        return

    global _tray_icon

    icon_img = _draw_icon(TrayState.STARTING) or Image.new("RGB", (64, 64), "#888888")

    def _run():
        global _tray_icon
        _tray_icon = pystray.Icon(
            name  = "ai-sentinel",
            icon  = icon_img,
            title = _state_label(),
            menu  = pystray.Menu(
                pystray.MenuItem(lambda text, item: _state_label(), None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Open threat log", lambda: _open_log()),
                pystray.MenuItem("Stop AI Sentinel", lambda: stop_callback()),
            ),
        )
        _tray_icon.run()

    t = threading.Thread(target=_run, daemon=True, name="tray-icon")
    t.start()
    print("[tray] System tray icon started.")


def stop() -> None:
    """Remove the tray icon (call on shutdown)."""
    global _tray_icon
    if _tray_icon:
        try:
            set_state(TrayState.STOPPED)
            time.sleep(0.2)
            _tray_icon.stop()
        except Exception:
            pass
        _tray_icon = None
