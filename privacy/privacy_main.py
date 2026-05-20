"""
AI Sentinel — Privacy Layer entry point.

Usage:
    python -m privacy.privacy_main [--no-nym] [--proxy-port 8877]

What this does:
  1. Loads / generates your Ed25519 identity (public key = your only address).
  2. Starts the Nym SOCKS5 client (anonymous mixnet routing).
  3. Starts the AI Sentinel scanning proxy (mitmproxy addon) on --proxy-port.
     All traffic flowing through the proxy is scanned for malware, C2 beacons,
     and de-anonymization attempts before reaching you or the network.
  4. Sets the Windows system proxy to 127.0.0.1:<proxy-port> so all
     WinINet-based traffic goes through this stack automatically.
  5. On Ctrl-C: clears the system proxy and shuts everything down cleanly.

First run:
  • Nym binary (~15 MB) will be downloaded and a mixnet identity initialised.
  • mitmproxy will generate a CA certificate at %USERPROFILE%\.mitmproxy\
  • Run `setup_certificates()` below (or call privacy_main.py --setup-certs)
    to install the CA cert into Windows so HTTPS scanning works in all apps.
"""
import os
import sys
import time
import signal
import shutil
import argparse
import platform
import subprocess
import threading
import traceback
import urllib.parse as _urlparse
from pathlib import Path

_SYSTEM = platform.system()   # "Windows" | "Darwin" | "Linux"

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_STARTUP_LOG = ROOT / "data" / "sentinel_startup.log"


def _log(msg: str) -> None:
    """Write to startup log and stdout. Safe to call before anything is initialised."""
    _STARTUP_LOG.parent.mkdir(parents=True, exist_ok=True)
    from datetime import datetime
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    try:
        with open(_STARTUP_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line)

from dotenv import load_dotenv
from privacy import identity as _identity
from privacy.routing import nym_client as _nym
from privacy.routing import i2p_client as _i2p
from privacy.tray import TrayState
import privacy.tray as _tray

PROXY_HOST = "127.0.0.1"
PROXY_PORT  = 8877


# ---------------------------------------------------------------------------
# Startup notification
# ---------------------------------------------------------------------------

_THREAT_TYPES = [
    "Malware & virus domains (VirusTotal)",
    "Hacker C2 beacon patterns",
    "Threat intelligence feeds (OTX/AbuseIPDB)",
    "WebRTC IP address leaks",
    "Canvas & device fingerprinting",
    "Browser tracking libraries (FingerprintJS etc.)",
    "Plugin & font enumeration tracking",
    "External IP probe scripts",
]

def _show_startup_notification(routing: str | None) -> None:
    route = routing if routing else "Scanning only"
    body  = f"{route} · {len(_THREAT_TYPES)} threat types monitored"
    if _SYSTEM == "Windows":
        try:
            from winotify import Notification
            Notification(app_id="AI Sentinel", title="AI Sentinel — Active",
                         msg=body, duration="short").show()
            return
        except Exception:
            pass
    # macOS / Linux / fallback
    try:
        from plyer import notification as _notif
        _notif.notify(title="AI Sentinel — Active", message=body,
                      app_name="AI Sentinel", timeout=5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# System proxy helpers (Windows + macOS)
# ---------------------------------------------------------------------------

def _mac_network_services() -> list[str]:
    try:
        out = subprocess.check_output(
            ["networksetup", "-listallnetworkservices"],
            text=True, stderr=subprocess.DEVNULL,
        )
        return [l.strip() for l in out.splitlines()
                if l.strip() and not l.lower().startswith("an asterisk")]
    except Exception:
        return ["Wi-Fi", "Ethernet"]


def _set_system_proxy(host: str, port: int) -> None:
    if _SYSTEM == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
            winreg.SetValueEx(key, "ProxyEnable",  0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            print(f"[privacy] System proxy → {host}:{port}")
        except Exception as exc:
            print(f"[privacy] Could not set system proxy: {exc}")
    elif _SYSTEM == "Darwin":
        for svc in _mac_network_services():
            subprocess.run(["networksetup", "-setwebproxy",       svc, host, str(port)],
                           capture_output=True)
            subprocess.run(["networksetup", "-setsecurewebproxy", svc, host, str(port)],
                           capture_output=True)
        print(f"[privacy] macOS system proxy → {host}:{port}")
    else:
        print(f"[privacy] Set your proxy manually to {host}:{port}")


def _clear_system_proxy() -> None:
    if _SYSTEM == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            print("[privacy] System proxy cleared.")
        except Exception:
            pass
    elif _SYSTEM == "Darwin":
        for svc in _mac_network_services():
            subprocess.run(["networksetup", "-setwebproxystate",       svc, "off"],
                           capture_output=True)
            subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "off"],
                           capture_output=True)
        print("[privacy] macOS system proxy cleared.")


# ---------------------------------------------------------------------------
# CA certificate installation (run once so HTTPS scanning works)
# ---------------------------------------------------------------------------

def setup_certificates() -> None:
    """Install mitmproxy's CA certificate into the OS trust store."""
    cert_candidates = [
        Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer",
        Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem",
        Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.p12",
    ]

    if not any(c.exists() for c in cert_candidates):
        print("[privacy] Generating mitmproxy CA certificate ...")
        mitmdump = shutil.which("mitmdump")
        if not mitmdump:
            print("[privacy] mitmdump not found. Run: pip install mitmproxy")
            return
        proc = subprocess.Popen([mitmdump, "--quiet", "--listen-port", "18877"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        proc.terminate()
        proc.wait()

    cert_path = next((c for c in cert_candidates if c.exists()), None)
    if not cert_path:
        print("[privacy] Could not locate mitmproxy CA cert. Run mitmdump once first.")
        return

    print(f"[privacy] Installing CA cert: {cert_path}")

    if _SYSTEM == "Windows":
        result = subprocess.run(
            ["certutil", "-addstore", "-user", "Root", str(cert_path)],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print("[privacy] CA certificate installed. HTTPS scanning is active.")
        else:
            print(f"[privacy] certutil failed: {result.stderr.strip()}")
            print("[privacy] Try running as Administrator or install the cert manually.")

    elif _SYSTEM == "Darwin":
        result = subprocess.run(
            ["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
             "-k", "/Library/Keychains/System.keychain", str(cert_path)],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print("[privacy] CA certificate installed. HTTPS scanning is active.")
        else:
            print(f"[privacy] security command failed: {result.stderr.strip()}")
            print(f"[privacy] Install manually: sudo security add-trusted-cert -d -r trustRoot "
                  f"-k /Library/Keychains/System.keychain {cert_path}")
    else:
        print(f"[privacy] Install the CA cert manually from: {cert_path}")
        print("[privacy] On Debian/Ubuntu: sudo cp cert.pem /usr/local/share/ca-certificates/ && sudo update-ca-certificates")


# ---------------------------------------------------------------------------
# Scanning proxy launcher
# ---------------------------------------------------------------------------

def _start_proxy(upstream: str | None, port: int) -> subprocess.Popen:
    addon = Path(__file__).parent / "proxy" / "sentinel_proxy.py"
    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        sys.exit("[privacy] ERROR: mitmdump not found. Run: pip install mitmproxy")

    cmd = [
        mitmdump,
        "--listen-host", PROXY_HOST,
        "--listen-port", str(port),
        "-s", str(addon),
        "--set", "ssl_insecure=true",
        "--quiet",
    ]
    if upstream:
        cmd += ["--mode", f"upstream:{upstream}"]

    print(f"[privacy] Scanning proxy on {PROXY_HOST}:{port}"
          + (f" → {upstream}" if upstream else " (direct, no anonymous routing)"))
    _no_window = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    return subprocess.Popen(cmd, cwd=str(ROOT), creationflags=_no_window)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    load_dotenv(ROOT / "app" / ".env")

    parser = argparse.ArgumentParser(description="AI Sentinel Privacy Layer")
    parser.add_argument("--route", choices=["nym", "i2p", "none"], default="i2p",
                        help="Anonymous routing backend (default: i2p)")
    parser.add_argument("--proxy-port",  type=int, default=PROXY_PORT,
                        help=f"Local scanning proxy port (default: {PROXY_PORT})")
    parser.add_argument("--setup-certs", action="store_true",
                        help="Install mitmproxy CA cert then exit")
    parser.add_argument("--setup", action="store_true",
                        help="Run first-time setup wizard (Defender exclusion + autostart)")
    parser.add_argument("--remove-startup", action="store_true",
                        help="Remove AI Sentinel from Windows startup and exit")
    args = parser.parse_args()

    if args.setup_certs:
        setup_certificates()
        return

    if args.setup:
        from privacy.autostart import setup as _run_setup
        _run_setup(interactive=True)
        return

    if args.remove_startup:
        from privacy.autostart import remove_startup as _rm
        _rm()
        return

    print("=" * 62)
    print("  AI SENTINEL — PRIVACY LAYER")
    print("=" * 62)

    # Start tray icon early so the user sees it immediately
    def _tray_stop():
        import signal as _sig
        import os as _os
        _os.kill(_os.getpid(), _sig.SIGINT)

    _tray.start(_tray_stop)

    # 1. Cryptographic identity
    ident = _identity.load_or_create()
    print(f"\n  Your Sentinel Address (public key — this is your only ID):")
    print(f"  {ident['address']}\n")

    # 2. Anonymous routing
    upstream: str | None = None
    routing_label = "DISABLED"

    try:
        if args.route == "none":
            print("[privacy] --route=none: scanning proxy only, no anonymous routing.")

        elif args.route == "i2p":
            print("[privacy] Starting I2P routing (i2pd) ...")
            try:
                if _i2p.start():
                    upstream      = _i2p.socks5_upstream()
                    routing_label = "I2P  (garlic routing)"
                else:
                    print("[privacy] i2pd port did not open — running without routing.")
            except Exception as exc:
                print(f"[privacy] I2P failed: {exc}")
                print("[privacy] Running with scanning proxy only.")

        elif args.route == "nym":
            print("[privacy] Starting Nym mixnet client ...")
            try:
                if _nym.start():
                    upstream      = _nym.socks5_upstream()
                    routing_label = "Nym mixnet"
                else:
                    print("[privacy] Nym port did not open — running without routing.")
            except RuntimeError as exc:
                print(f"\n[privacy] Nym unavailable: {exc}")
                print("[privacy] Run with --route=i2p or --route=none.")

    except KeyboardInterrupt:
        print("\n[privacy] Interrupted during startup — cleaning up ...")
        if _nym.is_running():
            _nym.stop()
        if _i2p.is_running():
            _i2p.stop()
        sys.exit(0)

    # 3. If routing is SOCKS5, bridge it to HTTP so mitmproxy can chain through it.
    #    mitmproxy --mode upstream only accepts http:// — not socks5://.
    if upstream and upstream.startswith("socks5://"):
        from privacy.routing import socks5_bridge as _bridge
        parsed     = _urlparse.urlparse(upstream)
        s5_host    = parsed.hostname or "127.0.0.1"
        s5_port    = parsed.port    or 1080
        bridge_thread = threading.Thread(
            target=_bridge.run,
            kwargs={"bridge_port": 8878, "socks5_host": s5_host, "socks5_port": s5_port},
            daemon=True,
            name="socks5-bridge",
        )
        bridge_thread.start()
        time.sleep(0.3)           # let the asyncio server bind
        upstream = "http://127.0.0.1:8878"

    # 5. Scanning proxy
    proxy = _start_proxy(upstream, args.proxy_port)
    time.sleep(1)  # give mitmdump a moment to bind the port

    # 6. System proxy
    _set_system_proxy(PROXY_HOST, args.proxy_port)

    # Hint first-time users about setup wizard
    from privacy.autostart import is_in_startup
    if not is_in_startup():
        print("[privacy] Tip: run with --setup to add autostart + Defender exclusion.")

    # Update tray to reflect actual running state
    _tray.set_state(TrayState.ACTIVE if upstream else TrayState.SCANNING)

    # Show startup notification so the user knows protection is active
    _show_startup_notification(routing_label if upstream else None)

    print(f"""
[privacy] ACTIVE
  Scanning proxy  : {PROXY_HOST}:{args.proxy_port}
  Anonymous route : {routing_label if upstream else "DISABLED — traffic is scanned but real IP is visible"}
  Threat layers   : VT domain lookup + OTX pulses + C2 heuristics + Deanon scanner + Fingerprint Poisoning
  Identity        : {ident['address'][:32]}...
  Threat log      : data/privacy_threats.json

  Press Ctrl-C to stop and restore normal networking.
""")

    # 7. Graceful shutdown on SIGINT / SIGTERM
    def _shutdown(sig, _frame):
        print("\n[privacy] Shutting down ...")
        _tray.stop()
        _clear_system_proxy()
        proxy.terminate()
        proxy.wait(timeout=5)
        if _nym.is_running():
            _nym.stop()
        if _i2p.is_running():
            _i2p.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # 8. Watch the proxy process — restart it if it dies unexpectedly.
    #    Give up after 3 consecutive fast failures (< 10 s) to avoid an
    #    infinite loop when mitmproxy itself has a startup error.
    consecutive_failures = 0
    last_start_time = time.time()

    while True:
        time.sleep(5)
        if proxy.poll() is not None:
            uptime = time.time() - last_start_time
            if uptime < 10:
                consecutive_failures += 1
            else:
                consecutive_failures = 1  # reset — it ran for a while

            if consecutive_failures >= 3:
                _clear_system_proxy()
                sys.exit(
                    "\n[privacy] ERROR: Scanning proxy crashed 3 times in a row within 10 s.\n"
                    "  This usually means mitmproxy has a dependency problem.\n"
                    "  Fix: pip install bcrypt==4.0.1   (resolves passlib/bcrypt conflict)\n"
                    "  Then restart: python -m privacy.privacy_main\n"
                )

            print(f"[privacy] Scanning proxy exited (failure {consecutive_failures}/3) — restarting ...")
            _clear_system_proxy()
            last_start_time = time.time()
            proxy = _start_proxy(upstream, args.proxy_port)
            time.sleep(1)
            _set_system_proxy(PROXY_HOST, args.proxy_port)


if __name__ == "__main__":
    try:
        _log("AI Sentinel starting up.")
        main()
    except SystemExit:
        raise   # clean exits (Ctrl-C, --setup, etc.) pass through normally
    except Exception:
        tb = traceback.format_exc()
        _log("CRASH — unhandled exception:\n" + tb)
        try:
            if _SYSTEM == "Windows":
                import ctypes
                ctypes.windll.user32.MessageBoxW(
                    0,
                    f"AI Sentinel crashed on startup.\n\nError log: {_STARTUP_LOG}\n\n{tb[-800:]}",
                    "AI Sentinel — Startup Error",
                    0x10,
                )
            elif _SYSTEM == "Darwin":
                subprocess.run(
                    ["osascript", "-e",
                     f'display alert "AI Sentinel crashed." '
                     f'message "Check log: {_STARTUP_LOG}"'],
                    check=False,
                )
        except Exception:
            pass
        sys.exit(1)
