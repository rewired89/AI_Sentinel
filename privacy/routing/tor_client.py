"""
Tor routing manager for Windows.

Downloads the Tor Expert Bundle (official Tor Project release — no browser,
just the tor.exe daemon), starts it as a background process, and exposes a
SOCKS5 proxy on 127.0.0.1:9050 for mitmproxy to upstream through.

Why Tor here when the user was sceptical?
  The original objection was to Tails (USB-based OS) and the general UX
  friction of Tor Browser. The Tor *protocol* is the right tool for Windows
  right now because:
    • Nym has dropped Windows binaries in every 2026 release.
    • Tor's Windows Expert Bundle is actively maintained and ~15 MB.
    • For the threat model we care about (ISP tracking, ad fingerprinting,
      casual surveillance) Tor is more than sufficient.
    • A determined nation-state adversary with full network visibility can
      theoretically do timing correlation on Tor — but that is not the
      realistic threat for 99 % of users.

Tor SOCKS5 is on 127.0.0.1:9050 by default (same port Tor Browser uses).
"""
import json
import platform
import socket
import subprocess
import time
import urllib.request
import zipfile
from pathlib import Path

_SYSTEM  = platform.system()
TOR_DIR  = Path(__file__).parent.parent.parent / "data" / "tor"
TOR_BIN  = TOR_DIR / ("tor.exe" if _SYSTEM == "Windows" else "tor")
TOR_PORT = 9050

# Tor Project's official Expert Bundle for Windows (no browser, just the daemon).
# Always check https://www.torproject.org/download/tor/ for the latest URL.
_DOWNLOAD_URLS = {
    "Windows": "https://archive.torproject.org/tor-package-archive/torbrowser/14.5.1/tor-expert-bundle-windows-x86_64-14.5.1.tar.gz",
    "Linux":   "https://archive.torproject.org/tor-package-archive/torbrowser/14.5.1/tor-expert-bundle-linux-x86_64-14.5.1.tar.gz",
    "Darwin":  "https://archive.torproject.org/tor-package-archive/torbrowser/14.5.1/tor-expert-bundle-macos-x86_64-14.5.1.tar.gz",
}

_nym_proc: subprocess.Popen | None = None   # kept for API symmetry
_tor_proc: subprocess.Popen | None = None


def is_downloaded() -> bool:
    return TOR_BIN.exists()


def _download_file(url: str, dest: Path) -> None:
    headers = {"User-Agent": "AI-Sentinel/1.0", "Accept": "application/octet-stream"}
    try:
        import requests as _req
        with _req.get(url, headers=headers, stream=True, timeout=60) as r:
            r.raise_for_status()
            total   = int(r.headers.get("content-length", 0))
            written = 0
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    f.write(chunk)
                    written += len(chunk)
                    if total:
                        pct = min(100, written * 100 // total)
                        print(f"\r[tor] Download: {pct}%", end="", flush=True)
        print()
    except ImportError:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as f:
            f.write(resp.read())


def download() -> None:
    """Download and unpack the Tor Expert Bundle."""
    url = _DOWNLOAD_URLS.get(_SYSTEM)
    if not url:
        raise RuntimeError(f"No Tor bundle URL configured for platform: {_SYSTEM}")

    TOR_DIR.mkdir(parents=True, exist_ok=True)
    archive = TOR_DIR / "tor_dl.tar.gz"

    print(f"[tor] Downloading Tor Expert Bundle (~15 MB) ...")
    _download_file(url, archive)

    print("[tor] Unpacking ...")
    import tarfile
    with tarfile.open(archive) as tf:
        tf.extractall(TOR_DIR)
    archive.unlink(missing_ok=True)

    # The bundle extracts to a sub-folder like tor/tor.exe — find it
    if not TOR_BIN.exists():
        found = list(TOR_DIR.rglob("tor.exe" if _SYSTEM == "Windows" else "tor"))
        # Exclude tor-browser variants
        found = [p for p in found if "browser" not in str(p).lower()]
        if found:
            found[0].rename(TOR_BIN)

    if not TOR_BIN.exists():
        raise RuntimeError(
            f"[tor] tor binary not found after unpack.\n"
            f"  Expected: {TOR_BIN}\n"
            f"  Check {TOR_DIR}"
        )

    if _SYSTEM != "Windows":
        TOR_BIN.chmod(0o755)

    print(f"[tor] Binary ready: {TOR_BIN}")


def start() -> bool:
    """
    Start the Tor daemon in the background.
    Returns True when the SOCKS5 port is accepting connections.
    """
    global _tor_proc

    if not is_downloaded():
        print("[tor] Tor not found. Downloading ...")
        download()

    if _tor_proc and _tor_proc.poll() is None:
        print(f"[tor] Already running on port {TOR_PORT}.")
        return True

    log_path = TOR_DIR / "tor.log"
    print(f"[tor] Starting Tor (log → {log_path}) ...")

    with open(log_path, "a") as lf:
        _tor_proc = subprocess.Popen(
            [str(TOR_BIN)],
            stdout=lf,
            stderr=lf,
            cwd=str(TOR_DIR),
        )

    # Tor typically bootstraps within 10–30 s; poll for up to 45 s
    for _ in range(90):
        try:
            with socket.create_connection(("127.0.0.1", TOR_PORT), timeout=1):
                pass
            print(f"[tor] SOCKS5 proxy ready on 127.0.0.1:{TOR_PORT}")
            return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)

    print("[tor] Warning: Tor SOCKS5 port did not open within 45 s.")
    print("[tor] Tor may still be bootstrapping — check data/tor/tor.log")
    return False


def stop() -> None:
    global _tor_proc
    if _tor_proc and _tor_proc.poll() is None:
        _tor_proc.terminate()
        try:
            _tor_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _tor_proc.kill()
        print("[tor] Tor stopped.")
    _tor_proc = None


def is_running() -> bool:
    return _tor_proc is not None and _tor_proc.poll() is None


def socks5_upstream() -> str:
    return f"socks5h://127.0.0.1:{TOR_PORT}"
