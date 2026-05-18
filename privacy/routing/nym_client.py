"""
Nym SOCKS5 client manager.

Downloads the pre-built Nym binary, initialises a client config, and runs the
client as a background subprocess. The Nym client exposes a SOCKS5 proxy on
127.0.0.1:1080 — mitmproxy is configured to upstream all traffic through it.

Why Nym instead of Tor?
  • Nym uses a mixnet (Sphinx packets) with deliberate mixing delays and cover
    traffic. This defeats timing-correlation attacks that break Tor when the
    adversary controls enough of the network (ISP, state-level).
  • Traffic analysis resistance is Nym's explicit design goal; it is not a
    side-effect of onion routing the way it is with Tor.
  • No exit-node liability for you: you run a client, not a relay.

Trade-off you must accept:
  • Latency. Mixing delays are real — typically 50–200 ms extra per hop.
    This is not a VPN. It is not meant to feel like one.
  • The Nym network is smaller than Tor. Maturity gap exists.
"""
import os
import sys
import time
import json
import socket
import platform
import zipfile
import tarfile
import subprocess
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

NYM_DIR    = Path(__file__).parent.parent.parent / "data" / "nym"
_SYSTEM    = platform.system()
NYM_BIN    = NYM_DIR / ("nym-socks5-client.exe" if _SYSTEM == "Windows" else "nym-socks5-client")

# Platform-specific asset name hints, tried in order from strictest to loosest.
# Nym has changed their release naming across versions (used to include the
# target triple like "x86_64-pc-windows-msvc", now sometimes just "nym-socks5-client").
# We try each tier and accept the first match.
_ASSET_TIERS = {
    "Windows": [
        ("nym-socks5-client", "windows"),   # e.g. nym-socks5-client-windows.zip
        ("nym-socks5-client", "msvc"),       # e.g. ...-x86_64-pc-windows-msvc.zip
        ("nym-socks5-client", "win"),        # any "win" variant
        ("nym-socks5-client",),              # bare name — last resort
    ],
    "Linux": [
        ("nym-socks5-client", "linux"),
        ("nym-socks5-client", "musl"),
        ("nym-socks5-client", "gnu"),
        ("nym-socks5-client",),
    ],
    "Darwin": [
        ("nym-socks5-client", "darwin"),
        ("nym-socks5-client", "macos"),
        ("nym-socks5-client", "apple"),
        ("nym-socks5-client",),
    ],
}

GITHUB_API = "https://api.github.com/repos/nymtech/nym/releases/latest"

NYM_CONFIG_ID  = "sentinel-client"
NYM_SOCKS5_PORT = 1080

_nym_proc: subprocess.Popen | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_downloaded() -> bool:
    return NYM_BIN.exists()


def _resolve_download_url() -> tuple[str, bool]:
    """
    Ask the GitHub API for the latest Nym release and return
    (download_url, _unused) for this platform's socks5-client asset.
    Format detection is now done by reading magic bytes after download.

    Tries asset name tiers from strictest to loosest so that a bare
    'nym-socks5-client' asset (Nym's newer single-file releases) is
    accepted when no platform-tagged variant exists.
    """
    tiers = _ASSET_TIERS.get(_SYSTEM)
    if not tiers:
        raise RuntimeError(f"No Nym binary available for platform: {_SYSTEM}")

    print("[nym] Checking GitHub for latest Nym release ...")
    req = urllib.request.Request(GITHUB_API, headers={"User-Agent": "AI-Sentinel"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())

    tag    = data.get("tag_name", "unknown")
    assets = data.get("assets", [])

    # Build a lookup: lowercase name → asset dict
    by_name = {a.get("name", "").lower(): a for a in assets}
    socks5_assets = [n for n in by_name if "socks5" in n]

    for tier in tiers:
        for name_lower, asset in by_name.items():
            if all(frag.lower() in name_lower for frag in tier):
                url    = asset["browser_download_url"]
                is_zip = url.lower().endswith(".zip") or name_lower.endswith(".exe")
                print(f"[nym] Asset matched: {asset['name']}  (release {tag})")
                return url, is_zip

    raise RuntimeError(
        f"No socks5-client asset matched for {_SYSTEM} in Nym release {tag}.\n"
        f"  All socks5 assets found: {socks5_assets}\n"
        f"  Visit https://github.com/nymtech/nym/releases to check naming."
    )


def _detect_format(path: Path) -> str:
    """
    Read the first bytes of a downloaded file and return its actual format:
    'zip', 'gz', 'bz2', 'xz', or 'exe' (bare PE binary).
    """
    with open(path, "rb") as f:
        magic = f.read(8)

    if magic[:2] == b"PK":          return "zip"
    if magic[:2] == b"\x1f\x8b":   return "gz"
    if magic[:3] == b"BZh":        return "bz2"
    if magic[:6] == b"\xfd7zXZ\x00": return "xz"
    if magic[:2] == b"MZ":         return "exe"   # Windows PE executable
    return "unknown"


def download() -> None:
    """Download and unpack (or place) the Nym SOCKS5 client binary."""
    NYM_DIR.mkdir(parents=True, exist_ok=True)

    # Delete any leftover partial download from a previous failed attempt
    for stale in NYM_DIR.glob("nym_dl.*"):
        stale.unlink(missing_ok=True)

    url, _ = _resolve_download_url()
    archive = NYM_DIR / "nym_dl.bin"   # neutral name — format detected below

    print("[nym] Downloading ...")
    urllib.request.urlretrieve(url, archive, reporthook=_progress)
    print()

    fmt = _detect_format(archive)
    print(f"[nym] Detected format: {fmt}")

    if fmt == "exe":
        # Nym shipped a bare Windows executable — just move it into place
        archive.rename(NYM_BIN)

    elif fmt == "zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(NYM_DIR)
        archive.unlink(missing_ok=True)

    elif fmt in ("gz", "bz2", "xz"):
        with tarfile.open(archive) as tf:
            tf.extractall(NYM_DIR)
        archive.unlink(missing_ok=True)

    else:
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            f"[nym] Downloaded file has unrecognised format (magic bytes unknown).\n"
            f"  URL: {url}\n"
            f"  Try downloading manually from https://github.com/nymtech/nym/releases"
        )

    if _SYSTEM != "Windows" and NYM_BIN.exists():
        NYM_BIN.chmod(0o755)

    if not NYM_BIN.exists():
        # Archive may have placed the binary in a sub-folder — find and move it
        found = [
            p for p in NYM_DIR.rglob("nym-socks5-client*")
            if p.suffix in ("", ".exe") and p != NYM_BIN
        ]
        if found:
            found[0].rename(NYM_BIN)

    if not NYM_BIN.exists():
        raise RuntimeError(
            f"[nym] Binary not found after download. Check {NYM_DIR} manually.\n"
            f"  Expected: {NYM_BIN}"
        )

    print(f"[nym] Binary ready: {NYM_BIN}")


def init_config() -> None:
    """Run `nym-socks5-client init` once to create the mixnet identity."""
    config_marker = NYM_DIR / f"{NYM_CONFIG_ID}_config_done"
    if config_marker.exists():
        return
    print("[nym] Initialising Nym client config (first run, may take ~30 s) ...")
    result = subprocess.run(
        [str(NYM_BIN), "init", "--id", NYM_CONFIG_ID],
        cwd=str(NYM_DIR),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        print(f"[nym] Init stderr: {result.stderr[-600:]}")
        raise RuntimeError("Nym client init failed.")
    config_marker.touch()
    print("[nym] Config initialised.")


def start() -> bool:
    """
    Ensure the Nym SOCKS5 client is running.
    Downloads + inits on first use.
    Returns True when the SOCKS5 port is accepting connections.
    """
    global _nym_proc

    if not is_downloaded():
        download()

    init_config()

    if is_running():
        print(f"[nym] Already running on port {NYM_SOCKS5_PORT}.")
        return True

    log_path = NYM_DIR / "nym_client.log"
    print(f"[nym] Starting Nym client (log → {log_path}) ...")

    with open(log_path, "a") as lf:
        _nym_proc = subprocess.Popen(
            [str(NYM_BIN), "run", "--id", NYM_CONFIG_ID],
            stdout=lf,
            stderr=lf,
            cwd=str(NYM_DIR),
        )

    # Poll until SOCKS5 port is open (up to 20 s)
    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", NYM_SOCKS5_PORT), timeout=1):
                pass
            print(f"[nym] SOCKS5 proxy ready on 127.0.0.1:{NYM_SOCKS5_PORT}")
            return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)

    print("[nym] Warning: SOCKS5 port did not open within 20 s.")
    print("[nym] Nym may still be connecting to the mixnet — check data/nym/nym_client.log")
    print("[nym] Continuing with proxy only (no Nym routing until it connects).")
    return False


def stop() -> None:
    global _nym_proc
    if _nym_proc and _nym_proc.poll() is None:
        _nym_proc.terminate()
        try:
            _nym_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _nym_proc.kill()
        print("[nym] Nym client stopped.")
    _nym_proc = None


def is_running() -> bool:
    return _nym_proc is not None and _nym_proc.poll() is None


def socks5_upstream() -> str:
    """Return the upstream address string for mitmproxy's --mode flag."""
    return f"socks5h://127.0.0.1:{NYM_SOCKS5_PORT}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _progress(count: int, block: int, total: int) -> None:
    if total > 0:
        pct = min(100, count * block * 100 // total)
        print(f"\r[nym] Download: {pct}%", end="", flush=True)
