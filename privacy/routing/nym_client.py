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

# Pinned to a known-good release. Update when Nym publishes a new stable tag.
# Check: https://github.com/nymtech/nym/releases
NYM_VERSION = "2024.9-topdeck"

_DOWNLOAD_URLS = {
    "Windows": (
        f"https://github.com/nymtech/nym/releases/download/"
        f"nym-binaries-v{NYM_VERSION}/nym-socks5-client-x86_64-pc-windows-msvc.zip"
    ),
    "Linux": (
        f"https://github.com/nymtech/nym/releases/download/"
        f"nym-binaries-v{NYM_VERSION}/nym-socks5-client-x86_64-unknown-linux-musl.tar.gz"
    ),
    "Darwin": (
        f"https://github.com/nymtech/nym/releases/download/"
        f"nym-binaries-v{NYM_VERSION}/nym-socks5-client-aarch64-apple-darwin.tar.gz"
    ),
}

NYM_CONFIG_ID  = "sentinel-client"
NYM_SOCKS5_PORT = 1080

_nym_proc: subprocess.Popen | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_downloaded() -> bool:
    return NYM_BIN.exists()


def download() -> None:
    """Download and unpack the Nym SOCKS5 client binary for this OS."""
    url = _DOWNLOAD_URLS.get(_SYSTEM)
    if not url:
        raise RuntimeError(f"No Nym binary available for platform: {_SYSTEM}")

    NYM_DIR.mkdir(parents=True, exist_ok=True)
    archive = NYM_DIR / ("nym_dl.zip" if _SYSTEM == "Windows" else "nym_dl.tar.gz")

    print(f"[nym] Downloading Nym v{NYM_VERSION} ...")
    urllib.request.urlretrieve(url, archive, reporthook=_progress)
    print()

    print("[nym] Unpacking ...")
    if _SYSTEM == "Windows":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(NYM_DIR)
    else:
        with tarfile.open(archive) as tf:
            tf.extractall(NYM_DIR)

    archive.unlink(missing_ok=True)

    if _SYSTEM != "Windows":
        NYM_BIN.chmod(0o755)

    if not NYM_BIN.exists():
        # Some archives nest files — try to find it
        found = list(NYM_DIR.rglob("nym-socks5-client*"))
        if found:
            found[0].rename(NYM_BIN)

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
