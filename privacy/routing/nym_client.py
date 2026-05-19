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

GITHUB_RELEASES_API = "https://api.github.com/repos/nymtech/nym/releases?per_page=10"

# Formats that are native to this OS — if we download something else, reject it.
_NATIVE_FORMATS = {
    "Windows": {"exe", "zip"},        # PE exe or a zip containing one
    "Linux":   {"elf", "gz", "xz", "bz2"},
    "Darwin":  {"macho", "gz", "xz", "bz2"},
}

NYM_CONFIG_ID  = "sentinel-client"
NYM_SOCKS5_PORT = 1080

_nym_proc: subprocess.Popen | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_downloaded() -> bool:
    return NYM_BIN.exists()


def _resolve_download_url() -> tuple[str, str]:
    """
    Search the last 10 Nym releases for a socks5-client asset that matches
    this platform. Returns (download_url, release_tag).

    Newer Nym releases sometimes only ship Linux binaries; this walks back
    through releases until it finds one with a Windows-compatible asset.
    Tiers go from strictest name match to loosest so a bare 'nym-socks5-client'
    is only accepted when no platform-tagged variant exists.
    """
    tiers = _ASSET_TIERS.get(_SYSTEM)
    if not tiers:
        raise RuntimeError(f"No Nym binary available for platform: {_SYSTEM}")

    print("[nym] Checking GitHub for a compatible Nym release ...")
    req = urllib.request.Request(GITHUB_RELEASES_API, headers={"User-Agent": "AI-Sentinel"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        releases = json.loads(resp.read())

    skipped: list[str] = []

    for release in releases:
        tag    = release.get("tag_name", "unknown")
        assets = release.get("assets", [])
        by_name = {a.get("name", "").lower(): a for a in assets}

        for tier in tiers:
            for name_lower, asset in by_name.items():
                if all(frag.lower() in name_lower for frag in tier):
                    # Reject bare 'nym-socks5-client' assets from releases that
                    # also contain platform-specific assets — the bare one is
                    # likely the Linux build named without a suffix.
                    if tier == ("nym-socks5-client",):
                        has_platform_asset = any(
                            "windows" in n or "linux" in n or "darwin" in n
                            or "msvc" in n or "musl" in n or "apple" in n
                            for n in by_name
                            if "socks5" in n
                        )
                        if has_platform_asset:
                            continue  # skip bare asset — platform ones exist

                    url = asset["browser_download_url"]
                    print(f"[nym] Found: {asset['name']}  (release {tag})")
                    return url, tag

        socks5_in_release = [n for n in by_name if "socks5" in n]
        skipped.append(f"{tag}: {socks5_in_release}")

    raise RuntimeError(
        f"No {_SYSTEM}-compatible socks5-client found in the last {len(releases)} Nym releases.\n"
        f"  Releases checked: {[r.get('tag_name') for r in releases]}\n"
        f"  Socks5 assets per release: {skipped}\n"
        f"  Visit https://github.com/nymtech/nym/releases"
    )


def _detect_format(path: Path) -> str:
    """
    Identify file format by magic bytes — completely independent of filename or
    Content-Type, so Nym's extensionless assets are handled correctly.
    """
    with open(path, "rb") as f:
        magic = f.read(8)

    if magic[:2]  == b"PK":               return "zip"
    if magic[:2]  == b"\x1f\x8b":         return "gz"
    if magic[:3]  == b"BZh":              return "bz2"
    if magic[:6]  == b"\xfd7zXZ\x00":     return "xz"
    if magic[:2]  == b"MZ":               return "exe"   # Windows PE
    if magic[:4]  == b"\x7fELF":          return "elf"   # Linux ELF
    if magic[:4]  == b"\xcf\xfa\xed\xfe": return "macho" # macOS Mach-O
    return "unknown"


def _download_file(url: str, dest: Path) -> None:
    """
    Download url → dest using requests with the headers GitHub needs to serve
    raw binary assets (including extensionless ones).
    Falls back to urllib if requests isn't available.
    """
    headers = {
        "User-Agent": "AI-Sentinel/1.0",
        "Accept":     "application/octet-stream",
    }
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
                        print(f"\r[nym] Download: {pct}%", end="", flush=True)
        print()
    except ImportError:
        # requests not installed — fall back to urllib (less reliable for GitHub)
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as f:
            f.write(resp.read())


def download() -> None:
    """Download and install the Nym SOCKS5 client binary."""
    NYM_DIR.mkdir(parents=True, exist_ok=True)

    # Remove any leftover partial downloads
    for stale in NYM_DIR.glob("nym_dl.*"):
        stale.unlink(missing_ok=True)
    (NYM_DIR / "nym_dl.bin").unlink(missing_ok=True)

    url, tag = _resolve_download_url()
    archive  = NYM_DIR / "nym_dl.bin"

    print(f"[nym] Downloading from release {tag} ...")
    _download_file(url, archive)

    fmt   = _detect_format(archive)
    magic = archive.read_bytes()[:8]
    print(f"[nym] Detected format: {fmt}  (magic: {magic.hex()})")

    # Sanity-check: reject a binary built for the wrong OS before trying to run it.
    native = _NATIVE_FORMATS.get(_SYSTEM, set())
    if native and fmt not in native:
        preview = archive.read_bytes()[:80]
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            f"[nym] Downloaded binary is not compatible with {_SYSTEM}.\n"
            f"  Format detected : {fmt}  (magic: {magic.hex()})\n"
            f"  Expected one of : {native}\n"
            f"  This release ({tag}) may not ship a {_SYSTEM} build.\n"
            f"  Preview: {preview!r}"
        )

    if fmt in ("exe", "elf", "macho"):
        # Bare binary — move it directly into place
        if NYM_BIN.exists():
            NYM_BIN.unlink()
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
        # Show first 120 bytes as text to help diagnose (e.g. HTML error page)
        preview = archive.read_bytes()[:120]
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            f"[nym] Downloaded file has unrecognised format.\n"
            f"  URL     : {url}\n"
            f"  Magic   : {magic.hex()}\n"
            f"  Preview : {preview!r}\n"
            f"  This usually means GitHub returned an error or redirect page.\n"
            f"  Try downloading manually from https://github.com/nymtech/nym/releases"
        )

    if _SYSTEM != "Windows" and NYM_BIN.exists():
        NYM_BIN.chmod(0o755)

    if not NYM_BIN.exists():
        # Archive may have placed the binary in a sub-folder — find and move it
        found = [
            p for p in NYM_DIR.rglob("nym-socks5-client*")
            if p.suffix in ("", ".exe") and p.is_file() and p != NYM_BIN
        ]
        if found:
            found[0].rename(NYM_BIN)

    if not NYM_BIN.exists():
        raise RuntimeError(
            f"[nym] Binary not found after download.\n"
            f"  Expected : {NYM_BIN}\n"
            f"  Check    : {NYM_DIR}"
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
