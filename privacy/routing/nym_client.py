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
import json
import platform
import socket
import subprocess
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

NYM_DIR    = Path(__file__).parent.parent.parent / "data" / "nym"
_SYSTEM    = platform.system()
NYM_BIN    = NYM_DIR / ("nym-socks5-client.exe" if _SYSTEM == "Windows" else "nym-socks5-client")

# Asset name tiers — tried from most specific to least specific.
# Outer loop is tier, inner loop is release, so a platform-tagged asset in ANY
# release beats a bare asset in the latest release.
_ASSET_TIERS = {
    "Windows": [
        ("nym-socks5-client", "windows"),
        ("nym-socks5-client", "msvc"),
        ("nym-socks5-client", "win"),
        ("nym-socks5-client",),           # bare name — last resort
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

# Magic-byte format strings that are native to each OS.
# A downloaded binary whose format is NOT in this set is silently skipped.
_NATIVE_FORMATS = {
    "Windows": {"exe", "zip"},
    "Linux":   {"elf", "gz", "xz", "bz2"},
    "Darwin":  {"macho", "gz", "xz", "bz2"},
}

GITHUB_RELEASES_API = "https://api.github.com/repos/nymtech/nym/releases?per_page=10"

NYM_CONFIG_ID   = "sentinel-client"
NYM_SOCKS5_PORT = 1080

_nym_proc: subprocess.Popen | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_downloaded() -> bool:
    return NYM_BIN.exists()


def _fetch_candidates() -> list[tuple[str, str]]:
    """
    Return an ordered list of (download_url, release_tag) from the last 10
    Nym releases.

    Ordering: tier 0 (most platform-specific name) across ALL releases comes
    before tier 1 across all releases, and so on. This guarantees a
    platform-tagged asset in an older release beats a bare/wrong-OS asset in
    the latest release.
    """
    tiers = _ASSET_TIERS.get(_SYSTEM)
    if not tiers:
        raise RuntimeError(f"No Nym binary available for platform: {_SYSTEM}")

    print("[nym] Checking GitHub for a compatible Nym release ...")
    req = urllib.request.Request(GITHUB_RELEASES_API, headers={"User-Agent": "AI-Sentinel"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        releases = json.loads(resp.read())

    candidates: list[tuple[str, str]] = []

    for tier in tiers:
        for release in releases:
            tag     = release.get("tag_name", "unknown")
            by_name = {a.get("name", "").lower(): a for a in release.get("assets", [])}
            for name_lower, asset in by_name.items():
                if all(frag.lower() in name_lower for frag in tier):
                    entry = (asset["browser_download_url"], tag)
                    if entry not in candidates:
                        candidates.append(entry)

    if not candidates:
        all_socks5 = [
            f"{r.get('tag_name')}: "
            f"{[a['name'] for a in r.get('assets', []) if 'socks5' in a['name'].lower()]}"
            for r in releases
        ]
        raise RuntimeError(
            f"No socks5-client asset found in last {len(releases)} Nym releases.\n"
            f"  {all_socks5}\n"
            f"  Visit https://github.com/nymtech/nym/releases"
        )

    return candidates


def _detect_format(path: Path) -> str:
    """Identify file format by magic bytes — independent of filename."""
    with open(path, "rb") as f:
        magic = f.read(8)
    if magic[:2]  == b"PK":                return "zip"
    if magic[:2]  == b"\x1f\x8b":          return "gz"
    if magic[:3]  == b"BZh":               return "bz2"
    if magic[:6]  == b"\xfd7zXZ\x00":      return "xz"
    if magic[:2]  == b"MZ":                return "exe"    # Windows PE
    if magic[:4]  == b"\x7fELF":           return "elf"    # Linux ELF
    if magic[:4]  == b"\xcf\xfa\xed\xfe":  return "macho"  # macOS Mach-O
    return "unknown"


def _download_file(url: str, dest: Path) -> None:
    """Download url → dest with headers GitHub requires for raw binary assets."""
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
                        print(f"\r[nym] Download: {pct}%", end="", flush=True)
        print()
    except ImportError:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as f:
            f.write(resp.read())


def _install(archive: Path, fmt: str, url: str) -> None:
    """Move or unpack archive into NYM_BIN."""
    if fmt in ("exe", "elf", "macho"):
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
        preview = archive.read_bytes()[:120]
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            f"[nym] Unrecognised file format after download.\n"
            f"  URL    : {url}\n"
            f"  Preview: {preview!r}"
        )

    if _SYSTEM != "Windows" and NYM_BIN.exists():
        NYM_BIN.chmod(0o755)

    if not NYM_BIN.exists():
        # Archive may have placed the binary in a sub-folder — find and promote it
        found = [
            p for p in NYM_DIR.rglob("nym-socks5-client*")
            if p.suffix in ("", ".exe") and p.is_file() and p != NYM_BIN
        ]
        if found:
            found[0].rename(NYM_BIN)

    if not NYM_BIN.exists():
        raise RuntimeError(
            f"[nym] Binary not found after unpack.\n"
            f"  Expected: {NYM_BIN}"
        )


def download() -> None:
    """
    Download the Nym SOCKS5 client binary.

    Iterates candidates (most platform-specific first, across all recent
    releases). If a downloaded file turns out to be wrong-OS it is discarded
    and the next candidate is tried.

    If no compatible binary exists for this OS across all checked releases,
    writes a flag file so future runs skip the download loop entirely.
    """
    NYM_DIR.mkdir(parents=True, exist_ok=True)
    archive    = NYM_DIR / "nym_dl.bin"
    no_win_flag = NYM_DIR / "no_windows_binary.flag"
    archive.unlink(missing_ok=True)

    candidates = _fetch_candidates()
    native     = _NATIVE_FORMATS.get(_SYSTEM, set())
    tried: list[str] = []

    for url, tag in candidates:
        archive.unlink(missing_ok=True)
        print(f"[nym] Trying release {tag} ...")
        _download_file(url, archive)

        magic = archive.read_bytes()[:8]
        fmt   = _detect_format(archive)
        print(f"[nym] Format: {fmt}  (magic: {magic.hex()})")

        if native and fmt not in native:
            print(f"[nym] Skipping — {fmt} is not native to {_SYSTEM}.")
            tried.append(f"{tag} ({fmt})")
            archive.unlink(missing_ok=True)
            continue

        _install(archive, fmt, url)
        print(f"[nym] Binary ready: {NYM_BIN}")
        no_win_flag.unlink(missing_ok=True)  # clear flag if it existed
        return

    # All candidates exhausted — write a flag so we never loop again
    no_win_flag.write_text(
        f"Checked {len(tried)} releases on {__import__('datetime').date.today()}. "
        f"None had a {_SYSTEM} binary.\nSkipped: {tried}"
    )
    raise RuntimeError(
        f"[nym] No compatible {_SYSTEM} binary found after {len(tried)} attempts.\n"
        f"  Skipped: {tried}\n"
        f"  A flag has been written to {no_win_flag} — Nym download will be skipped on future runs.\n"
        f"  Delete that file to retry."
    )


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
    Raises RuntimeError immediately if a previous run confirmed no binary exists.
    """
    global _nym_proc

    no_win_flag = NYM_DIR / "no_windows_binary.flag"
    if no_win_flag.exists():
        raise RuntimeError(
            f"[nym] Nym has no {_SYSTEM} binary in recent releases (cached result).\n"
            f"  Delete {no_win_flag} to retry."
        )

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
    print("[nym] Nym may still be connecting — check data/nym/nym_client.log")
    print("[nym] Continuing without anonymous routing until it connects.")
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
    return f"socks5://127.0.0.1:{NYM_SOCKS5_PORT}"
