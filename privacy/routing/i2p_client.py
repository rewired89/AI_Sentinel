"""
i2pd (I2P daemon) routing manager for Windows.

Downloads the official i2pd binary (C++ I2P router — no Java required),
writes a minimal config, and runs it as a background subprocess.
Exposes a SOCKS5 proxy on 127.0.0.1:4447 for mitmproxy to upstream through.

I2P characteristics relevant to this use case:
  • Garlic routing — each message is bundled with others in encrypted "cloves",
    making traffic analysis significantly harder than onion routing.
  • Fully distributed — no central directory servers, no exit-node list.
  • First startup: 2–5 minutes to build tunnels and populate the network DB.
    Subsequent starts reuse the cached netDB and are much faster (~30 s).
  • Clearnet traffic routes through public "outproxies". There are fewer of
    these than Tor exit nodes; most clearnet HTTPS works, some sites may
    be slow or unreachable through I2P outproxy.
  • .i2p hidden services work natively and are faster than clearnet routing.

i2pd GitHub: https://github.com/PurpleI2P/i2pd/releases
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
I2P_DIR  = Path(__file__).parent.parent.parent / "data" / "i2p"
I2P_BIN  = I2P_DIR / ("i2pd.exe" if _SYSTEM == "Windows" else "i2pd")
I2P_CONF = I2P_DIR / "i2pd.conf"

I2P_SOCKS5_PORT = 4447

GITHUB_RELEASES_API = "https://api.github.com/repos/PurpleI2P/i2pd/releases?per_page=5"

# Asset name fragments per platform, strictest to loosest
_ASSET_TIERS = {
    "Windows": [
        ("i2pd", "win64", ".zip"),
        ("i2pd", "win",   ".zip"),
        ("i2pd", "win64"),
        ("i2pd", "win"),
    ],
    "Linux": [
        ("i2pd", "linux", "amd64"),
        ("i2pd", "linux"),
    ],
    "Darwin": [
        ("i2pd", "osx"),
        ("i2pd", "mac"),
        ("i2pd", "darwin"),
    ],
}

_NATIVE_FORMATS = {
    "Windows": {"exe", "zip"},
    "Linux":   {"elf", "gz", "xz", "bz2", "zip"},
    "Darwin":  {"macho", "gz", "xz", "bz2", "zip"},
}

_i2p_proc: subprocess.Popen | None = None


def _tail_log(path: Path, lines: int = 20) -> None:
    """Print the last N lines of a log file to help diagnose startup failures."""
    try:
        text = path.read_text(errors="replace")
        tail = text.strip().splitlines()[-lines:]
        if tail:
            print(f"\n[i2p] Last {len(tail)} lines of {path.name}:")
            for line in tail:
                print(f"  {line}")
    except (FileNotFoundError, OSError):
        pass


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------

def _fetch_candidates() -> list[tuple[str, str]]:
    tiers = _ASSET_TIERS.get(_SYSTEM)
    if not tiers:
        raise RuntimeError(f"No i2pd asset configured for platform: {_SYSTEM}")

    print("[i2p] Checking GitHub for latest i2pd release ...")
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
        all_assets = [
            f"{r.get('tag_name')}: {[a['name'] for a in r.get('assets', [])]}"
            for r in releases
        ]
        raise RuntimeError(
            f"No i2pd asset found for {_SYSTEM} in recent releases.\n"
            f"  {all_assets}\n"
            f"  Visit https://github.com/PurpleI2P/i2pd/releases"
        )

    return candidates


def _detect_format(path: Path) -> str:
    with open(path, "rb") as f:
        magic = f.read(8)
    if magic[:2]  == b"PK":                return "zip"
    if magic[:2]  == b"\x1f\x8b":          return "gz"
    if magic[:3]  == b"BZh":               return "bz2"
    if magic[:6]  == b"\xfd7zXZ\x00":      return "xz"
    if magic[:2]  == b"MZ":                return "exe"
    if magic[:4]  == b"\x7fELF":           return "elf"
    if magic[:4]  == b"\xcf\xfa\xed\xfe":  return "macho"
    return "unknown"


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
                        print(f"\r[i2p] Download: {pct}%", end="", flush=True)
        print()
    except ImportError:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as f:
            f.write(resp.read())


def _install(archive: Path, fmt: str) -> None:
    if fmt == "zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(I2P_DIR)
        archive.unlink(missing_ok=True)
    elif fmt in ("exe",):
        if I2P_BIN.exists():
            I2P_BIN.unlink()
        archive.rename(I2P_BIN)
    else:
        import tarfile
        with tarfile.open(archive) as tf:
            tf.extractall(I2P_DIR)
        archive.unlink(missing_ok=True)

    if not I2P_BIN.exists():
        found = [
            p for p in I2P_DIR.rglob("i2pd*")
            if p.suffix in ("", ".exe") and p.is_file() and p != I2P_BIN
        ]
        if found:
            # Pick the actual binary, not a .sig or .conf
            exes = [p for p in found if not any(p.name.endswith(s) for s in (".sig", ".conf", ".txt"))]
            if exes:
                exes[0].rename(I2P_BIN)

    if _SYSTEM != "Windows" and I2P_BIN.exists():
        I2P_BIN.chmod(0o755)

    if not I2P_BIN.exists():
        raise RuntimeError(
            f"[i2p] i2pd binary not found after unpack.\n"
            f"  Expected: {I2P_BIN}\n"
            f"  Check {I2P_DIR}"
        )


def download() -> None:
    """Download and install the i2pd binary."""
    I2P_DIR.mkdir(parents=True, exist_ok=True)
    archive = I2P_DIR / "i2pd_dl.bin"
    archive.unlink(missing_ok=True)

    candidates = _fetch_candidates()
    native     = _NATIVE_FORMATS.get(_SYSTEM, set())
    tried: list[str] = []

    for url, tag in candidates:
        archive.unlink(missing_ok=True)
        print(f"[i2p] Trying release {tag} ...")
        _download_file(url, archive)

        magic = archive.read_bytes()[:8]
        fmt   = _detect_format(archive)
        print(f"[i2p] Format: {fmt}  (magic: {magic.hex()})")

        if native and fmt not in native:
            print(f"[i2p] Skipping — {fmt} is not native to {_SYSTEM}.")
            tried.append(f"{tag} ({fmt})")
            archive.unlink(missing_ok=True)
            continue

        _install(archive, fmt)
        print(f"[i2p] Binary ready: {I2P_BIN}")
        return

    raise RuntimeError(
        f"[i2p] No compatible {_SYSTEM} binary found after {len(tried)} attempts.\n"
        f"  Skipped: {tried}\n"
        f"  Visit https://github.com/PurpleI2P/i2pd/releases"
    )


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _write_config() -> None:
    """Write a minimal i2pd.conf that enables SOCKS5 and disables unused services."""
    if I2P_CONF.exists():
        return
    I2P_CONF.write_text(
        "[socksproxy]\n"
        "enabled = true\n"
        f"port = {I2P_SOCKS5_PORT}\n"
        "\n"
        "[httpproxy]\n"
        "enabled = false\n"
        "\n"
        "[ntcp2]\n"
        "enabled = true\n"
    )
    print(f"[i2p] Config written: {I2P_CONF}")


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def is_downloaded() -> bool:
    return I2P_BIN.exists()


def start() -> bool:
    """
    Start i2pd in the background and wait for the SOCKS5 port to open.

    First run note: I2P spends 2–5 minutes building tunnels and populating
    its network database. The SOCKS5 port opens quickly but traffic may not
    flow until tunnels are ready. Subsequent starts are much faster (~30 s)
    because the netDB is cached in data/i2p/.
    """
    global _i2p_proc

    if not is_downloaded():
        print("[i2p] i2pd not found. Downloading ...")
        download()

    _write_config()

    if _i2p_proc and _i2p_proc.poll() is None:
        print(f"[i2p] Already running on port {I2P_SOCKS5_PORT}.")
        return True

    log_path = I2P_DIR / "i2pd.log"
    print(f"[i2p] Starting i2pd (log → {log_path}) ...")
    print("[i2p] First run: allow 2–5 minutes for tunnel building.")

    with open(log_path, "a") as lf:
        _i2p_proc = subprocess.Popen(
            [
                str(I2P_BIN),
                f"--conf={I2P_CONF}",
                f"--datadir={I2P_DIR}",
                "--log=file",
                f"--logfile={log_path}",
            ],
            stdout=lf,
            stderr=lf,
            cwd=str(I2P_DIR),
        )

    # Poll for SOCKS5 port — up to 60 s (port opens before tunnels are ready)
    print("[i2p] Waiting for SOCKS5 port ", end="", flush=True)
    try:
        for _ in range(120):
            try:
                with socket.create_connection(("127.0.0.1", I2P_SOCKS5_PORT), timeout=1):
                    pass
                print(" ready.")
                print(f"[i2p] SOCKS5 proxy on 127.0.0.1:{I2P_SOCKS5_PORT}")
                print("[i2p] Note: tunnels may take another 2–5 min to fully build on first run.")
                return True
            except (ConnectionRefusedError, OSError):
                print(".", end="", flush=True)
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[i2p] Interrupted — stopping i2pd ...")
        stop()
        raise

    print()
    _tail_log(log_path)
    print("[i2p] SOCKS5 port did not open within 60 s — check data/i2p/i2pd.log")
    return False


def stop() -> None:
    global _i2p_proc
    if _i2p_proc and _i2p_proc.poll() is None:
        _i2p_proc.terminate()
        try:
            _i2p_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _i2p_proc.kill()
        print("[i2p] i2pd stopped.")
    _i2p_proc = None


def is_running() -> bool:
    return _i2p_proc is not None and _i2p_proc.poll() is None


def socks5_upstream() -> str:
    return f"socks5h://127.0.0.1:{I2P_SOCKS5_PORT}"
