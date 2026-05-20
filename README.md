# AI Sentinel

> Your computer's personal bodyguard — running silently in the background, 24/7.

---

## For Everyone (No Tech Knowledge Required)

### What is AI Sentinel?

Normally when you browse the internet, three things happen that you probably don't know about:

1. **Your internet provider (ISP) can see every website you visit.** Every time you open Netflix, Google, a news site, anything — your ISP logs it. They can sell that data, hand it to governments, or get hacked and leak it.

2. **Every website you visit can build a profile of you** — even without cookies. They fingerprint your browser: your screen size, your graphics card, your fonts, your timezone. Put it all together and they know it's *you*, even in private/incognito mode.

3. **Malware and hacker tools phone home silently.** If something bad ends up on your PC, it quietly calls out to a hacker's server in the background. Most antivirus software catches files, not network calls.

**AI Sentinel fixes all three at once.**

---

### What does it actually do?

Think of AI Sentinel as three bodyguards working together:

#### 🛡️ Bodyguard 1 — The Traffic Guard (Scanning Proxy)
Every single connection your computer makes — every website, every app, every background request — passes through AI Sentinel first. It checks it against known hacker and malware databases. If something looks like a hacker's remote control signal (a "C2 beacon"), it gets blocked immediately. You get a notification.

#### 🌐 Bodyguard 2 — The Route Changer (I2P Routing)
Instead of your traffic going straight from your computer to the website (where your ISP can see everything), AI Sentinel bounces it through the **I2P network** — a private underground internet made up of thousands of computers worldwide. Your ISP sees an encrypted blob going to an I2P node. They have no idea what sites you're visiting. The website sees an I2P exit IP, not yours.

Think of it like: instead of driving your car directly to a destination (where cameras on the road see you), you get into a tunnel system with thousands of other cars, switch vehicles a few times, and come out somewhere else. Nobody who was watching the road knows where you went.

#### 🎭 Bodyguard 3 — The Faker (Fingerprint Poisoning)
When a website tries to fingerprint your browser — reading your screen size, graphics card, number of CPU cores, installed fonts, timezone — AI Sentinel intercepts that and **feeds the website fake data**. Every session you get a different fake identity. Trackers think you're a different person every time. Fingerprinting-based tracking breaks completely.

---

### What does the shield icon mean?

Look at the bottom-right corner of your screen (system tray). AI Sentinel shows a shield:

| Shield Color | Meaning |
|---|---|
| 🟢 Green | Full protection — I2P routing + scanning + fingerprint poisoning all active |
| 🟡 Amber | Partial protection — scanning + fingerprint poisoning active, but I2P routing didn't start |
| 🔴 Red | Threat detected right now — something was blocked |
| ⚫ Grey | Starting up or stopped |

**Left-click** the shield to open your threat log.
**Right-click** for options.

---

### How do I set it up?

1. Make sure Python is installed on your PC
2. Double-click **`install.bat`** — it installs everything and adds AI Sentinel to your Windows startup
3. That's it. AI Sentinel will now start automatically every time you log in. You don't have to do anything.

To build the standalone `.exe` (no Python required after that):
- Double-click **`build.bat`**
- Run `dist\AIsentinel\AIsentinel.exe`

---

### Is it slowing down my internet?

Slightly. I2P adds a small latency because your traffic takes a longer route. Most browsing feels normal. Large file downloads may be slower through I2P. If speed matters more than anonymity in a session, you can run with `--route=none` to disable routing and keep only the scanning and fingerprint poisoning layers.

---

## For Tech Users

### Architecture

```
Browser / App
     │
     ▼ (Windows system proxy: 127.0.0.1:8877)
┌─────────────────────────────────────────┐
│         mitmproxy (port 8877)           │
│  • C2 beacon heuristics (UA + path)     │
│  • Domain reputation: VT + OTX (async) │
│  • HTML response injection (poisoning) │
└─────────────────────┬───────────────────┘
                      │ --mode upstream:http://127.0.0.1:8878
                      ▼
┌─────────────────────────────────────────┐
│     asyncio HTTP-CONNECT→SOCKS5 bridge  │
│            (port 8878)                  │
│  Accepts HTTP CONNECT, tunnels through  │
│  SOCKS5 with RFC-1928 domain ATYP       │
│  (no DNS leak — hostname passed raw)    │
└─────────────────────┬───────────────────┘
                      │ SOCKS5
                      ▼
┌─────────────────────────────────────────┐
│           i2pd (port 4447)              │
│  C++ I2P router — garlic routing        │
│  Fully distributed, no exit-node list   │
│  netDB cached in data/i2p/ after        │
│  first run (~30s startup vs 2-5min)     │
└─────────────────────┬───────────────────┘
                      │
                      ▼
              I2P Network / Internet
```

### Components

#### `privacy/routing/i2p_client.py`
Manages the i2pd lifecycle. Downloads the correct binary for the current platform using GitHub Releases API with magic-byte format detection (not filename guessing). Writes a minimal config (SOCKS5 on 4447, no webconsole, no HTTP proxy). Polls SOCKS5 port for up to 60s. Falls back gracefully if i2pd fails — the rest of the stack continues without routing.

#### `privacy/routing/socks5_bridge.py`
Pure asyncio bridge listening on 127.0.0.1:8878. Accepts standard HTTP CONNECT requests from mitmproxy's upstream mode (which only speaks HTTP), performs RFC-1928 SOCKS5 handshake with i2pd, and tunnels the raw TCP stream. Uses ATYP 0x03 (domain name) so hostnames are resolved by i2pd, not locally — no DNS leak.

#### `privacy/proxy/sentinel_proxy.py`
mitmproxy addon. On every request: C2 heuristics check (User-Agent and path pattern matching), then async domain reputation lookup against VirusTotal v3 API and AlienVault OTX (results cached 10 min, TTL-evicted). On every HTML response: calls the poison injector and strips Content-Length. Threat events are written to `data/privacy_threats.json` and trigger the tray THREAT state for 30s.

#### `privacy/proxy/poison_injector.py`
Generates a consistent fake session identity at import time using `secrets` + SHA-256. Injects a `<script>` block into every HTML response that overrides:
- `HTMLCanvasElement.prototype.toDataURL` / `toBlob` — returns noise-seeded canvas data
- `RTCPeerConnection` — strips all ICE server configs, preventing WebRTC IP leaks
- `screen.width` / `screen.height` / `screen.availWidth` / `screen.availHeight`
- `navigator.hardwareConcurrency` / `navigator.deviceMemory`
- `navigator.language` / `navigator.languages`
- `Date.prototype.getTimezoneOffset`
- `navigator.plugins` / `navigator.mimeTypes` — returns empty iterables
- `document.fonts.check` — always returns false

Injection is idempotent (marker attribute checked). Injected after `<head>` or before first `<script>`, with fallback to prepend.

#### `privacy/tray.py`
pystray-based tray icon using `run_detached()` (non-blocking, pystray manages its own Win32 HWND message pump thread). Icon drawn dynamically with PIL — dark rounded-rectangle background for taskbar visibility, state-colored shield polygon, bold S lettermark. States: STARTING / ACTIVE / SCANNING / THREAT / STOPPED. Thread-safe state transitions via `threading.Lock`.

#### `privacy/autostart.py`
Windows autostart via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (no admin required). Defender exclusion via `Add-MpPreference -ExclusionPath` through PowerShell (requires elevation — prints manual instructions if not elevated).

#### `privacy/identity.py`
Ed25519 keypair generated with `cryptography` library. Public key is the user's only persistent identity — no accounts, no registration. Stored in `data/identity/`.

### Threat detection layers

| Layer | Method | Action |
|---|---|---|
| Malicious domains | VirusTotal v3 API (async, cached) | Block 403 |
| Threat intelligence | AlienVault OTX pulse count | Block 403 |
| C2 beacons | UA string + path heuristics | Block 403 |
| De-anonymization JS | Pattern scan on response body | Log + header |
| WebRTC leaks | RTCPeerConnection override (JS injection) | Neutralized silently |
| Canvas fingerprinting | toDataURL noise injection | Poisoned silently |
| Hardware fingerprinting | navigator.* overrides | Poisoned silently |
| DNS leaks | SOCKS5 ATYP 0x03 (hostname forwarded raw) | Prevented by design |

### Running without the exe

```powershell
# Install deps
pip install -r requirements.txt

# First-time setup (Defender exclusion + autostart)
python -m privacy.privacy_main --setup

# Run
python -m privacy.privacy_main

# Routing options
python -m privacy.privacy_main --route=i2p     # default — I2P garlic routing
python -m privacy.privacy_main --route=nym     # Nym mixnet (if available)
python -m privacy.privacy_main --route=none    # scanning + poisoning only

# Install mitmproxy CA cert for HTTPS interception
python -m privacy.privacy_main --setup-certs
```

### Environment variables (`.env` or shell)

| Variable | Purpose |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 domain lookups (free tier: 500 req/day) |
| `ALIENVAULT_API_KEY` | AlienVault OTX pulse lookups (free) |

Without API keys, domain reputation checks are skipped. C2 heuristics, fingerprint poisoning, and de-anonymization scanning still work without any keys.

### Building the exe

```powershell
.\build.bat
```

Runs PyInstaller with `build/sentinel.spec`. Output: `dist\AIsentinel\AIsentinel.exe` — fully self-contained, no Python required. The spec bundles `privacy/`, `app/`, `model/`, and `assets/sentinel.ico`. Hidden imports declared for mitmproxy, cryptography, pystray, sklearn, and bcrypt (pinned to 4.0.1 — bcrypt ≥ 4.1 removed the `__about__` attribute that passlib requires).

### Known issues / workarounds

- **Windows Defender quarantines i2pd.exe** — run `python -m privacy.privacy_main --setup` to add a Defender exclusion for `data/i2p/`
- **mitmproxy only accepts `http://` upstream** — the SOCKS5 bridge exists specifically for this; i2pd's SOCKS5 on 4447 is not used directly by mitmproxy
- **Tray icon invisible after first run** — Windows 11 hides new tray icons; go to Settings → Personalization → Taskbar → Other system tray icons and enable it. The built `.exe` registers its own app identity and stays visible permanently.
- **bcrypt/passlib conflict** — pinned `bcrypt==4.0.1` in requirements.txt; do not upgrade
