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

On **Windows** the shield is in the bottom-right corner (system tray).
On **Mac** it's in the top-right corner (menu bar).

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

#### Windows
1. Make sure Python is installed on your PC
2. Double-click **`install.bat`** — it installs everything and adds AI Sentinel to your Windows startup
3. That's it. AI Sentinel will now start automatically every time you log in.

To build the standalone `.exe` (no Python required after that):
- Double-click **`build.bat`**
- Run `dist\AIsentinel\AIsentinel.exe`

#### Mac
1. Make sure Python 3 is installed — open Terminal and type `python3 --version`. If it's not there, download it from python.org or run `brew install python`
2. Open Terminal, drag the `AI_Sentinel` folder into it, and run:
   ```
   bash install.sh
   ```
3. That's it. AI Sentinel will start automatically at next login.

> **First time on Mac:** When i2pd (the anonymity router) runs for the first time, macOS may show a security warning saying the app is from an unidentified developer. Go to **System Settings → Privacy & Security** and click **"Allow Anyway"**. You only have to do this once. i2pd is the official open-source I2P router, not malware — macOS just doesn't recognize unsigned binaries.

---

### Is it slowing down my internet?

Slightly. I2P adds a small latency because your traffic takes a longer route. Most browsing feels normal. Large file downloads may be slower through I2P. If speed matters more than anonymity in a session, you can run with `--route=none` to disable routing and keep only the scanning and fingerprint poisoning layers.

---

## For Tech Users

### Architecture

```
Browser / App
     │
     ▼ (system proxy: 127.0.0.1:8877 — set via winreg on Windows, networksetup on macOS)
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
Cross-platform autostart and AV exclusion setup.
- **Windows**: autostart via `HKCU\...\Run` (no admin); Defender exclusion via `Add-MpPreference` through PowerShell (requires elevation — prints manual fallback if not elevated)
- **macOS**: autostart via `~/Library/LaunchAgents/com.ai-sentinel.plist` using `plistlib` + `launchctl load` (no admin); Gatekeeper instructions printed instead of Defender exclusion

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

**Windows (PowerShell)**
```powershell
pip install -r requirements.txt
python -m privacy.privacy_main --setup   # first run: Defender exclusion + autostart
python -m privacy.privacy_main
```

**macOS / Linux (Terminal)**
```bash
pip3 install -r requirements.txt
python3 -m privacy.privacy_main --setup  # first run: LaunchAgent autostart
python3 -m privacy.privacy_main
# or just:
bash install.sh   # does both steps above
bash start.sh
```

**Routing options (all platforms)**
```bash
python3 -m privacy.privacy_main --route=i2p     # default — I2P garlic routing
python3 -m privacy.privacy_main --route=nym     # Nym mixnet (if available)
python3 -m privacy.privacy_main --route=none    # scanning + poisoning only
```

**Install mitmproxy CA cert for HTTPS scanning**
```bash
python3 -m privacy.privacy_main --setup-certs
# Windows: uses certutil (run as Administrator)
# macOS:   uses 'sudo security add-trusted-cert' against System.keychain
```

### Environment variables (`.env` or shell)

| Variable | Purpose |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 domain lookups (free tier: 500 req/day) |
| `ALIENVAULT_API_KEY` | AlienVault OTX pulse lookups (free) |

Without API keys, domain reputation checks are skipped. C2 heuristics, fingerprint poisoning, and de-anonymization scanning still work without any keys.

### Building the standalone app

**Windows** — produces `dist\AIsentinel\AIsentinel.exe`
```powershell
.\build.bat
```

**macOS** — produces `dist/AIsentinel/AIsentinel` (Unix binary)
```bash
pip3 install pyinstaller pillow
python3 build/make_icon.py
pyinstaller build/sentinel.spec --distpath dist --workpath build/work --noconfirm
```

Both use `build/sentinel.spec` via PyInstaller. The bundle includes `privacy/`, `app/`, `model/`, and `assets/sentinel.ico`. Hidden imports declared for mitmproxy, cryptography, pystray (Win32 + Darwin backends), plyer (Win + macOS), sklearn, and bcrypt (pinned to 4.0.1 — bcrypt ≥ 4.1 removed the `__about__` attribute that passlib requires).

### Platform differences at a glance

| Feature | Windows | macOS |
|---|---|---|
| System proxy | `winreg` (HKCU Internet Settings) | `networksetup` (all active services) |
| Autostart | HKCU Run key | `~/Library/LaunchAgents/` plist |
| CA cert install | `certutil -addstore` (as Admin) | `sudo security add-trusted-cert` |
| AV exclusion | Defender `Add-MpPreference` | Gatekeeper "Allow Anyway" (one click) |
| Notifications | winotify (Win11 toast) | plyer → macOS Notification Center |
| Open threat log | `explorer.exe` | `open` |
| Crash dialog | `MessageBoxW` | `osascript display alert` |
| Shield location | Bottom-right taskbar (system tray) | Top-right menu bar |

### Known issues / workarounds

**Windows**
- **Defender quarantines i2pd.exe** — run `python -m privacy.privacy_main --setup` to add a Defender exclusion for `data/i2p/`
- **Tray icon invisible after first run** — Windows 11 hides new tray icons; go to Settings → Personalization → Taskbar → Other system tray icons and enable it. The built `.exe` stays visible permanently.
- **bcrypt/passlib conflict** — pinned `bcrypt==4.0.1`; do not upgrade

**macOS**
- **Gatekeeper blocks i2pd on first run** — open System Settings → Privacy & Security → click "Allow Anyway". One-time action.
- **mitmproxy CA cert requires sudo** — `python3 -m privacy.privacy_main --setup-certs` will prompt for your password
- **System proxy requires active network service name** — `networksetup -listallnetworkservices` is called automatically; if your VPN or custom interface isn't detected, set the proxy manually in System Settings → Network

**All platforms**
- **mitmproxy only accepts `http://` upstream** — the SOCKS5 bridge (`socks5_bridge.py`) exists for this; i2pd's port 4447 is never used directly by mitmproxy
