"""
Fingerprint poisoning injector.

When a de-anonymization attempt is detected, this module injects a <script>
block into the HTML response that overrides the browser APIs fingerprinters
use. The tracker runs, collects "your fingerprint," and gets back plausible
but completely fake data.

Design principles:
  - Consistent within a session: fake values are generated once at import time
    and held for the process lifetime. Two scripts on the same page get the
    same fake data and don't detect inconsistency.
  - Randomised across sessions: every restart produces a different fake identity.
  - Plausible: values fall within real-world ranges so anomaly detectors don't
    flag them as spoofed.
  - Non-breaking: overrides are wrapped in try/catch so pages that don't
    fingerprint are completely unaffected.
"""
import hashlib
import secrets

# One random seed per process lifetime
_SEED = secrets.token_bytes(16)


def _seeded_int(key: str, lo: int, hi: int) -> int:
    """Deterministically derive an int in [lo, hi] from the session seed."""
    digest = hashlib.sha256(_SEED + key.encode()).digest()
    return lo + int.from_bytes(digest[:4], "big") % (hi - lo + 1)


def _seeded_choice(key: str, options: list):
    return options[_seeded_int(key, 0, len(options) - 1)]


# ---------------------------------------------------------------------------
# Session fake identity (generated once, consistent for the whole session)
# ---------------------------------------------------------------------------

FAKE_SCREEN = _seeded_choice("screen", [
    (1920, 1080), (1366, 768), (2560, 1440),
    (1440, 900),  (1280, 800), (1600, 900),
])
FAKE_CORES    = _seeded_choice("cores",    [2, 4, 4, 6, 8, 8, 12])
FAKE_MEMORY   = _seeded_choice("memory",   [4, 8, 8, 16, 16, 32])
FAKE_TZ_OFF   = _seeded_choice("tz",       [-480, -420, -360, -300, 0, 60, 120, 180])
FAKE_LANG     = _seeded_choice("lang",     ["en-US", "en-GB", "de-DE", "fr-FR", "es-ES"])
CANVAS_NOISE  = _seeded_int("canvas_r", 1, 7)   # tiny pixel shift, imperceptible visually
CANVAS_NOISE2 = _seeded_int("canvas_g", 1, 5)


def _build_script() -> str:
    w, h = FAKE_SCREEN
    return f"""<script data-sentinel="poison-v1">
(function(){{
  'use strict';

  /* ── Canvas fingerprint noise ───────────────────────────────────────── */
  try {{
    var _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type, quality) {{
      var ctx2d = this.getContext('2d');
      if (ctx2d) {{
        var iw = this.width  || 1;
        var ih = this.height || 1;
        var id = ctx2d.getImageData(0, 0, iw, ih);
        /* Shift a few pixels by 1-7 units — invisible to the eye,
           unique per session, destroys cross-session hashing. */
        for (var i = 0; i < id.data.length; i += 4) {{
          id.data[i]   = (id.data[i]   + {CANVAS_NOISE})  & 0xFF;
          id.data[i+1] = (id.data[i+1] + {CANVAS_NOISE2}) & 0xFF;
        }}
        ctx2d.putImageData(id, 0, 0);
      }}
      return _origToDataURL.call(this, type, quality);
    }};
  }} catch(e) {{}}

  /* ── WebRTC IP leak prevention ──────────────────────────────────────── */
  try {{
    var _origRTC = window.RTCPeerConnection
                || window.webkitRTCPeerConnection
                || window.mozRTCPeerConnection;
    if (_origRTC) {{
      var FakeRTC = function(cfg, opt) {{
        /* Strip all ICE servers so no STUN/TURN UDP packets are sent,
           which would expose the real IP even behind a proxy. */
        if (cfg && cfg.iceServers) cfg.iceServers = [];
        return new _origRTC(cfg, opt);
      }};
      FakeRTC.prototype = _origRTC.prototype;
      if (window.RTCPeerConnection)       window.RTCPeerConnection       = FakeRTC;
      if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = FakeRTC;
      if (window.mozRTCPeerConnection)    window.mozRTCPeerConnection    = FakeRTC;
    }}
  }} catch(e) {{}}

  /* ── Screen geometry ────────────────────────────────────────────────── */
  try {{
    Object.defineProperty(screen, 'width',       {{get: function(){{ return {w}; }}}});
    Object.defineProperty(screen, 'height',      {{get: function(){{ return {h}; }}}});
    Object.defineProperty(screen, 'availWidth',  {{get: function(){{ return {w}; }}}});
    Object.defineProperty(screen, 'availHeight', {{get: function(){{ return {h - 40}; }}}});
    Object.defineProperty(screen, 'colorDepth',  {{get: function(){{ return 24; }}}});
    Object.defineProperty(screen, 'pixelDepth',  {{get: function(){{ return 24; }}}});
  }} catch(e) {{}}

  /* ── Hardware fingerprints ──────────────────────────────────────────── */
  try {{
    Object.defineProperty(navigator, 'hardwareConcurrency', {{get: function(){{ return {FAKE_CORES}; }}}});
  }} catch(e) {{}}
  try {{
    Object.defineProperty(navigator, 'deviceMemory', {{get: function(){{ return {FAKE_MEMORY}; }}}});
  }} catch(e) {{}}

  /* ── Language ───────────────────────────────────────────────────────── */
  try {{
    Object.defineProperty(navigator, 'language',  {{get: function(){{ return '{FAKE_LANG}'; }}}});
    Object.defineProperty(navigator, 'languages', {{get: function(){{ return ['{FAKE_LANG}', 'en']; }}}});
  }} catch(e) {{}}

  /* ── Timezone ───────────────────────────────────────────────────────── */
  try {{
    var _origGTO = Date.prototype.getTimezoneOffset;
    Date.prototype.getTimezoneOffset = function() {{ return {FAKE_TZ_OFF}; }};
  }} catch(e) {{}}

  /* ── Plugin / MIME enumeration ──────────────────────────────────────── */
  try {{
    Object.defineProperty(navigator, 'plugins',   {{get: function(){{ return []; }}}});
    Object.defineProperty(navigator, 'mimeTypes', {{get: function(){{ return []; }}}});
  }} catch(e) {{}}

  /* ── Font enumeration via document.fonts ────────────────────────────── */
  try {{
    if (document.fonts && document.fonts.check) {{
      document.fonts.check = function() {{ return false; }};
    }}
  }} catch(e) {{}}

}})();
</script>"""


# Build once at import — same script for the whole process lifetime
POISON_SCRIPT: str = _build_script()
_INJECT_MARKER = b"data-sentinel=\"poison-v1\""


def inject(html: bytes, encoding: str = "utf-8") -> bytes:
    """
    Inject the poisoning script into an HTML response body.

    Injects immediately after <head> if present, otherwise before the first
    <script> tag, otherwise prepends to the body. Returns the modified bytes.
    Skips injection if the script is already present (idempotent).
    """
    if _INJECT_MARKER in html:
        return html   # already injected

    script_bytes = POISON_SCRIPT.encode(encoding, errors="replace")
    lower = html.lower()

    # Prefer injecting right after <head> — script runs before any other JS
    idx = lower.find(b"<head>")
    if idx != -1:
        pos = idx + len(b"<head>")
        return html[:pos] + b"\n" + script_bytes + b"\n" + html[pos:]

    # Fallback: before first <script> tag
    idx = lower.find(b"<script")
    if idx != -1:
        return html[:idx] + script_bytes + b"\n" + html[idx:]

    # Last resort: prepend everything
    return script_bytes + b"\n" + html
