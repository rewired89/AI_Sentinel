"""
AI Sentinel Privacy Proxy — mitmproxy addon.

Sits between the user and the Nym SOCKS5 upstream. Every request and response
passes through this layer before anything reaches the network or the browser.

Threat layers:
  request  → C2 beacon heuristics, malicious domain/IP check (VT + OTX, cached)
  response → de-anonymization / fingerprinting scan on JS + HTML payloads

Blocked traffic gets a 403 with a plain-text explanation. Deanon findings are
injected as an X-Sentinel-Warning header so the browser extension can surface
an alert without the proxy having to push a notification itself.
"""
import os
import sys
import json
import time
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from mitmproxy import http, ctx
from privacy.proxy.deanon_detector import scan_response_body
from privacy.proxy.poison_injector import inject as _poison_inject
from privacy.alerts import notify, notify_deanon

# ---------------------------------------------------------------------------
# AI-generated rules — loaded from data/ai_rules.json, hot-reloaded on change
# ---------------------------------------------------------------------------

_AI_RULES_FILE  = ROOT / "data" / "ai_rules.json"
_ai_rules_lock  = threading.Lock()
_ai_rules_mtime = 0.0
_ai_rules: dict = {
    "block_domains":           [],
    "block_ips":               [],
    "block_ua_patterns":       [],
    "block_path_patterns":     [],
    "block_response_patterns": [],
}


def _reload_ai_rules() -> None:
    """Reload data/ai_rules.json if it has changed on disk."""
    global _ai_rules_mtime, _ai_rules
    try:
        mtime = _AI_RULES_FILE.stat().st_mtime
        if mtime <= _ai_rules_mtime:
            return
        rules = json.loads(_AI_RULES_FILE.read_text())
        with _ai_rules_lock:
            _ai_rules       = rules
            _ai_rules_mtime = mtime
        ctx.log.info(
            f"[sentinel] AI rules reloaded — "
            f"{len(rules.get('block_domains', []))} domains, "
            f"{len(rules.get('block_ips', []))} IPs"
        )
    except Exception:
        pass


def _ai_block_domains() -> list[str]:
    with _ai_rules_lock:
        return _ai_rules.get("block_domains", [])


def _ai_block_ips() -> list[str]:
    with _ai_rules_lock:
        return _ai_rules.get("block_ips", [])


def _ai_block_ua_patterns() -> list[str]:
    with _ai_rules_lock:
        return _ai_rules.get("block_ua_patterns", [])


def _ai_block_path_patterns() -> list[str]:
    with _ai_rules_lock:
        return _ai_rules.get("block_path_patterns", [])


def _ai_block_response_patterns() -> list[str]:
    with _ai_rules_lock:
        return _ai_rules.get("block_response_patterns", [])

def _tray_threat(host: str = "") -> None:
    """Increment blocked counter, flash tray red for 30 s, then restore."""
    try:
        import privacy.tray as _tray
        from privacy.tray import TrayState
        _tray.increment_blocked()
        prev = _tray._state
        _tray.set_state(TrayState.THREAT, threat_host=host)
        def _restore():
            import time
            time.sleep(30)
            _tray.set_state(prev)
        threading.Thread(target=_restore, daemon=True).start()
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Domain/IP reputation cache  (TTL = 10 min, thread-safe)
# ---------------------------------------------------------------------------
_cache: dict[str, tuple[bool, float]] = {}
_cache_lock = threading.Lock()
CACHE_TTL = 600


def _cache_get(key: str) -> Optional[bool]:
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.time() - entry[1] < CACHE_TTL:
            return entry[0]
        if entry:
            del _cache[key]
    return None


def _cache_set(key: str, is_threat: bool) -> None:
    with _cache_lock:
        _cache[key] = (is_threat, time.time())


# ---------------------------------------------------------------------------
# Threat intelligence lookups (run in background threads to stay non-blocking)
# ---------------------------------------------------------------------------

def _vt_check_domain(domain: str) -> bool:
    vt_key = (os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY", "")).strip()
    if not vt_key:
        return False
    try:
        import requests as _req
        r = _req.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": vt_key},
            timeout=5,
        )
        if r.status_code == 200:
            stats = (
                r.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return int(stats.get("malicious", 0)) > 0 or int(stats.get("suspicious", 0)) > 1
    except Exception:
        pass
    return False


def _otx_check_domain(domain: str) -> bool:
    otx_key = (os.getenv("ALIENVAULT_API_KEY") or os.getenv("OTX_API_KEY", "")).strip()
    if not otx_key:
        return False
    try:
        import requests as _req
        r = _req.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"X-OTX-API-KEY": otx_key},
            timeout=5,
        )
        if r.status_code == 200:
            return int(r.json().get("pulse_info", {}).get("count", 0)) > 0
    except Exception:
        pass
    return False


def _urlhaus_check_domain(domain: str) -> bool:
    """URLhaus — free, no API key. Checks if domain hosts malware."""
    try:
        import requests as _req
        r = _req.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=5,
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("query_status") == "is_host" and data.get("urls_count", 0) > 0
    except Exception:
        pass
    return False


def _threatfox_check_domain(domain: str) -> bool:
    """ThreatFox — free, no API key. Checks domain against IOC database."""
    try:
        import requests as _req
        r = _req.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": domain},
            timeout=5,
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("query_status") == "ok" and len(data.get("data", [])) > 0
    except Exception:
        pass
    return False


def _background_check(domain: str) -> None:
    """Check domain against all available threat intel sources (background thread)."""
    result = (
        _urlhaus_check_domain(domain)    # always active — no key needed
        or _threatfox_check_domain(domain)  # always active — no key needed
        or _vt_check_domain(domain)      # active when VIRUSTOTAL_API_KEY is set
        or _otx_check_domain(domain)     # active when ALIENVAULT_API_KEY is set
    )
    _cache_set(domain, result)
    if result:
        ctx.log.warn(f"[sentinel] Threat confirmed: {domain} — will block on next request.")


# ---------------------------------------------------------------------------
# C2 beacon heuristics
# ---------------------------------------------------------------------------

_C2_UA = [
    "python-requests", "curl/", "wget/", "go-http-client",
    "masscan", "zgrab", "nuclei", "sqlmap", "nmap scripting",
]
_C2_PATHS = [
    "/gate.php", "/panel/", "/c2/", "/bot/", "/rat/",
    "/update.php", "/task.php", "/check.php",
    "/beacon", "/callback", "/ping?id=", "/report.php",
]


def _is_c2_beacon(flow: http.HTTPFlow) -> bool:
    ua   = (flow.request.headers.get("user-agent") or "").lower()
    path = flow.request.path.lower()
    return (
        any(p in ua   for p in _C2_UA) or
        any(p in path for p in _C2_PATHS)
    )


# ---------------------------------------------------------------------------
# Threat log
# ---------------------------------------------------------------------------

_THREAT_LOG = ROOT / "data" / "privacy_threats.json"
_log_lock   = threading.Lock()


def _log_threat(entry: dict) -> None:
    _THREAT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with _log_lock:
        existing: list = []
        if _THREAT_LOG.exists():
            try:
                existing = json.loads(_THREAT_LOG.read_text())
            except Exception:
                pass
        existing.append(entry)
        _THREAT_LOG.write_text(json.dumps(existing[-500:], indent=2))


# ---------------------------------------------------------------------------
# mitmproxy addon
# ---------------------------------------------------------------------------

class SentinelProxyAddon:

    def request(self, flow: http.HTTPFlow) -> None:
        # Hot-reload AI rules if the file changed
        _reload_ai_rules()

        host = flow.request.pretty_host
        url  = flow.request.pretty_url

        # Skip loopback / private addresses (localhost, LAN, etc.)
        try:
            import ipaddress
            if ipaddress.ip_address(host).is_private:
                return
        except ValueError:
            pass  # hostname — proceed

        # --- AI-generated domain blocklist ---
        if host in _ai_block_domains():
            ctx.log.warn(f"[sentinel] AI-blocked domain: {host}")
            _log_threat({
                "type": "ai_blocked_domain",
                "url": url,
                "host": host,
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            notify("malicious_domain", extra={"url": url, "host": host})
            _tray_threat(host)
            flow.response = http.Response.make(
                403,
                f"AI Sentinel: {host} blocked by threat intelligence.".encode(),
                {"Content-Type": "text/plain"},
            )
            return

        # --- AI-generated IP blocklist ---
        if host in _ai_block_ips():
            ctx.log.warn(f"[sentinel] AI-blocked IP: {host}")
            _log_threat({
                "type": "ai_blocked_ip",
                "url": url,
                "host": host,
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            notify("malicious_domain", extra={"url": url, "host": host})
            _tray_threat(host)
            flow.response = http.Response.make(
                403,
                f"AI Sentinel: {host} blocked by threat intelligence.".encode(),
                {"Content-Type": "text/plain"},
            )
            return

        # --- C2 beacon check (hardcoded + AI patterns) ---
        ua   = (flow.request.headers.get("user-agent") or "").lower()
        path = flow.request.path.lower()
        ai_ua_hit   = any(p in ua   for p in _ai_block_ua_patterns())
        ai_path_hit = any(p in path for p in _ai_block_path_patterns())

        if _is_c2_beacon(flow) or ai_ua_hit or ai_path_hit:
            ctx.log.warn(f"[sentinel] C2 beacon blocked: {url}")
            _log_threat({
                "type": "c2_beacon",
                "url": url,
                "host": host,
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            notify("c2_beacon", extra={"url": url, "host": host})
            _tray_threat(host)
            flow.response = http.Response.make(
                403,
                b"AI Sentinel: C2 beacon pattern blocked.",
                {"Content-Type": "text/plain"},
            )
            return

        # --- Domain reputation check ---
        cached = _cache_get(host)

        if cached is True:
            # Known bad — block immediately
            ctx.log.warn(f"[sentinel] Malicious domain blocked: {host}")
            _log_threat({
                "type": "malicious_domain",
                "url": url,
                "host": host,
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            notify("malicious_domain", extra={"url": url, "host": host})
            flow.response = http.Response.make(
                403,
                f"AI Sentinel: {host} is flagged as malicious.".encode(),
                {"Content-Type": "text/plain"},
            )
        elif cached is None:
            # Unknown — let this request through but check in background so the
            # next request to the same host will be caught if it's bad.
            threading.Thread(target=_background_check, args=(host,), daemon=True).start()
        # cached is False → known clean, allow silently

    def response(self, flow: http.HTTPFlow) -> None:
        # Only scan JS and HTML — skip images, fonts, binary assets
        ct = flow.response.headers.get("content-type", "")
        if "javascript" not in ct and "html" not in ct:
            return

        try:
            body = flow.response.get_text(strict=False) or ""
        except Exception:
            return

        # Skip huge files (> 2 MB) to avoid latency spikes
        if len(body) > 2_000_000:
            return

        # Always inject fingerprint-poisoning script into HTML responses.
        # This runs even when no deanon patterns are detected — proactive defence.
        if "html" in ct:
            try:
                raw      = flow.response.raw_content or b""
                encoding = flow.response.headers.get("content-type", "")
                enc      = "utf-8"
                if "charset=" in encoding:
                    enc = encoding.split("charset=")[-1].split(";")[0].strip() or "utf-8"
                flow.response.raw_content = _poison_inject(raw, enc)
                # Remove Content-Length so mitmproxy recalculates it
                flow.response.headers.pop("content-length", None)
            except Exception as exc:
                ctx.log.debug(f"[sentinel] Poison inject failed: {exc}")

        # --- AI-generated response body patterns ---
        for pattern in _ai_block_response_patterns():
            if pattern and pattern in body:
                host = flow.request.pretty_host
                ctx.log.warn(f"[sentinel] AI-blocked malicious payload from {host}: {pattern[:40]}")
                _log_threat({
                    "type":    "ai_blocked_payload",
                    "host":    host,
                    "url":     flow.request.pretty_url,
                    "pattern": pattern[:80],
                    "ts":      datetime.now(timezone.utc).isoformat(),
                })
                _tray_threat(host)
                flow.response = http.Response.make(
                    403,
                    b"AI Sentinel: Malicious payload blocked.",
                    {"Content-Type": "text/plain"},
                )
                return

        findings = scan_response_body(body, url=flow.request.pretty_url)
        if not findings:
            return

        host    = flow.request.pretty_host
        summary = [{"category": f.category, "snippet": f.snippet} for f in findings]

        ctx.log.warn(
            f"[sentinel] De-anonymization from {host}: "
            + ", ".join(f.category for f in findings)
        )
        _log_threat({
            "type":     "deanon_attempt",
            "host":     host,
            "url":      flow.request.pretty_url,
            "findings": summary,
            "ts":       datetime.now(timezone.utc).isoformat(),
        })
        notify_deanon(findings, host=host)
        _tray_threat(host)

        # Inject warning header — browser extension reads this and shows an alert.
        flow.response.headers["X-Sentinel-Warning"] = (
            "deanon:" + ",".join(f.category for f in findings)
        )


addons = [SentinelProxyAddon()]
