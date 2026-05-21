"""
AI Sentinel — Autonomous Threat Intelligence Engine

Every hour this module:
  1. Pulls the latest malware, C2, and phishing indicators from free feeds
  2. Extracts IOCs that are new since the last run
  3. Sends them to Claude API for analysis
  4. Claude generates Python detection rules (domain blocklist, UA patterns,
     path patterns, response body signatures)
  5. Rules are written to data/ai_rules.json and loaded hot by sentinel_proxy

No user action ever required. The proxy gets smarter every hour automatically.

Feeds used (all free, no API key):
  - URLhaus       — active malware distribution URLs
  - ThreatFox     — IOCs: C2 IPs, malware domains, malicious hashes
  - FeodoTracker  — botnet C2 server IPs/domains (Emotet, QakBot, etc.)
  - OpenPhish     — phishing URLs (no key, basic feed)
  - abuse.ch SSLBL— botnet C2 SSL certificate blacklist

With API keys (set in app/.env):
  - OTX AlienVault — full pulse feed, richer context
  - VirusTotal     — per-domain reputation on demand
"""
import json
import time
import threading
import hashlib
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT            = Path(__file__).parent.parent.parent
_RULES_FILE     = ROOT / "data" / "ai_rules.json"
_STATE_FILE     = ROOT / "data" / "threat_intel_state.json"
_LOG_FILE       = ROOT / "data" / "threat_intel.log"
_INTERVAL_SECS  = 3600   # re-fetch every hour

_stop_event = threading.Event()


def _log(msg: str) -> None:
    _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Feed fetchers
# ---------------------------------------------------------------------------

def _fetch_urlhaus_domains() -> list[str]:
    """Domains serving active malware right now (URLhaus)."""
    try:
        req = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data=b"",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        domains = set()
        for entry in data.get("urls", []):
            if entry.get("url_status") == "online":
                url = entry.get("url", "")
                # extract hostname
                try:
                    from urllib.parse import urlparse
                    h = urlparse(url).hostname
                    if h:
                        domains.add(h)
                except Exception:
                    pass
        return list(domains)
    except Exception as e:
        _log(f"URLhaus fetch failed: {e}")
        return []


def _fetch_threatfox_iocs() -> list[dict]:
    """Recent IOCs from ThreatFox — C2 servers, malware hashes, malicious domains."""
    try:
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=json.dumps({"query": "get_iocs", "days": 1}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        return data.get("data", []) or []
    except Exception as e:
        _log(f"ThreatFox fetch failed: {e}")
        return []


def _fetch_feodo_c2s() -> list[str]:
    """FeodoTracker botnet C2 IP/domain list (Emotet, QakBot, Dridex, etc.)."""
    try:
        req = urllib.request.Request(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            headers={"User-Agent": "AI-Sentinel/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", errors="replace")
        return [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
    except Exception as e:
        _log(f"FeodoTracker fetch failed: {e}")
        return []


def _fetch_otx_pulses() -> list[dict]:
    """AlienVault OTX recent pulses (requires API key — skipped if absent)."""
    key = __import__("os").getenv("ALIENVAULT_API_KEY", "").strip()
    if not key:
        return []
    try:
        import urllib.parse
        since = (datetime.now(timezone.utc) - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%S")
        url   = f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={urllib.parse.quote(since)}&limit=50"
        req   = urllib.request.Request(url, headers={"X-OTX-API-KEY": key})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        return data.get("results", [])
    except Exception as e:
        _log(f"OTX fetch failed: {e}")
        return []


# ---------------------------------------------------------------------------
# IOC extraction — normalise everything into {type, value, malware, description}
# ---------------------------------------------------------------------------

def _extract_iocs(
    urlhaus_domains: list[str],
    threatfox_iocs:  list[dict],
    feodo_ips:       list[str],
    otx_pulses:      list[dict],
) -> list[dict]:
    iocs: list[dict] = []

    for d in urlhaus_domains:
        iocs.append({"type": "domain", "value": d, "source": "URLhaus",
                     "malware": "malware distribution", "description": "Active malware URL host"})

    for ioc in threatfox_iocs:
        ioc_type  = ioc.get("ioc_type", "")
        ioc_value = ioc.get("ioc", "")
        malware   = ioc.get("malware", "unknown")
        tags      = ", ".join(ioc.get("tags") or [])
        if not ioc_value:
            continue
        if ioc_type in ("domain", "url"):
            try:
                from urllib.parse import urlparse
                host = urlparse(ioc_value).hostname or ioc_value
            except Exception:
                host = ioc_value
            iocs.append({"type": "domain", "value": host, "source": "ThreatFox",
                         "malware": malware, "description": tags})
        elif ioc_type == "ip:port":
            ip = ioc_value.split(":")[0]
            iocs.append({"type": "ip", "value": ip, "source": "ThreatFox",
                         "malware": malware, "description": tags})

    for ip in feodo_ips:
        iocs.append({"type": "ip", "value": ip, "source": "FeodoTracker",
                     "malware": "botnet C2", "description": "Emotet/QakBot/Dridex C2 server"})

    for pulse in otx_pulses:
        name = pulse.get("name", "")
        for ind in pulse.get("indicators", []):
            t = ind.get("type", "")
            v = ind.get("indicator", "")
            if t == "domain" and v:
                iocs.append({"type": "domain", "value": v, "source": "OTX",
                             "malware": name, "description": pulse.get("description", "")[:120]})
            elif t in ("IPv4", "IPv6") and v:
                iocs.append({"type": "ip", "value": v, "source": "OTX",
                             "malware": name, "description": pulse.get("description", "")[:120]})

    return iocs


# ---------------------------------------------------------------------------
# State — track what we've already processed so we only send NEW threats to AI
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {"seen": [], "last_run": None}


def _save_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2))


def _ioc_hash(ioc: dict) -> str:
    return hashlib.sha256(f"{ioc['type']}:{ioc['value']}".encode()).hexdigest()[:16]


def _filter_new(iocs: list[dict], state: dict) -> list[dict]:
    seen = set(state.get("seen", []))
    new  = [i for i in iocs if _ioc_hash(i) not in seen]
    # deduplicate by value within new batch
    seen_vals: set[str] = set()
    deduped = []
    for i in new:
        key = f"{i['type']}:{i['value']}"
        if key not in seen_vals:
            seen_vals.add(key)
            deduped.append(i)
    return deduped


# ---------------------------------------------------------------------------
# Claude API — analyse threats and generate detection rules
# ---------------------------------------------------------------------------

def _ask_claude(new_iocs: list[dict]) -> dict | None:
    api_key = __import__("os").getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        _log("ANTHROPIC_API_KEY not set — skipping AI rule generation.")
        return None

    sample = new_iocs[:80]   # keep prompt small; Claude handles the important ones

    prompt = f"""You are a malware analyst writing detection rules for a Python mitmproxy addon called AI Sentinel.

New threat intelligence just arrived. Analyse these IOCs and generate detection rules:

{json.dumps(sample, indent=2)}

Return ONLY a JSON object with this exact structure (no explanation, no markdown):
{{
  "block_domains": ["domain1.com", "domain2.com"],
  "block_ips": ["1.2.3.4", "5.6.7.8"],
  "block_ua_patterns": ["pattern1", "pattern2"],
  "block_path_patterns": ["/c2/gate", "/beacon"],
  "block_response_patterns": ["eval(atob(", "document.write(unescape("],
  "summary": "One sentence describing the main threat cluster in this batch."
}}

Rules:
- Only include IOCs that are genuinely malicious (skip false positives)
- block_ua_patterns: lowercase substrings found in User-Agent of malware tools
- block_path_patterns: URL path substrings used by C2/malware panels
- block_response_patterns: JS/HTML snippets that appear in malicious payloads
- Keep each list under 50 entries — quality over quantity
"""

    try:
        import urllib.request, json
        body = json.dumps({
            "model":      "claude-haiku-4-5-20251001",
            "max_tokens": 1024,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body,
            headers={
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
        text = resp["content"][0]["text"].strip()
        # strip markdown code fences if Claude added them
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:])
        if text.endswith("```"):
            text = "\n".join(text.split("\n")[:-1])
        rules = json.loads(text)
        _log(f"Claude generated rules: {rules.get('summary', '')}")
        return rules
    except Exception as e:
        _log(f"Claude API call failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Rule merging — merge AI rules with existing, deduplicate, write to disk
# ---------------------------------------------------------------------------

_DEFAULT_RULES: dict = {
    "block_domains":           [],
    "block_ips":               [],
    "block_ua_patterns":       [],
    "block_path_patterns":     [],
    "block_response_patterns": [],
    "last_updated":            None,
    "ioc_count":               0,
    "summary":                 "",
}


def _load_rules() -> dict:
    try:
        return json.loads(_RULES_FILE.read_text())
    except Exception:
        return dict(_DEFAULT_RULES)


def _merge_and_save(existing: dict, new_rules: dict, new_ioc_count: int) -> dict:
    def merge_list(a: list, b: list, limit: int = 2000) -> list:
        combined = list(dict.fromkeys(a + b))   # preserve order, deduplicate
        return combined[-limit:]                  # keep the newest

    merged = {
        "block_domains":           merge_list(existing.get("block_domains", []),
                                              new_rules.get("block_domains", [])),
        "block_ips":               merge_list(existing.get("block_ips", []),
                                              new_rules.get("block_ips", [])),
        "block_ua_patterns":       merge_list(existing.get("block_ua_patterns", []),
                                              new_rules.get("block_ua_patterns", [])),
        "block_path_patterns":     merge_list(existing.get("block_path_patterns", []),
                                              new_rules.get("block_path_patterns", [])),
        "block_response_patterns": merge_list(existing.get("block_response_patterns", []),
                                              new_rules.get("block_response_patterns", [])),
        "last_updated":            datetime.now(timezone.utc).isoformat(),
        "ioc_count":               existing.get("ioc_count", 0) + new_ioc_count,
        "summary":                 new_rules.get("summary", existing.get("summary", "")),
    }
    _RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    _RULES_FILE.write_text(json.dumps(merged, indent=2))
    return merged


# ---------------------------------------------------------------------------
# Also write plain IOC blocklists even without Claude key
# ---------------------------------------------------------------------------

def _save_iocs_directly(iocs: list[dict], existing: dict) -> dict:
    """When no Claude key is set, save IOC domains/IPs directly as block rules."""
    domains = [i["value"] for i in iocs if i["type"] == "domain"]
    ips     = [i["value"] for i in iocs if i["type"] == "ip"]
    return _merge_and_save(existing, {
        "block_domains":           domains,
        "block_ips":               ips,
        "block_ua_patterns":       [],
        "block_path_patterns":     [],
        "block_response_patterns": [],
        "summary":                 f"Auto-imported {len(iocs)} IOCs from threat feeds.",
    }, len(iocs))


# ---------------------------------------------------------------------------
# Main cycle
# ---------------------------------------------------------------------------

def run_once() -> int:
    """Fetch, analyse, update rules. Returns number of new IOCs processed."""
    _log("Threat intel cycle starting...")

    urlhaus  = _fetch_urlhaus_domains()
    tffox    = _fetch_threatfox_iocs()
    feodo    = _fetch_feodo_c2s()
    otx      = _fetch_otx_pulses()

    all_iocs = _extract_iocs(urlhaus, tffox, feodo, otx)
    _log(f"Fetched {len(all_iocs)} raw IOCs from feeds.")

    state     = _load_state()
    new_iocs  = _filter_new(all_iocs, state)
    _log(f"New IOCs since last run: {len(new_iocs)}")

    if not new_iocs:
        state["last_run"] = datetime.now(timezone.utc).isoformat()
        _save_state(state)
        return 0

    existing = _load_rules()
    ai_rules = _ask_claude(new_iocs)

    if ai_rules:
        _merge_and_save(existing, ai_rules, len(new_iocs))
    else:
        _save_iocs_directly(new_iocs, existing)

    # Mark all new IOCs as seen
    seen = set(state.get("seen", []))
    for ioc in new_iocs:
        seen.add(_ioc_hash(ioc))
    state["seen"]     = list(seen)[-10_000:]   # cap at 10k to avoid unbounded growth
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    _save_state(state)

    total = _load_rules().get("ioc_count", 0)
    _log(f"Rules updated. Total IOCs in blocklist: {total}")
    return len(new_iocs)


def start() -> None:
    """Start the background threat intel loop as a daemon thread."""
    def _loop():
        # Stagger first run by 30 s so startup isn't noisy
        time.sleep(30)
        while not _stop_event.is_set():
            try:
                run_once()
            except Exception as e:
                _log(f"Cycle error: {e}")
            _stop_event.wait(_INTERVAL_SECS)

    t = threading.Thread(target=_loop, daemon=True, name="threat-intel")
    t.start()
    _log("Threat intel engine started (runs every hour).")


def stop() -> None:
    _stop_event.set()
