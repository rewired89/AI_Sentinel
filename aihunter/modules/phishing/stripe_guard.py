# aihunter/modules/phishing/stripe_guard.py
import os
import re
import html
import time
import requests
from urllib.parse import urlparse

VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# Regex simple y robusto para URLs
URL_REGEX = re.compile(r'(?i)\bhttps?://[^\s<>"\'\]\)]+')

def extract_urls_from_text(text: str):
    if not text:
        return []
    return list(set(URL_REGEX.findall(html.unescape(text))))

def is_official_stripe_domain(netloc: str) -> bool:
    n = netloc.lower().strip(".")
    return n == "stripe.com" or n.endswith(".stripe.com")

def looks_like_stripe_imposter(netloc: str) -> bool:
    n = netloc.lower()
    if is_official_stripe_domain(n):
        return False
    # “stripe” presente fuera del dominio oficial → señal fuerte
    if "stripe" in n:
        return True
    # Punycode/typos frecuentes
    if "str1pe" in n or "xn--" in n:
        return True
    return False

def vt_lookup_url(url: str, timeout=8):
    """Envía la URL a VT y consulta el análisis. Requiere VT_API_KEY."""
    if not VT_API_KEY:
        return {"ok": False, "reason": "no_vt_key"}
    try:
        headers = {"x-apikey": VT_API_KEY}
        # 1) Submit
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=timeout,
        )
        if submit.status_code >= 400:
            return {"ok": False, "reason": f"vt_submit_{submit.status_code}"}
        url_id = submit.json().get("data", {}).get("id")
        if not url_id:
            return {"ok": False, "reason": "vt_no_id"}
        # 2) Poll result (pequeña espera)
        time.sleep(1.2)
        res = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{url_id}",
            headers=headers,
            timeout=timeout,
        )
        if res.status_code >= 400:
            return {"ok": False, "reason": f"vt_get_{res.status_code}"}
        stats = res.json().get("data", {}).get("attributes", {}).get("stats", {})
        return {
            "ok": True,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "raw": stats,
        }
    except Exception as e:
        return {"ok": False, "reason": f"vt_exc_{type(e).__name__}"}

def otx_lookup_domain(domain: str, timeout=8):
    """Consulta si el dominio aparece en pulses de OTX. Requiere OTX_API_KEY."""
    if not OTX_API_KEY:
        return {"ok": False, "reason": "no_otx_key"}
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers,
            timeout=timeout,
        )
        if r.status_code == 404:
            return {"ok": True, "found": False, "pulses": 0}
        if r.status_code >= 400:
            return {"ok": False, "reason": f"otx_{r.status_code}"}
        data = r.json()
        pulses = len(data.get("pulse_info", {}).get("pulses", []))
        return {"ok": True, "found": True, "pulses": pulses}
    except Exception as e:
        return {"ok": False, "reason": f"otx_exc_{type(e).__name__}"}

def analyze_url(url: str):
    p = urlparse(url)
    netloc = (p.netloc or "").lower()

    # 1) Allowlist estricto: stripe.com y subdominios
    if is_official_stripe_domain(netloc):
        return {"decision": "ALLOW", "reason": "official_stripe_domain", "url": url}

    # 2) Heurística de impostor (rápida)
    heuristic_imposter = looks_like_stripe_imposter(netloc)

    vt = {"ok": False}
    otx = {"ok": False}

    # 3) Reputación (solo si parece impostor o si quieres ampliar cobertura)
    if heuristic_imposter:
        vt = vt_lookup_url(url)
        otx = otx_lookup_domain(netloc)

    vt_flag = vt.get("ok") and (vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0)
    otx_flag = otx.get("ok") and otx.get("found") and otx.get("pulses", 0) > 0

    # 4) Decisión combinada
    if heuristic_imposter and (vt_flag or otx_flag):
        return {
            "decision": "BLOCK",
            "reason": "stripe_imposter_reputation_hit",
            "url": url,
            "intel": {"vt": vt, "otx": otx},
        }
    if heuristic_imposter:
        return {
            "decision": "SUSPICIOUS",
            "reason": "stripe_imposter_pattern_no_intel",
            "url": url,
            "intel": {"vt": vt, "otx": otx},
        }
    return {"decision": "UNKNOWN", "reason": "non_stripe", "url": url}

class StripePhishingGuard:
    """
    Uso:
        guard = StripePhishingGuard()
        out = guard.scan_message(subject, body_text, body_html)
        out["verdict"] in {"ALLOW","SUSPICIOUS","BLOCK","UNKNOWN"}
    """
    def __init__(self):
        self.enabled = True

    def scan_message(self, subject: str = "", body_text: str = "", body_html: str = ""):
        urls = set()
        urls |= set(extract_urls_from_text(subject))
        urls |= set(extract_urls_from_text(body_text))
        urls |= set(extract_urls_from_text(body_html))

        hits = []
        verdict = "ALLOW"
        for u in urls:
            r = analyze_url(u)
            hits.append(r)
            if r["decision"] == "BLOCK":
                verdict = "BLOCK"
            elif r["decision"] == "SUSPICIOUS" and verdict != "BLOCK":
                verdict = "SUSPICIOUS"
            elif r["decision"] == "UNKNOWN" and verdict not in ("BLOCK", "SUSPICIOUS"):
                verdict = "UNKNOWN"

        return {
            "verdict": verdict if urls else "UNKNOWN",
            "hits": hits,
            "total_urls": len(urls),
        }
