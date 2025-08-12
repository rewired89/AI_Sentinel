# app/tools/virustotal_client.py
import os, json, urllib.request, urllib.error

API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
BASE = "https://www.virustotal.com/api/v3"

def _get(url: str):
    if not API_KEY:
        return {"ok": False, "error": "VIRUSTOTAL_API_KEY not set"}
    req = urllib.request.Request(url, headers={"x-apikey": API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            raw = r.read().decode("utf-8", "ignore")
            data = json.loads(raw or "{}")
            return {"ok": True, "data": data}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "ignore")
        except Exception:
            pass
        return {"ok": False, "error": f"HTTP {e.code}", "body": body}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _extract_stats(data: dict):
    try:
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        return {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
        }
    except Exception:
        return None

def lookup_ip(ip: str):
    res = _get(f"{BASE}/ip_addresses/{ip}")
    if not res["ok"]:
        return res
    return {"ok": True, "reputation": _extract_stats(res["data"]), "raw": res["data"]}

def lookup_domain(domain: str):
    res = _get(f"{BASE}/domains/{domain}")
    if not res["ok"]:
        return res
    return {"ok": True, "reputation": _extract_stats(res["data"]), "raw": res["data"]}

def lookup_hash(sha256_or_md5: str):
    res = _get(f"{BASE}/files/{sha256_or_md5}")
    if not res["ok"]:
        return res
    return {"ok": True, "reputation": _extract_stats(res["data"]), "raw": res["data"]}
