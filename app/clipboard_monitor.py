# app/clipboard_monitor.py
from dotenv import load_dotenv
import os, time, json, socket
import requests, pyperclip, validators
from urllib.parse import urlparse
from datetime import datetime
from win10toast import ToastNotifier

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")  # put this in your .env

# --- Tunables ---
VT_THRESHOLD = 5            # block if VirusTotal "malicious" vendors >= 5
POLL_SECONDS = 1            # check clipboard every N seconds
LOG_FILE = "threat_report.txt"

toast = ToastNotifier()
DOMAIN_CACHE: dict[str, int] = {}

def log_event(event_type: str, url: str, domain: str | None, score: int, extra=None):
    line = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event_type,
        "url": url,
        "domain": domain,
        "vt_score": score,
        "extra": extra or {}
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")

def extract_domain(url_or_text: str) -> str | None:
    """Accept full URL or a bare host and return domain/host."""
    try:
        txt = url_or_text.strip()
        if not txt:
            return None
        parsed = urlparse(txt if "://" in txt else "http://" + txt)
        host = parsed.netloc or parsed.path
        host = host.split("@")[-1]      # drop creds if any
        host = host.split(":")[0]       # drop port
        if not host or "." not in host:
            return None
        return host.lower()
    except Exception:
        return None

def vt_domain_score(domain: str) -> int:
    """Return VirusTotal 'malicious' count for a domain (cached)."""
    if not VT_API_KEY:
        return 0
    if domain in DOMAIN_CACHE:
        return DOMAIN_CACHE[domain]
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            score = int(stats.get("malicious", 0))
            DOMAIN_CACHE[domain] = score
            return score
    except Exception:
        pass
    return 0

def block_domain_ips(domain: str) -> list[str]:
    """Resolve domain to IPv4s and block via Windows Firewall."""
    ips: list[str] = []
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET)
        ips = sorted({info[4][0] for info in infos})
    except Exception:
        pass

    for ip in ips:
        try:
            os.popen(f'netsh advfirewall firewall add rule name="AIHunter_Block_{ip}" dir=in action=block remoteip={ip}')
            os.popen(f'netsh advfirewall firewall add rule name="AIHunter_Block_{ip}_out" dir=out action=block remoteip={ip}')
        except Exception:
            pass
    return ips

def sanitize_clipboard():
    """Replace dangerous clipboard content with a safe marker."""
    try:
        pyperclip.copy("[AI Hunter blocked a malicious URL]")
    except Exception:
        pass

def main():
    if not VT_API_KEY:
        print("⚠️  VT_API_KEY not set in .env — clipboard monitor will run without VT scoring.")
    print("📋 Clipboard Protection running... (Ctrl+C to stop)")

    last_value = None
    while True:
        try:
            txt = pyperclip.paste()
        except Exception:
            txt = ""

        if txt and txt != last_value:
            last_value = txt
            # Consider as URL if validators says so OR if we can extract a plausible domain
            if validators.url(txt) or extract_domain(txt):
                domain = extract_domain(txt)
                if domain:
                    score = vt_domain_score(domain)
                    print(f"🔎 Clipboard URL -> {domain} | VT malicious: {score}")
                    log_event("clipboard_checked", txt, domain, score)

                    if score >= VT_THRESHOLD:
                        sanitize_clipboard()
                        ips = block_domain_ips(domain)
                        toast.show_toast(
                            "AI Hunter – Malicious URL Blocked 🚫",
                            f"{domain} flagged (score {score}). Clipboard sanitized.",
                            duration=5
                        )
                        log_event("clipboard_blocked", txt, domain, score, {"ips_blocked": ips})

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped.")
