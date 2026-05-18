"""
AI Sentinel — Plain-English Alert System.

Every security event that AI Sentinel detects gets translated into three things:
  1. What happened (no jargon)
  2. What AI Sentinel already did about it
  3. What you can do right now (optional, only when useful)

A Windows desktop notification is shown immediately, and every alert is also
written to data/alerts_human.json so there is a permanent readable history.
"""
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Alert structure
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    severity: str        # "info" | "warning" | "critical"
    headline: str        # One short line shown as the notification title
    what_happened: str   # Plain English — what the threat is
    what_we_did: str     # What AI Sentinel already did
    what_you_can_do: str # Tip for the user (empty string = nothing required)


# ---------------------------------------------------------------------------
# Message templates — one per threat type
# ---------------------------------------------------------------------------

_MESSAGES: dict[str, Alert] = {

    # --- Privacy proxy threats -----------------------------------------------

    "c2_beacon": Alert(
        severity        = "critical",
        headline        = "A program tried to contact a hacker's server",
        what_happened   = (
            "Something running on your computer sent signals that look exactly like "
            "malware checking in with its controller. This is how viruses receive "
            "instructions remotely."
        ),
        what_we_did     = (
            "AI Sentinel blocked that connection before it could go anywhere "
            "and logged exactly which program was responsible."
        ),
        what_you_can_do = (
            "Think about what you opened recently — an email attachment, a downloaded "
            "file, or a USB drive. Avoid opening anything new until this is cleared up. "
            "If this alert keeps appearing, restart your computer and run AI Sentinel again."
        ),
    ),

    "malicious_domain": Alert(
        severity        = "warning",
        headline        = "A dangerous website was blocked before it loaded",
        what_happened   = (
            "Your computer tried to connect to a website that security researchers "
            "around the world have flagged as dangerous — it may spread viruses, "
            "steal passwords, or run scams."
        ),
        what_we_did     = (
            "AI Sentinel blocked the connection completely. The website never "
            "received any data from you and nothing from it reached your computer."
        ),
        what_you_can_do = (
            "If you typed that address yourself, double-check you spelled it correctly — "
            "criminals create fake versions of popular sites with small typos. "
            "If you did not try to visit any website, something on your computer "
            "may be trying to connect without you knowing."
        ),
    ),

    # --- De-anonymization subtypes -------------------------------------------

    "deanon:WebRTC IP Leak": Alert(
        severity        = "warning",
        headline        = "A website tried to find your real location",
        what_happened   = (
            "The website used a browser feature called WebRTC — normally used for "
            "video calls — to try to discover your real IP address and location, "
            "bypassing the privacy protection you have enabled."
        ),
        what_we_did     = (
            "AI Sentinel detected the attempt and flagged it. Your real IP address "
            "was not exposed because your traffic is routed through the privacy layer."
        ),
        what_you_can_do = (
            "No action needed. This is the privacy layer working as designed. "
            "You can safely continue browsing."
        ),
    ),

    "deanon:Canvas Fingerprinting": Alert(
        severity        = "info",
        headline        = "A website tried to secretly identify your device",
        what_happened   = (
            "The website used a hidden technique called canvas fingerprinting — "
            "it draws invisible graphics in your browser and reads the tiny differences "
            "in how your computer renders them to create a unique ID for your device, "
            "so it can track you without cookies."
        ),
        what_we_did     = (
            "AI Sentinel detected the fingerprinting code in the page and logged it. "
            "This is recorded so you know which sites are trying to track you."
        ),
        what_you_can_do = (
            "This is very common on advertising-heavy websites. "
            "Consider whether you trust this site. No immediate action required."
        ),
    ),

    "deanon:Fingerprint Library": Alert(
        severity        = "info",
        headline        = "A website is running tracking software on your device",
        what_happened   = (
            "The page contains a known tracking library — software specifically "
            "designed to build a unique profile of your device and follow you "
            "across the internet without your permission."
        ),
        what_we_did     = (
            "AI Sentinel identified the library and logged which site is using it."
        ),
        what_you_can_do = (
            "This is extremely common. The privacy layer reduces what that library "
            "can learn about you. You don't need to do anything right now."
        ),
    ),

    "deanon:Plugin/Font Enumeration": Alert(
        severity        = "info",
        headline        = "A website checked what software you have installed",
        what_happened   = (
            "The website looked at what fonts and browser plugins are on your computer. "
            "This combination is often unique enough to identify you personally "
            "across different websites, even without cookies."
        ),
        what_we_did     = "AI Sentinel detected and logged this tracking attempt.",
        what_you_can_do = (
            "No action needed. The fewer browser extensions you have installed, "
            "the harder you are to fingerprint this way."
        ),
    ),

    "deanon:External IP Probe": Alert(
        severity        = "warning",
        headline        = "A website tried to look up your real IP address",
        what_happened   = (
            "The page tried to contact an external service — like 'what is my IP' — "
            "to find out your real internet address. This is a direct attempt to "
            "identify your location and bypass your privacy protection."
        ),
        what_we_did     = (
            "AI Sentinel detected the probe attempt. If you are routing through Nym, "
            "the IP address that service would see is a Nym exit node, not yours."
        ),
        what_you_can_do = (
            "Be cautious about this website. A legitimate site has no reason to "
            "look up your IP address this way."
        ),
    ),

    # --- Existing antivirus events -------------------------------------------

    "process_quarantined": Alert(
        severity        = "critical",
        headline        = "I stopped and locked away a suspicious program",
        what_happened   = (
            "A program on your computer was behaving the way viruses and malware "
            "behave — using unusual amounts of resources, hiding itself, or trying "
            "to communicate in suspicious ways."
        ),
        what_we_did     = (
            "AI Sentinel stopped that program immediately and locked a copy of it "
            "in a secure quarantine folder so it cannot run again. "
            "The threat is contained."
        ),
        what_you_can_do = (
            "Your computer is safer now. Avoid opening new files or email attachments "
            "until you restart. If this happens repeatedly, consider running a "
            "full system scan with Windows Defender."
        ),
    ),

    "malicious_ip_blocked": Alert(
        severity        = "warning",
        headline        = "Your computer was talking to a known criminal server — I cut it off",
        what_happened   = (
            "An active connection on your computer was going to an IP address that "
            "security agencies worldwide have linked to criminal activity — "
            "things like ransomware, botnets, or data theft."
        ),
        what_we_did     = (
            "AI Sentinel cut that connection and blocked the address in your firewall. "
            "No further communication with that server is possible."
        ),
        what_you_can_do = (
            "Check which programs are open right now and close anything unfamiliar. "
            "If you did not install a program recently, this may mean something "
            "was installed without your knowledge."
        ),
    ),

    "otx_threat_found": Alert(
        severity        = "warning",
        headline        = "A connection to a known threat was blocked",
        what_happened   = (
            "Your computer was connected to an address that appears in global "
            "threat intelligence feeds — databases maintained by security researchers "
            "tracking active hacking campaigns."
        ),
        what_we_did     = (
            "AI Sentinel added a firewall rule blocking all traffic to and from "
            "that address. The connection is permanently cut."
        ),
        what_you_can_do = "No immediate action required. AI Sentinel is monitoring.",
    ),

    "port_exposed": Alert(
        severity        = "warning",
        headline        = "A door to your computer is open to the internet",
        what_happened   = (
            "A network port that should not be publicly visible is currently "
            "accessible from outside your home or office network. This is like "
            "leaving a door to your house unlocked — attackers scan for these."
        ),
        what_we_did     = "AI Sentinel detected and logged the open port.",
        what_you_can_do = (
            "If you did not intentionally set up a server or remote access, "
            "restart the program using that port or restart your computer. "
            "Check your router settings if this happens repeatedly."
        ),
    ),

    "kill_switch_activated": Alert(
        severity        = "critical",
        headline        = "Your internet has been cut off to protect you",
        what_happened   = (
            "AI Sentinel detected a serious threat and activated the emergency "
            "network kill-switch — your computer is now completely disconnected "
            "from the internet to stop any ongoing attack."
        ),
        what_we_did     = (
            "All outgoing internet traffic has been blocked using your firewall. "
            "Nothing can leave your computer right now."
        ),
        what_you_can_do = (
            "Your internet will be restored automatically in a short while. "
            "While offline, avoid plugging in USB drives or external devices. "
            "When reconnected, restart your browser."
        ),
    ),

    # --- Fallback for unknown types -------------------------------------------

    "unknown": Alert(
        severity        = "info",
        headline        = "AI Sentinel flagged something unusual",
        what_happened   = "An unusual security event was detected on your computer.",
        what_we_did     = "AI Sentinel has logged it for review.",
        what_you_can_do = "No immediate action required.",
    ),
}


# ---------------------------------------------------------------------------
# Alert log
# ---------------------------------------------------------------------------

_LOG_PATH  = Path(__file__).parent.parent / "data" / "alerts_human.json"
_log_lock  = threading.Lock()


def _write_log(threat_type: str, alert: Alert, extra: dict) -> None:
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts":               datetime.now(timezone.utc).isoformat(),
        "severity":         alert.severity,
        "threat_type":      threat_type,
        "headline":         alert.headline,
        "what_happened":    alert.what_happened,
        "what_we_did":      alert.what_we_did,
        "what_you_can_do":  alert.what_you_can_do,
        **extra,
    }
    with _log_lock:
        existing: list = []
        if _LOG_PATH.exists():
            try:
                existing = json.loads(_LOG_PATH.read_text())
            except Exception:
                pass
        existing.append(entry)
        _LOG_PATH.write_text(json.dumps(existing[-200:], indent=2))


# ---------------------------------------------------------------------------
# Notification delivery
# ---------------------------------------------------------------------------

def _toast(title: str, message: str) -> None:
    """Show a Windows desktop notification. Silent if plyer is unavailable."""
    try:
        from plyer import notification
        notification.notify(
            app_name    = "AI Sentinel",
            title       = title,
            message     = message,
            timeout     = 12,
        )
        return
    except Exception:
        pass
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast(title, message, duration=12, threaded=True)
    except Exception:
        pass


def _severity_prefix(severity: str) -> str:
    return {"critical": "🚨 ", "warning": "⚠️ ", "info": "ℹ️ "}.get(severity, "")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def notify(threat_type: str, extra: dict | None = None) -> None:
    """
    Look up the plain-English alert for threat_type, log it, and show a
    Windows desktop notification.

    threat_type examples:
      "c2_beacon", "malicious_domain", "deanon:WebRTC IP Leak",
      "process_quarantined", "malicious_ip_blocked", "port_exposed"

    extra: optional dict of technical details (host, url, pid, etc.) to
           include in the log entry alongside the human message.
    """
    alert = _MESSAGES.get(threat_type) or _MESSAGES.get(
        # Try matching deanon sub-category even if category combo not in dict
        next((k for k in _MESSAGES if threat_type.startswith(k)), "unknown")
    ) or _MESSAGES["unknown"]

    extra = extra or {}
    _write_log(threat_type, alert, extra)

    # Notification body: what happened + what we did (keep it concise)
    body = f"{alert.what_happened}\n\n{alert.what_we_did}"
    if alert.what_you_can_do:
        body += f"\n\n{alert.what_you_can_do}"

    prefix = _severity_prefix(alert.severity)
    _toast(f"{prefix}{alert.headline}", body)

    # Always print to terminal too — useful when running from PowerShell
    print(f"\n{'='*60}")
    print(f"  {prefix}{alert.headline}")
    print(f"{'='*60}")
    print(f"  What happened:   {alert.what_happened}")
    print(f"  What we did:     {alert.what_we_did}")
    if alert.what_you_can_do:
        print(f"  What you can do: {alert.what_you_can_do}")
    print(f"{'='*60}\n")


def notify_deanon(findings: list, host: str) -> None:
    """
    Convenience wrapper for de-anonymization findings from the proxy.
    Fires one notification per distinct category found.
    """
    seen: set[str] = set()
    for finding in findings:
        key = f"deanon:{finding.category}"
        if key not in seen:
            seen.add(key)
            notify(key, extra={"host": host, "snippet": finding.snippet})
