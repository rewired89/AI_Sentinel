"""
De-anonymization attempt detector.
Scans HTTP response bodies (JS/HTML) for patterns that could reveal the user's
real identity, IP address, or device fingerprint even when routing through a proxy.
"""
import re
from dataclasses import dataclass
from typing import List

# WebRTC STUN/TURN usage — the browser makes UDP connections that bypass proxies,
# leaking the real IP unless WebRTC is disabled or properly isolated.
_WEBRTC = [
    r"new\s+RTCPeerConnection\s*\(",
    r"webkitRTCPeerConnection\s*\(",
    r"mozRTCPeerConnection\s*\(",
    r"RTCIceCandidate",
    r"onicecandidate\s*=",
    r"createOffer\s*\(",
    r"stun:[a-zA-Z0-9.\-:]+",
]

# Canvas fingerprinting — draws text/shapes and reads pixel data to create a
# device-specific hash without any permission prompt.
_CANVAS = [
    r"\.toDataURL\s*\(",
    r"\.getImageData\s*\(",
    r"fillText\s*\(",
    r"measureText\s*\(",
]

# Known fingerprint library signatures found in minified JS bundles.
_FP_LIBS = [
    r"fingerprintjs",
    r"Fingerprint2",
    r"ClientJS",
    r"fpjs-pro",
    r"fp\.get\s*\(",
    r"getFingerprint\s*\(",
    r'"visitorId"',
]

# Font/plugin enumeration — enumerates installed fonts or MIME types to build
# a fingerprint without any explicit sensor access.
_ENUM = [
    r"navigator\.plugins",
    r"navigator\.mimeTypes",
    r"document\.fonts\.check",
    r"document\.fonts\.load",
]

# External IP probing — explicit calls to IP-reveal services.
_IP_PROBE = [
    r"ipify\.org",
    r"icanhazip\.com",
    r"api\.ip\.sb",
    r"checkip\.",
    r"whatismyip\.",
    r"ifconfig\.me",
]


@dataclass
class Finding:
    category: str
    snippet: str   # short surrounding context, truncated


def scan_response_body(body: str, url: str = "") -> List[Finding]:
    """
    Scan an HTTP response body for de-anonymization techniques.
    Returns one Finding per category hit; empty list means clean.
    """
    findings: List[Finding] = []

    checks = [
        ("WebRTC IP Leak",          _WEBRTC),
        ("Canvas Fingerprinting",   _CANVAS),
        ("Fingerprint Library",     _FP_LIBS),
        ("Plugin/Font Enumeration", _ENUM),
        ("External IP Probe",       _IP_PROBE),
    ]

    for category, patterns in checks:
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                s = max(0, m.start() - 40)
                e = min(len(body), m.end() + 40)
                snippet = body[s:e].replace("\n", " ").strip()[:120]
                findings.append(Finding(category=category, snippet=snippet))
                break  # one finding per category is sufficient

    return findings
