import argparse
import json
import sys
import platform
from aihunter.core.guards import GuardRegistry

def maybe_windows_alert(title: str, message: str):
    # Only try on Windows; fail silently elsewhere
    if platform.system().lower().startswith("win"):
        try:
            from aihunter.ui.alerts.windows_popup import show_alert
            show_alert(title, message)
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="AI Sentinel - Message Scanner")
    parser.add_argument("--subject", default="", help="Email subject")
    parser.add_argument("--text", default="", help="Plain text body")
    parser.add_argument("--html", default="", help="HTML body (optional)")
    args = parser.parse_args()

    reg = GuardRegistry()
    out = reg.scan_message(args.subject, args.text, args.html)

    print(json.dumps(out, indent=2))

    # Show Windows popup for risky outcomes
    if out["verdict"] in ("BLOCK", "SUSPICIOUS"):
        # Build a short English message with first hit if available
        first = out["hits"][0] if out.get("hits") else {}
        host = ""
        if "url" in first:
            try:
                from urllib.parse import urlparse
                host = urlparse(first["url"]).netloc
            except Exception:
                host = ""
        reason = first.get("reason", out["verdict"])
        msg = f"Access to {host or 'the link'} was blocked/flagged.\nReason: {reason}."
        title = "AI Sentinel — Security Alert"
        maybe_windows_alert(title, msg)

    # Exit codes
    if out["verdict"] == "BLOCK":
        sys.exit(2)
    elif out["verdict"] == "SUSPICIOUS":
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
