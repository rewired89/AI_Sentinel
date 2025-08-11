# app/trust.py
import json, os, subprocess, shlex

# Add any vendors you trust here
TRUSTED_PUBLISHERS = {
    "Microsoft Windows",
    "Microsoft Corporation",
    "Microsoft Windows Publisher",
}

def is_signed_by_trusted_publisher(path: str) -> bool:
    """
    Uses PowerShell Get-AuthenticodeSignature to check file signature.
    Returns True if the signer is in TRUSTED_PUBLISHERS.
    """
    if not path or not os.path.exists(path):
        return False

    # Build a PS command that returns JSON
    ps = (
        "powershell -NoProfile -ExecutionPolicy Bypass "
        f"(Get-AuthenticodeSignature -FilePath {shlex.quote(path)} | "
        "Select-Object Status, @{n='Signer';e={$_.SignerCertificate.Subject}} | "
        "ConvertTo-Json -Depth 3)"
    )

    try:
        proc = subprocess.run(ps, capture_output=True, text=True)
        if proc.returncode != 0 or not proc.stdout.strip():
            return False

        data = json.loads(proc.stdout)

        # Normalize to dict
        if isinstance(data, list) and data:
            data = data[0]

        status = (data.get("Status") or "").lower()
        signer = (data.get("Signer") or "")
        # Subject strings look like: "CN=Microsoft Windows, O=Microsoft Corporation, L=..., C=US"
        # So we match if any trusted name is contained.
        if status == "valid" and any(vendor.lower() in signer.lower() for vendor in TRUSTED_PUBLISHERS):
            return True
    except Exception:
        return False

    return False
