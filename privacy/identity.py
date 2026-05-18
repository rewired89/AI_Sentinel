"""
Cryptographic identity for AI Sentinel Privacy.
Your identity is an Ed25519 keypair — no name, email, or phone number ever stored.
The public key (hex) is your "Sentinel Address".
"""
import json
import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)

IDENTITY_DIR = Path(__file__).parent.parent / "data" / "identity"
IDENTITY_FILE = IDENTITY_DIR / "sentinel_identity.json"


def load_or_create() -> dict:
    """
    Return the stored identity or generate a fresh Ed25519 keypair.
    Returned dict has keys: address, private_key_pem, created_at
    """
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)

    if IDENTITY_FILE.exists():
        data = json.loads(IDENTITY_FILE.read_text())
        print(f"[identity] Sentinel Address: {data['address']}")
        return data

    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    private_pem   = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    public_raw    = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    address       = public_raw.hex()

    data = {
        "address":         address,
        "private_key_pem": private_pem,
        "created_at":      datetime.datetime.utcnow().isoformat() + "Z",
    }
    IDENTITY_FILE.write_text(json.dumps(data, indent=2))

    print(f"[identity] New Sentinel Address: {address}")
    print(f"[identity] Stored at: {IDENTITY_FILE}")
    return data


def get_address() -> str:
    """Return the public-key hex that serves as your anonymous address."""
    return load_or_create()["address"]
