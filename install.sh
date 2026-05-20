#!/usr/bin/env bash
# AI Sentinel — macOS / Linux install script
# Run once: bash install.sh

set -e
cd "$(dirname "$0")"

echo ""
echo "  ============================================================"
echo "   AI SENTINEL — Setup"
echo "  ============================================================"
echo ""

# ---------------------------------------------------------------------------
# Step 1 — Python check
# ---------------------------------------------------------------------------
if ! command -v python3 &>/dev/null; then
    echo "  ERROR: python3 not found."
    echo ""
    echo "  macOS:  brew install python   OR   download from https://python.org"
    echo "  Linux:  sudo apt install python3 python3-pip"
    exit 1
fi

PYTHON=$(command -v python3)
echo "  [1/5] Python found: $($PYTHON --version)"

# ---------------------------------------------------------------------------
# Step 2 — Install dependencies
# ---------------------------------------------------------------------------
echo "  [2/5] Installing packages (may take 2-5 min on first run)..."
$PYTHON -m pip install -r requirements.txt --quiet
echo "  [2/5] Packages ready."
echo ""

# ---------------------------------------------------------------------------
# Step 3 — macOS: pre-clear Gatekeeper quarantine on i2pd
#           i2pd is an unsigned binary. macOS stamps downloaded files with a
#           quarantine attribute that triggers the "unidentified developer"
#           popup. We remove it as soon as the binary is downloaded so the
#           user never sees the warning.
# ---------------------------------------------------------------------------
if [[ "$(uname)" == "Darwin" ]]; then
    echo "  [3/5] Preparing for macOS security (Gatekeeper)..."
    mkdir -p data/i2p
    # Hook: after i2pd downloads we strip the quarantine bit automatically.
    # The actual download happens on first start; this creates a wrapper that
    # strips the attribute right after download completes.
    cat > data/i2p/.post_download_hook.sh << 'HOOK'
#!/usr/bin/env bash
# Called by i2p_client.py after binary is installed on macOS
if [[ -f "$(dirname "$0")/i2pd" ]]; then
    xattr -d com.apple.quarantine "$(dirname "$0")/i2pd" 2>/dev/null || true
    echo "[i2p] Gatekeeper quarantine attribute removed."
fi
HOOK
    chmod +x data/i2p/.post_download_hook.sh
    echo "  [3/5] Gatekeeper hook ready (quarantine will be stripped automatically)."
else
    echo "  [3/5] Skipped (Gatekeeper only applies to macOS)."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4 — Register autostart
# ---------------------------------------------------------------------------
echo "  [4/5] Registering autostart at login..."
$PYTHON -m privacy.privacy_main --setup
echo ""

# ---------------------------------------------------------------------------
# Step 5 — Launch AI Sentinel
# ---------------------------------------------------------------------------
echo "  [5/5] Starting AI Sentinel..."
$PYTHON -m privacy.privacy_main &
SENTINEL_PID=$!

echo ""
echo "  ============================================================"
echo ""
echo "   AI Sentinel is running (PID $SENTINEL_PID)."
if [[ "$(uname)" == "Darwin" ]]; then
    echo "   Look for the shield icon in the menu bar (top-right)."
else
    echo "   Look for the shield icon in your system tray."
fi
echo ""
echo "   GREEN shield  = Full protection (I2P + scanning)"
echo "   AMBER shield  = Scanning only (I2P is still connecting)"
echo "   RED shield    = Threat detected"
echo ""
echo "   If the shield stays AMBER after 5 minutes on macOS:"
echo "     System Settings → Privacy & Security → Allow Anyway (for i2pd)"
echo "   Then restart: bash start.sh"
echo ""
echo "  ============================================================"
echo ""
