#!/usr/bin/env bash
# AI Sentinel — macOS / Linux setup
# Run once: bash install.sh

set -e
cd "$(dirname "$0")"

echo ""
echo "  ============================================================"
echo "   AI SENTINEL — Setup"
echo "  ============================================================"
echo ""

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "  ERROR: python3 not found."
    echo "  macOS:  brew install python   or   https://python.org"
    echo "  Linux:  sudo apt install python3 python3-pip"
    exit 1
fi

# Install dependencies
echo "  Installing packages..."
python3 -m pip install -r requirements.txt --quiet
echo "  Packages ready."
echo ""

# Launch — auto-setup (LaunchAgent autostart + Gatekeeper fix) runs
# automatically on first launch inside privacy_main.py
echo "  Starting AI Sentinel..."
echo "  On first launch, autostart and security settings are configured"
echo "  automatically. You do not need to do anything else."
echo ""

python3 -m privacy.privacy_main &

echo "  ============================================================"
echo ""
if [[ "$(uname)" == "Darwin" ]]; then
    echo "   Look for the shield icon in the menu bar (top-right)."
else
    echo "   Look for the shield icon in the system tray."
fi
echo ""
echo "   GREEN = full protection    AMBER = starting up    RED = threat"
echo ""
echo "  ============================================================"
echo ""
