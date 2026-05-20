#!/usr/bin/env bash
# AI Sentinel — macOS install script
# Run once: bash install.sh

set -e
cd "$(dirname "$0")"

echo ""
echo "  ============================================================"
echo "   AI SENTINEL — macOS Setup"
echo "  ============================================================"
echo ""

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "  ERROR: python3 not found."
    echo "  Install it from https://www.python.org or via Homebrew: brew install python"
    exit 1
fi

# Check pip
if ! python3 -m pip --version &>/dev/null; then
    echo "  ERROR: pip not found. Run: python3 -m ensurepip"
    exit 1
fi

# Install dependencies
echo "  Installing dependencies..."
python3 -m pip install -r requirements.txt

echo ""
echo "  Running first-time setup (autostart + security note)..."
python3 -m privacy.privacy_main --setup

echo ""
echo "  ============================================================"
echo "   Done!"
echo "   AI Sentinel will start at next login."
echo "   To start now: bash start.sh"
echo "   Look for the shield icon in your menu bar (top-right)."
echo "  ============================================================"
echo ""
