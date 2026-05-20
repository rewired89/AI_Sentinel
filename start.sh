#!/usr/bin/env bash
# AI Sentinel — macOS/Linux launcher
# Run: bash start.sh

cd "$(dirname "$0")"
python3 -m privacy.privacy_main "$@"
