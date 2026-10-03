#!/bin/bash
# NetProbe launcher for macOS / Linux
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
    exec python3 netprobe.py "$@"
elif command -v python >/dev/null 2>&1; then
    exec python netprobe.py "$@"
else
    echo "[NetProbe] Python 3 not found. Install with: brew install python3"
    exit 1
fi
