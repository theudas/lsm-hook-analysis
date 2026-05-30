#!/bin/bash
#
# lha_start.sh — Load all LSM hook analysis modules and start logging.
#
# After running this script, any file operation on the system will be
# captured and logged to /var/log/lha/YYYY-MM-DD.log as NDJSON.
#
# Usage: sudo bash lha_start.sh [project_dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${1:-$SCRIPT_DIR}"
KMOD_DIR="$PROJECT_DIR/kmod"
USERSPACE_DIR="$PROJECT_DIR/userspace"
LOG_DIR="/var/log/lha"

MODULES=(
    lha_centos9_resolver
    lha_centos9_avc_capture
    lha_centos9_event_channel
    lha_centos9_capture
)

# ---- Build if .ko not found ----
if [ ! -f "$KMOD_DIR/lha_centos9_capture.ko" ]; then
    echo "[*] Building kernel modules..."
    make -C "$KMOD_DIR"
fi
if [ ! -f "$USERSPACE_DIR/lha-eventd" ]; then
    echo "[*] Building lha-eventd..."
    make -C "$USERSPACE_DIR"
fi

# ---- Load modules ----
for mod in "${MODULES[@]}"; do
    if lsmod | grep -q "^${mod} "; then
        echo "[*] $mod already loaded, skipping"
    else
        echo "[*] Loading $mod"
        insmod "$KMOD_DIR/${mod}.ko"
    fi
done

# ---- Start lha-eventd ----
mkdir -p "$LOG_DIR"

if pgrep -f lha-eventd > /dev/null 2>&1; then
    echo "[*] lha-eventd already running"
else
    echo "[*] Starting lha-eventd"
    nohup "$USERSPACE_DIR/lha-eventd" > /dev/null 2>&1 &
fi

echo ""
echo "Ready. All file operations are now being captured."
echo "View logs:  tail -f $LOG_DIR/$(date +%Y-%m-%d).log"
