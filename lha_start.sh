#!/bin/bash
#
# lha_start.sh — Clean, build, load all modules, and start logging.
#
# Idempotent: safe to run regardless of current machine state (0, partial,
# or all modules loaded). It will tear everything down first, rebuild from
# source, then bring the full pipeline up.
#
# After running, any file operation is captured and logged as NDJSON to
# /var/log/lha/YYYY-MM-DD.log.
#
# Usage: sudo bash lha_start.sh [project_dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${1:-$SCRIPT_DIR}"
KMOD_DIR="$PROJECT_DIR/kmod"
USERSPACE_DIR="$PROJECT_DIR/userspace"
LOG_DIR="/var/log/lha"

# Load order; unload is always reversed.
MODULES=(
    lha_centos9_resolver
    lha_centos9_avc_capture
    lha_centos9_event_channel
    lha_centos9_capture
)

# ================================================================
# Step 1: Stop lha-eventd (releases /dev device so rmmod can work)
# ================================================================
echo "=== Step 1: Stop lha-eventd ==="
if pkill -f lha-eventd 2>/dev/null; then
    sleep 1
    echo "[+] lha-eventd stopped"
else
    echo "[*] lha-eventd not running"
fi

# ================================================================
# Step 2: Unload all modules (reverse order)
# ================================================================
echo ""
echo "=== Step 2: Unload all modules ==="
for ((i=${#MODULES[@]}-1; i>=0; i--)); do
    mod="${MODULES[$i]}"
    if lsmod | grep -q "^${mod} "; then
        echo "[*] Removing $mod"
        rmmod "$mod" || { echo "[-] Failed to remove $mod"; exit 1; }
    fi
done
# Also remove injector if loaded
if lsmod | grep -q "^lha_centos9_injector "; then
    echo "[*] Removing lha_centos9_injector"
    rmmod lha_centos9_injector || true
fi
echo "[+] All modules unloaded"

# ================================================================
# Step 3: Build everything
# ================================================================
echo ""
echo "=== Step 3: Build kernel modules ==="
make -C "$KMOD_DIR" clean
make -C "$KMOD_DIR"
echo "[+] Kernel modules built"

echo ""
echo "=== Step 4: Build userspace ==="
make -C "$USERSPACE_DIR" clean
make -C "$USERSPACE_DIR"
echo "[+] lha-eventd built"

# ================================================================
# Step 5: Load modules
# ================================================================
echo ""
echo "=== Step 5: Load modules ==="
for mod in "${MODULES[@]}"; do
    echo "[*] Loading $mod"
    insmod "$KMOD_DIR/${mod}.ko"
done
echo "[+] All modules loaded"
lsmod | grep lha

# ================================================================
# Step 6: Start lha-eventd
# ================================================================
echo ""
echo "=== Step 6: Start lha-eventd ==="
mkdir -p "$LOG_DIR"
nohup "$USERSPACE_DIR/lha-eventd" > /dev/null 2>&1 &
sleep 1

if pgrep -f lha-eventd > /dev/null 2>&1; then
    echo "[+] lha-eventd running"
else
    echo "[-] lha-eventd failed to start"
    exit 1
fi

# ================================================================
# Done
# ================================================================
echo ""
echo "============================================"
echo "  Ready. All file operations are captured."
echo "  View logs:"
echo "    tail -f $LOG_DIR/$(date +%Y-%m-%d).log"
echo "============================================"
