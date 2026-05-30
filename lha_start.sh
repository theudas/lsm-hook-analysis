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
# Step 2: Unload all lha modules
# ================================================================
echo ""
echo "=== Step 2: Unload all modules ==="

# Repeatedly scan and remove lha_centos9_* modules with 0 refcount until
# none remain. This handles arbitrary dependency order without hardcoding.
MAX_ROUNDS=10
for ((round=1; round<=MAX_ROUNDS; round++)); do
    # Collect all loaded lha_centos9_* modules
    loaded=()
    while IFS=' ' read -r name _ refcnt deps _rest; do
        loaded+=("$name")
    done < <(lsmod | grep "^lha_centos9_" || true)

    [ ${#loaded[@]} -eq 0 ] && break

    removed_any=false
    for mod in "${loaded[@]}"; do
        # Try to remove; rmmod will fail if still depended on, that's fine
        if rmmod "$mod" 2>/dev/null; then
            echo "[*] Removed $mod"
            removed_any=true
        fi
    done

    if ! $removed_any; then
        echo "[-] Stuck: cannot remove remaining modules: ${loaded[*]}"
        echo "    Check 'lsmod | grep lha' for dependencies"
        exit 1
    fi
done

echo "[+] All lha modules unloaded"

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
