#!/bin/bash
#
# lha_capture_test.sh — one-click test for the full LSM hook capture pipeline
#
# Usage: bash lha_capture_test.sh [project_dir]
#   project_dir defaults to the directory containing this script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${1:-$SCRIPT_DIR}"
KMOD_DIR="$PROJECT_DIR/kmod"
USERSPACE_DIR="$PROJECT_DIR/userspace"
LOG_DIR="/var/log/lha"
EVENTD_PID=""

# Ordered module list (load order)
MODULES=(
    lha_centos9_resolver
    lha_centos9_avc_capture
    lha_centos9_event_channel
    lha_centos9_capture
)

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    # Stop lha-eventd
    if [ -n "$EVENTD_PID" ] && kill -0 "$EVENTD_PID" 2>/dev/null; then
        echo "[*] Stopping lha-eventd (pid $EVENTD_PID)"
        kill "$EVENTD_PID" 2>/dev/null || true
        wait "$EVENTD_PID" 2>/dev/null || true
    fi

    # Unload modules in reverse order
    for ((i=${#MODULES[@]}-1; i>=0; i--)); do
        mod="${MODULES[$i]}"
        if lsmod | grep -q "^${mod}"; then
            echo "[*] Unloading $mod"
            rmmod "$mod" 2>/dev/null || true
        fi
    done

    echo "[+] Cleanup done"
}

trap cleanup EXIT

# ---- Step 1: Build ----
echo "=== Step 1: Build kernel modules ==="
cd "$KMOD_DIR"
make clean
make
echo "[+] Kernel modules built"

echo ""
echo "=== Step 2: Build userspace ==="
cd "$USERSPACE_DIR"
make clean
make
echo "[+] lha-eventd built"

# ---- Step 3: Unload stale modules if any ----
echo ""
echo "=== Step 3: Unload stale modules ==="
for ((i=${#MODULES[@]}-1; i>=0; i--)); do
    mod="${MODULES[$i]}"
    if lsmod | grep -q "^${mod}"; then
        echo "[*] Removing leftover $mod"
        rmmod "$mod" 2>/dev/null || true
    fi
done
echo "[+] Clean slate"

# ---- Step 4: Load modules ----
echo ""
echo "=== Step 4: Load modules ==="
for mod in "${MODULES[@]}"; do
    echo "[*] Loading $mod"
    insmod "$KMOD_DIR/${mod}.ko"
done
echo "[+] All modules loaded"
lsmod | grep lha

# ---- Step 5: Start lha-eventd ----
echo ""
echo "=== Step 5: Start lha-eventd ==="
mkdir -p "$LOG_DIR"
"$USERSPACE_DIR/lha-eventd" &
EVENTD_PID=$!
sleep 1

if ! kill -0 "$EVENTD_PID" 2>/dev/null; then
    echo "[-] lha-eventd failed to start"
    exit 1
fi
echo "[+] lha-eventd running (pid $EVENTD_PID)"

# ---- Step 6: Generate file access events ----
echo ""
echo "=== Step 6: Generate test events ==="

echo "[*] cat /etc/hosts"
cat /etc/hosts > /dev/null

echo "[*] ls /tmp"
ls /tmp > /dev/null

echo "[*] write /tmp/lha_capture_test.txt"
echo "lha capture test $(date)" > /tmp/lha_capture_test.txt

echo "[*] read /tmp/lha_capture_test.txt"
cat /tmp/lha_capture_test.txt > /dev/null

echo "[*] stat /etc/passwd"
stat /etc/passwd > /dev/null

echo "[+] Test events generated, waiting 2s for processing..."
sleep 2

# ---- Step 7: Check results ----
echo ""
echo "=== Step 7: Verify results ==="

TODAY=$(date +%Y-%m-%d)
LOG_FILE="$LOG_DIR/$TODAY.log"

echo ""
echo "--- dmesg (lha_centos9) ---"
dmesg | grep lha_centos9 | tail -20

echo ""
if [ -f "$LOG_FILE" ]; then
    LINE_COUNT=$(wc -l < "$LOG_FILE")
    echo "--- Log file: $LOG_FILE ($LINE_COUNT events) ---"
    echo ""
    echo "First 5 events:"
    head -5 "$LOG_FILE"
    echo ""
    echo "[+] SUCCESS: Pipeline is working end-to-end!"
else
    echo "[-] FAIL: Log file $LOG_FILE not found"
    echo "    Check dmesg for errors"
    exit 1
fi

# ---- Step 8: Show event channel stats ----
echo ""
echo "=== Event channel stats ==="
SYSFS="/sys/devices/virtual/misc/lha_centos9_event_stream"
if [ -d "$SYSFS" ]; then
    echo "  submitted_total: $(cat $SYSFS/submitted_total)"
    echo "  dropped_total:   $(cat $SYSFS/dropped_total)"
    echo "  queue_depth:     $(cat $SYSFS/queue_depth)"
    echo "  reader_attached: $(cat $SYSFS/reader_attached)"
fi

echo ""
echo "=== Test complete ==="
echo "Full log at: $LOG_FILE"
