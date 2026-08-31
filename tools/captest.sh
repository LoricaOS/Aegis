#!/usr/bin/env bash
# Aegis kernel capability/syscall test.
#
# Boots the test ISO (kernel + a minimal rootfs whose /bin/vigil is the
# freestanding test-init). The init prints "[KTEST]" result lines to serial.
# Pass = it reaches "[KTEST] DONE all-pass" and no "[KTEST] FAIL" appears —
# proving the kernel boots a user process and enforces the capability model
# (a POWER-gated syscall is denied to baseline-cap pid 1).
set -u
ISO="${1:?usage: captest.sh <aegis-test.iso>}"
LOG="$(mktemp)"

timeout 40 qemu-system-x86_64 -machine pc -smp 4 -cdrom "$ISO" -boot order=d \
    -display none -vga std -nodefaults -serial stdio -no-reboot -m 2048M \
    -device virtio-net-pci -device virtio-rng-pci -device virtio-gpu-pci \
    > "$LOG" 2>&1 || true

fails=$(grep -c "\[KTEST\] FAIL" "$LOG" || true)

# The service-tier laundering guards must be OBSERVED firing, not merely not
# crashing. test/exectest.caps declares `service DISK_ADMIN ADMIN_AUTH`; both are
# admin-gated, so cap_policy must refuse both and say so. Without this assertion
# a regression that silently granted them would still show all-pass, because the
# only in-guest evidence is a kernel log line.
guards=0
grep -q "refusing service-tier DISK_ADMIN for /bin/exectest" "$LOG" && guards=$((guards+1))
grep -q "refusing service-tier ADMIN_AUTH for /bin/exectest" "$LOG" && guards=$((guards+1))
if [ "$guards" != 2 ]; then
    echo "[captest] FAIL: service-tier laundering guards did not fire ($guards/2)"
    grep -a "CAP_POLICY" "$LOG" | sed 's/^/  /'
    exit 1
fi

if grep -q "\[KTEST\] DONE all-pass" "$LOG" &&
   grep -q "\[NET6\] OK" "$LOG" && [ "$fails" = 0 ]; then
    echo "[captest] PASS: kernel booted test-init; capability model enforced"
    grep "\[KTEST\]" "$LOG" | sed 's/^/  /'
    rm -f "$LOG"
    exit 0
fi

echo "[captest] FAIL: test-init did not all-pass (FAIL lines: $fails)"
echo "----- [KTEST] lines + last 30 serial lines -----"
grep "\[KTEST\]" "$LOG" | sed 's/^/  /'
tail -30 "$LOG"
rm -f "$LOG"
exit 1
