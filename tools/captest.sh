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

timeout 40 qemu-system-x86_64 -machine pc -cdrom "$ISO" -boot order=d \
    -display none -vga std -nodefaults -serial stdio -no-reboot -m 2048M \
    > "$LOG" 2>&1 || true

fails=$(grep -c "\[KTEST\] FAIL" "$LOG" || true)
if grep -q "\[KTEST\] DONE all-pass" "$LOG" && [ "$fails" = 0 ]; then
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
