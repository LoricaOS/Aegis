#!/usr/bin/env bash
# Aegis arm64 capability/syscall test — the aarch64 twin of tools/captest.sh.
# Boots the test ISO (kernel + minimal rootfs with the aarch64 test-init as
# /bin/vigil) and checks the capability model holds at the syscall boundary.
set -u
ISO="${1:?usage: captest-arm64.sh <aegis-arm64-test.iso>}"
LOG="$(mktemp)"
FW=""
for f in /usr/share/AAVMF/AAVMF_CODE.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd; do
    [ -f "$f" ] && FW="$f" && break
done
[ -n "$FW" ] || { echo "[captest-arm64] FAIL: no AAVMF/QEMU_EFI firmware found"; exit 1; }

timeout 150 qemu-system-aarch64 -M virt,gic-version=3 -cpu cortex-a72 -smp 4 -m 2048M \
    -bios "$FW" \
    -cdrom "$ISO" \
    -display none -nodefaults -serial stdio -no-reboot \
    > "$LOG" 2>&1 || true

fails=$(grep -c "\[KTEST\] FAIL" "$LOG" || true)
if grep -q "\[KTEST\] DONE all-pass" "$LOG" && [ "$fails" = 0 ]; then
    echo "[captest-arm64] PASS: kernel booted test-init; capability model enforced"
    grep "\[KTEST\]" "$LOG" | sed 's/^/  /'
    rm -f "$LOG"
    exit 0
fi

echo "[captest-arm64] FAIL: test-init did not all-pass (FAIL lines: $fails)"
echo "----- [KTEST] lines + last 30 serial lines -----"
grep "\[KTEST\]" "$LOG" | sed 's/^/  /'
tail -30 "$LOG"
rm -f "$LOG"
exit 1
