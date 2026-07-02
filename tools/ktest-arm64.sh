#!/usr/bin/env bash
# Aegis arm64 kernel smoke test — the aarch64 twin of tools/ktest.sh.
# Boots the UEFI/Limine ISO on QEMU virt; success = the kernel runs all
# the way to init-spawn and panics "no init found" (no rootfs on this ISO).
set -u
ISO="${1:?usage: ktest-arm64.sh <aegis-arm64.iso>}"
LOG="$(mktemp)"
FW=""
for f in /usr/share/AAVMF/AAVMF_CODE.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd; do
    [ -f "$f" ] && FW="$f" && break
done
[ -n "$FW" ] || { echo "[ktest-arm64] FAIL: no AAVMF/QEMU_EFI firmware found"; exit 1; }

timeout 120 qemu-system-aarch64 -M virt,gic-version=3 -cpu cortex-a72 -m 2048M \
    -bios "$FW" \
    -cdrom "$ISO" \
    -display none -nodefaults -serial stdio -no-reboot \
    > "$LOG" 2>&1 || true

if grep -q "no init at" "$LOG"; then
    echo "[ktest-arm64] PASS: kernel reached init-spawn with no userland"
    rm -f "$LOG"
    exit 0
fi

echo "[ktest-arm64] FAIL: kernel did not reach init-spawn"
echo "----- last 40 serial lines -----"
tail -40 "$LOG"
rm -f "$LOG"
exit 1
