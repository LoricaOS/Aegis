#!/usr/bin/env bash
# Aegis arm64 virtio-blk boot gate. Boots the kernel-only ISO (no rootfs
# module) with an ext2 disk attached as virtio-blk-pci; the kernel must
# enumerate PCIe, bind virtio-blk, and mount + exec init from the disk.
# Pass = the capability test-init reaches "[KTEST] DONE all-pass".
set -u
ISO="${1:?usage: vblktest-arm64.sh <aegis-arm64.iso> <disk.img>}"
DISK="${2:?usage: vblktest-arm64.sh <aegis-arm64.iso> <disk.img>}"
LOG="$(mktemp)"
FW=""
for f in /usr/share/AAVMF/AAVMF_CODE.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd; do
    [ -f "$f" ] && FW="$f" && break
done
[ -n "$FW" ] || { echo "[vblktest-arm64] FAIL: no AAVMF firmware"; exit 1; }

timeout 120 qemu-system-aarch64 -M virt,gic-version=3 -cpu cortex-a72 -m 2048M \
    -bios "$FW" -cdrom "$ISO" \
    -drive file="$DISK",if=none,id=d0,format=raw \
    -device virtio-blk-pci,drive=d0 \
    -display none -nodefaults -serial stdio -no-reboot \
    > "$LOG" 2>&1 || true

fails=$(grep -c "\[KTEST\] FAIL" "$LOG" || true)
if grep -q "\[KTEST\] DONE all-pass" "$LOG" && [ "$fails" = 0 ] \
   && grep -q "mounted vblk0" "$LOG"; then
    echo "[vblktest-arm64] PASS: mounted rootfs from virtio-blk and ran init"
    grep -aE "\[PCIE\]|\[BLK\]|\[EXT2\] OK|\[KTEST\]" "$LOG" | sed 's/^/  /'
    rm -f "$LOG"; exit 0
fi

echo "[vblktest-arm64] FAIL: did not mount+run from virtio-blk (FAIL lines: $fails)"
echo "----- last 30 serial lines -----"
tail -30 "$LOG"
rm -f "$LOG"; exit 1
