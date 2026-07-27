#!/usr/bin/env bash
# Aegis microVM userspace test.
#
# Boots the microVM kernel (PVH direct boot — no bootloader) in QEMU's `microvm`
# machine with NO ACPI and NO PCI, mounting a virtio-blk-device disk over the
# virtio-mmio transport as the ext2 root. The freestanding test-init (packed as
# /bin/vigil) runs in ring 3 and prints "[KTEST]" result lines; a full pass ends
# with "[KTEST] DONE all-pass". Seeing that proves a complete userland — procs,
# fork/COW, signals, exec, mmap, capability enforcement, filesystem — running in
# a microVM the way Firecracker boots one: raw ELF, virtio-mmio, no legacy PC.
set -u
ELF="${1:?usage: captest-microvm.sh <aegis.elf> <rootfs.img>}"
IMG="${2:?usage: captest-microvm.sh <aegis.elf> <rootfs.img>}"
LOG="$(mktemp)"

# -machine microvm: PVH boot + virtio-mmio, no PCI. force-legacy=false selects
# the modern (v2) mmio transport. No acpi=on — the kernel runs ACPI-less.
timeout 40 qemu-system-x86_64 -machine microvm \
    -global virtio-mmio.force-legacy=false \
    -kernel "$ELF" -append "boot=text" \
    -drive id=root,file="$IMG",format=raw,if=none \
    -device virtio-blk-device,drive=root \
    -display none -nodefaults -serial stdio -no-reboot -m 512M \
    > "$LOG" 2>&1 || true

fails=$(grep -c "\[KTEST\] FAIL" "$LOG" || true)
if grep -q "\[KTEST\] DONE all-pass" "$LOG" && [ "$fails" = 0 ]; then
    echo "[captest-microvm] PASS: full userspace in a microVM (PVH, no ACPI/PCI, virtio-mmio)"
    grep "\[KTEST\]" "$LOG" | sed 's/^/  /'
    rm -f "$LOG"
    exit 0
fi

echo "[captest-microvm] FAIL: microVM did not reach a clean userspace all-pass"
echo "----- [KTEST] + boot lines, last 30 serial lines -----"
grep -iE "\[KTEST\]|VMMIO|EXT2|BLK\]|ACPI|PCIE|panic" "$LOG" | sed 's/^/  /'
tail -30 "$LOG"
rm -f "$LOG"
exit 1
