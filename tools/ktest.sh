#!/usr/bin/env bash
# Aegis kernel smoke test.
#
# Boots the kernel-only ISO (no rootfs, no userland) in QEMU headless. With no
# init binary on any root filesystem the kernel must run all the way through
# bring-up to init-spawn and panic "[INIT] no init found on root filesystem".
# Seeing that line proves the kernel boots end-to-end (PMM/VMM/SMP/sched/VFS all
# came up) with zero embedded userland — exactly the Linux "No init found" path.
set -u
ISO="${1:?usage: ktest.sh <kernel.iso>}"
LOG="$(mktemp)"

timeout 30 qemu-system-x86_64 -machine pc -cdrom "$ISO" -boot order=d \
    -display none -vga std -nodefaults -serial stdio -no-reboot -m 2048M \
    > "$LOG" 2>&1 || true

if grep -q "no init at" "$LOG"; then
    echo "[ktest] PASS: kernel reached init-spawn with no userland"
    rm -f "$LOG"
    exit 0
fi

echo "[ktest] FAIL: kernel did not reach init-spawn"
echo "----- last 40 serial lines -----"
tail -40 "$LOG"
rm -f "$LOG"
exit 1
