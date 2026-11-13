#!/bin/sh
# test-fdt.sh — host unit check for the arm64 FDT reader (kernel/arch/arm64/fdt.c).
#
# Dumps QEMU's own aarch64 'virt' device tree and asserts the parser
# extracts the GIC / ECAM bases from it. Independent of the kernel boot
# (the Limine+edk2 path presents ACPI, so the parser can't be verified
# through a boot). Exits non-zero on any failure.
set -eu

WORK=$(mktemp -d "${TMPDIR:-/tmp}/aegis-fdt.XXXXXXXX")
trap 'rm -rf "$WORK"' EXIT
DTB="$WORK/virt.dtb"
BIN="$WORK/fdt-test"

qemu-system-aarch64 -nodefaults -display none \
    -M virt,gic-version=3 -cpu cortex-a72 -smp 4 \
    -machine dumpdtb="$DTB" >/dev/null 2>&1

cc -O2 -Wall -Wextra -DFDT_HOSTTEST -Ikernel/arch/arm64 \
    test/fdt_test.c kernel/arch/arm64/fdt.c -o "$BIN"

"$BIN" "$DTB"

# Crafted-blob regression (audit 2026-08-01 A3-I1): an FDT_PROP whose length is
# chosen so `val + len` and the +3 round-up both wrap uint32 — the bound test
# passed because it overflowed too, and `off` failed to advance. The walker then
# handed that ~4 GiB length to compat_list_has, which is an out-of-range read
# (SIGBUS, reproduced). The parser must now reject the property and return.
EVIL="$WORK/fdt-crafted"
cc -O2 -w -DFDT_HOSTTEST -Ikernel/arch/arm64 \
    test/fdt_crafted_test.c kernel/arch/arm64/fdt.c -o "$EVIL"
if "$EVIL"; then
    echo "FDT-CRAFTED PASS"
else
    echo "FDT-CRAFTED FAIL (rc=$?) — crafted length not rejected"
    exit 1
fi

python3 -B test/fdt_root_test.py
