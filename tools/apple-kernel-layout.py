#!/usr/bin/env python3
"""Package the linked real kernel, including its BSS, in an owned RAM span."""
from pathlib import Path
import subprocess
import sys

build = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("build/applekernel")
elf = build / "kernel/aegis-arm64.elf"
syms = {}
for line in subprocess.check_output(["aarch64-linux-gnu-nm", str(elf)], text=True).splitlines():
    parts = line.split()
    if len(parts) == 3:
        syms[parts[2]] = int(parts[0], 16)
base = syms["apple_kernel_base"]
size = syms["_kernel_end"] - base
assert base == 0xffffffff80200000 and 0 < size < 0x1000000 and size % 4096 == 0
subprocess.run(["aarch64-linux-gnu-objcopy", "-O", "binary", str(elf),
                str(build / "kernel.raw")], check=True)
raw = (build / "kernel.raw").read_bytes()
assert len(raw) <= size
values = {
    "KERNEL_BASE": base, "KERNEL_SIZE": size,
    "KERNEL_ENTRY": syms["apple_kernel_start"],
    "KERNEL_TEXT_SIZE": syms["apple_kernel_text_end"] - base,
    "KERNEL_RO_SIZE": syms["apple_kernel_ro_end"] - base,
}
for path, data in (
    (build / "kernel.bin", raw + bytes(size - len(raw))),
    (build / "kernel_layout.h", "".join(
        f"#define {key} 0x{value:x}ULL\n" for key, value in values.items()).encode() +
        f'#define KERNEL_BINARY_PATH "{build / "kernel.bin"}"\n'.encode()),
):
    if not path.exists() or path.read_bytes() != data:
        path.write_bytes(data)
