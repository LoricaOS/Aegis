#!/usr/bin/env python3
"""
gen-pi5-image.py — flatten an arm64 ELF into a Linux arm64 Image, stamping
the image_size header field. Adapted from the pre-Limine port's
tools/gen-arm64-image.py (aegis-old); used for the native (non-Limine)
Pi 5 boot path, starting with kernel/arch/arm64/native/boot_probe.S.
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

HEADER_SIZE = 64
EXPECTED_CODE0 = 0x14000010
EXPECTED_FLAGS = 0x02
EXPECTED_MAGIC = 0x644D5241


def die(msg: str) -> None:
    sys.stderr.write(f"gen-pi5-image: {msg}\n")
    sys.exit(1)


def round_up(n: int, align: int) -> int:
    return (n + align - 1) & ~(align - 1)


def main() -> int:
    if len(sys.argv) != 3:
        die(f"usage: {sys.argv[0]} <elf> <img>")
    elf, img = Path(sys.argv[1]), Path(sys.argv[2])
    if not elf.exists():
        die(f"{elf} not found")

    img.parent.mkdir(parents=True, exist_ok=True)
    tmp = img.with_suffix(".flat")
    try:
        subprocess.run(
            ["aarch64-linux-gnu-objcopy", "-O", "binary", str(elf), str(tmp)],
            check=True,
        )
    except FileNotFoundError:
        die("aarch64-linux-gnu-objcopy not found")
    except subprocess.CalledProcessError as e:
        die(f"objcopy failed (rc={e.returncode})")

    flat = bytearray(tmp.read_bytes())
    tmp.unlink(missing_ok=True)

    if len(flat) < HEADER_SIZE:
        die(f"flat binary too small ({len(flat)} bytes)")
    code0, _code1, _text_offset, _image_size, flags = struct.unpack_from("<IIQQQ", flat, 0)
    magic, _res5 = struct.unpack_from("<II", flat, 0x38)

    if code0 != EXPECTED_CODE0:
        die(f"code0 mismatch: got 0x{code0:08x}, expected 0x{EXPECTED_CODE0:08x}")
    if magic != EXPECTED_MAGIC:
        die(f"magic mismatch at 0x38: got 0x{magic:08x}, expected 0x{EXPECTED_MAGIC:08x}")
    if flags != EXPECTED_FLAGS:
        die(f"flags mismatch: got 0x{flags:016x}, expected 0x{EXPECTED_FLAGS:016x}")

    eff_size = round_up(len(flat), 2 * 1024 * 1024)
    struct.pack_into("<Q", flat, 0x10, eff_size)
    img.write_bytes(flat)

    print(f"pi5 image: {img}  ({len(flat)} bytes flat, image_size={eff_size})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
