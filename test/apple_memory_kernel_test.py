#!/usr/bin/env python3
"""Execute existing PMM/VMM/KVA on an explicit loader-owned pool in QEMU."""
from pathlib import Path
import json
import re
import struct
import subprocess

from apple_probe_test import run_case, check_panel

BUILD = Path("build/applememory/loader").resolve()
KERNEL = Path("build/applememory/kernel/aegis-arm64.elf").resolve()
BASE, DMAP, KVA = 0xffffffff80200000, 0xffff900000000000, 0xffffffff84000000
PAGE, MASK = 4096, 0x0000fffffffff000
WB, DEVICE = 2 << 2, 1 << 2
AF, SH, RO, PXN, UXN = 1 << 10, 3 << 8, 1 << 7, 1 << 53, 1 << 54
for object_path in (BUILD / "kernel_bridge.o",
                    KERNEL.parent / "arch/arm64/apple/kernel_memory.o"):
    disassembly = subprocess.check_output(
        ["aarch64-linux-gnu-objdump", "-d", str(object_path)], text=True)
    assert re.search(r"\bdc\s+civac\b", disassembly)
    assert not re.search(r"\bdc\s+ivac\b", disassembly)
syms = {}
for line in subprocess.check_output(["aarch64-linux-gnu-nm", str(KERNEL)], text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        syms[fields[2]] = int(fields[0], 16)


def case(el2, high=False, pan_cpu=False, native_geometry=False):
    image = 0x10000200000 if high else 0x40200000
    dtb = 0x10003000000 if high else 0x43000000
    fb_arena = 0x10004000000 if high else 0x44000000
    width, height, stride = (3024, 1964, 12096) if native_geometry else (320, 160, 1280)

    def ready(command, tmp, loader):
        physical = image + loader["apple_kernel_blob"]
        command("pmemsave", val=physical + syms["apple_memory_report"] - BASE,
                size=8, filename=str(tmp / "ready"))
        return struct.unpack("<Q", (tmp / "ready").read_bytes())[0] in (5, 255)

    def check(command, tmp, loader, report, text):
        physical = image + loader["apple_kernel_blob"]

        def read(pa, size):
            command("pmemsave", val=pa, size=size, filename=str(tmp / "read"))
            return (tmp / "read").read_bytes()

        def kernel(symbol, size):
            return read(physical + syms[symbol] - BASE, size)

        text = kernel("apple_probe_console_text", 8192).split(b"\0")[0].decode()
        values = struct.unpack("<15Q", kernel("apple_memory_report", 120))
        stage, arena, size, initial, before, after, pa, va, root, empty, checks, mair, tcr, sctlr, daif = values
        assert stage == 5, (values, text, kernel("apple_qr_text", 640).split(b"\0")[0])
        assert size == 8 * 1024 * 1024 and initial == size // PAGE
        assert arena == image + loader["memory_arena"] and arena % PAGE == 0
        assert physical + syms["_kernel_end"] - BASE <= arena
        assert arena + size <= image + loader["apple_probe_end"]
        assert arena <= pa < arena + size and KVA <= va < KVA + 0x200000
        assert arena <= root < arena + size and root != empty
        assert arena <= empty < arena + size
        assert before == after and 0 < after < initial and checks == 31
        assert sctlr & 0x1005 == 5 and daif & 0x3c0 == 0x3c0
        assert mair == 0xff0044
        walks = (1 << 8) | (1 << 10) | (3 << 12) | (1 << 24) | (1 << 26) | (3 << 28)
        mask = (15 << 8) | (3 << 12) | (15 << 24) | (3 << 28)
        assert tcr & mask == walks
        assert read(empty, PAGE) == bytes(PAGE)
        for marker in ("[PMM] OK:", "[VMM] OK:", "[KVA] OK:",
                       "[APPLE] MEMORY CHECKPOINT: existing PMM/VMM/KVA passed\n"):
            assert marker in text, (marker, text)
        assert text.count("[UACCESS] OK:") == 2
        assert not any(marker in text for marker in ("[PANIC]", "[GIC]", "[PCIE]", "[TIMER]"))
        if pan_cpu:
            assert "[PAN] OK:" in text

        # Independently walk all final mappings; no blocks, foreign tables,
        # executable writable aliases, device windows, or identity mappings.
        leaves, tables = {}, set()

        def walk(table, level, prefix):
            assert arena <= table < arena + size and table % PAGE == 0
            assert table not in tables
            tables.add(table)
            for index, entry in enumerate(struct.unpack("<512Q", read(table, PAGE))):
                if not entry:
                    continue
                assert entry & 3 == 3
                address = prefix | (index << (39 - level * 9))
                if level < 3:
                    walk(entry & MASK, level + 1, address)
                else:
                    address |= 0xffff000000000000
                    assert not entry & (1 << 6)
                    assert entry & UXN
                    assert entry & RO or entry & PXN
                    leaves[address] = entry

        walk(root, 0, 0)
        expected = {}

        def add(start, end, physical_start, attrs):
            for address in range(start, end, PAGE):
                expected[address] = physical_start + address - start | attrs | 3

        normal = AF | SH | UXN | WB
        add(BASE, syms["apple_kernel_text_end"], physical, normal | RO)
        add(syms["apple_kernel_text_end"], syms["apple_kernel_ro_end"],
            physical + syms["apple_kernel_text_end"] - BASE, normal | RO | PXN)
        add(syms["apple_kernel_ro_end"], syms["_kernel_end"],
            physical + syms["apple_kernel_ro_end"] - BASE, normal | PXN)
        add(DMAP + arena, DMAP + arena + size, arena, normal | PXN)
        fb_start = fb_arena
        fb_end = (fb_arena + 64 + stride * height + PAGE - 1) & -PAGE
        add(DMAP + fb_start, DMAP + fb_end, fb_start, AF | SH | UXN | PXN | DEVICE)
        origin, = struct.unpack("<Q", kernel("s_bitmap_base", 8))
        assert origin == (arena if arena >= 1 << 32 else 0)
        slots, = struct.unpack("<Q", kernel("s_refcount_pages", 8))
        assert slots == (arena + size - origin) // PAGE
        rc_pages = (slots * 2 + PAGE - 1) // PAGE
        dynamic = {address: entry for address, entry in leaves.items()
                   if KVA <= address < KVA + 0x200000}
        assert len(dynamic) == rc_pages
        assert set(dynamic) == set(range(KVA, KVA + rc_pages * PAGE, PAGE))
        for address, entry in dynamic.items():
            assert arena <= entry & MASK < arena + size
            assert entry & ~MASK == normal | PXN | 3
            expected[address] = entry
        assert leaves == expected, (len(leaves), len(expected), set(leaves) ^ set(expected))

        bitmap = kernel("pmm_boot_bitmap", 128 * 1024)
        managed = range((arena - origin) // PAGE, (arena + size - origin) // PAGE)
        free = sum(not (bitmap[index // 8] & (1 << (index & 7))) for index in managed)
        assert free == after
        occupied = tables | {empty} | {entry & MASK for entry in dynamic.values()}
        assert len(occupied) == initial - after
        for frame in occupied:
            index = (frame - origin) // PAGE
            assert bitmap[index // 8] & (1 << (index & 7))

        qr_text = kernel("apple_qr_text", 640).split(b"\0")[0]
        qr = json.loads(qr_text)
        assert qr["build"] == "mem-qr1" and qr["phase"] == "memory-complete"
        assert tuple(int(qr[key], 16) for key in ("arena", "arena_bytes", "free", "root")) == \
            (arena, size, after, root)
        matrix = kernel("apple_qr_matrix", 1178)
        assert matrix[0] == 97
        gray = bytearray()
        for y in range(420):
            for x in range(420):
                mx, my = x // 4 - 4, y // 4 - 4
                bit = my * 97 + mx
                dark = 0 <= mx < 97 and 0 <= my < 97 and \
                    matrix[1 + bit // 8] & (1 << (bit & 7))
                gray.append(0 if dark else 255)
        pgm = tmp / "qr.pgm"
        pgm.write_bytes(b"P5\n420 420\n255\n" + gray)
        decoded = subprocess.check_output(
            ["zbarimg", "--nodbus", "--quiet", "--raw", str(pgm)]).strip()
        assert decoded == qr_text
        pixels = read(fb_arena, height * stride + 128)
        check_panel(pixels, bytes([0xa5]) * len(pixels), width, height, stride, 0x3fffffff, qr=True)
        if native_geometry:
            x0, y0, w, h = struct.unpack("<4I", kernel("apple_probe_qr_rect", 16))
            assert (x0, y0, w, h) == (1448, 16, 840, 840)
            actual = bytearray()
            for y in range(y0, y0 + h):
                for x in range(x0, x0 + w):
                    value = struct.unpack_from("<I", pixels, 64 + y * stride + x * 4)[0]
                    assert value in (0, 0x3fffffff)
                    actual.append(0 if value == 0 else 255)
            pgm.write_bytes(b"P5\n840 840\n255\n" + actual)
            assert subprocess.check_output(
                ["zbarimg", "--nodbus", "--quiet", "--raw", str(pgm)]).strip() == qr_text
            (BUILD / "memory-qr.json").write_bytes(qr_text + b"\n")
            (BUILD / "memory-qr.pgm").write_bytes(pgm.read_bytes())
            (BUILD / "memory-transcript.txt").write_text(text)
        print(f"MEMORY PASS: high={high}, EL2={el2}, {len(tables)} table pages, "
              f"{after}/{initial} free, exact owned mappings + QR")

    run_case(image, build=BUILD, el2=el2, version=3, stage=8,
             dtb_address=dtb, arena_address=fb_arena, sparse_high_ram=high,
             width=width, height=height, stride=stride, size=height * stride,
             post_check=check, cpu="cortex-a76" if pan_cpu else "cortex-a72",
             ready=ready, bridge=True)


if __name__ == "__main__":
    for el2 in (False, True):
        case(el2)
        case(el2, high=True, native_geometry=el2)
    case(True, pan_cpu=True)
