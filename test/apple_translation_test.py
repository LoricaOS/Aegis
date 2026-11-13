#!/usr/bin/env python3
"""Execute V3's real EL1/MMU transition, including high physical RAM."""
import argparse
from pathlib import Path
import struct

from apple_probe_test import run_case

PAGE, MASK = 4096, 0x0000fffffffff000
RO, PXN, UXN = 1 << 7, 1 << 53, 1 << 54


def check_case(build, image, el2, fault=0, high=False, fmt="x2r10g10b10",
               native_geometry=False, preview=None):
    dtb = 0x10003000000 if high else 0x43000000
    arena = 0x10004000000 if high else 0x44000000
    fb = arena + 64
    width, height, stride = (3024, 1890, 12096) if native_geometry else (320, 160, 1280)
    size = height * stride

    def check(command, tmp, syms, report, text):
        def read(address, count, name):
            command("pmemsave", val=address, size=count, filename=str(tmp / name))
            return (tmp / name).read_bytes()

        t = struct.unpack("<18Q", read(
            image + syms["apple_probe_translation_report"], 18 * 8, "translation"))
        incoming, current, hcr, before, after, root, tcr, mair, tables, pages = t[:10]
        cr, cw, dw, dr, dtw, fw, zr, success = t[10:]
        assert incoming == (2 if el2 else 1) and current == 1, t
        assert before & 5 == 0 and after & 0x1005 == 1, t
        assert root == image + syms["pool"] and 0 < tables <= 48, t
        assert tcr & 63 == 16 and (tcr >> 14) & 3 == 0 and tcr & (1 << 23)
        assert (tcr >> 32) & 7 == report[3] & 15 and mair == 0x44
        assert success == 1, t
        for par, address in ((cr, image), (dw, root), (dr, dtb), (fw, fb)):
            assert not par & 1 and par & MASK == address & MASK, t
        assert cw & 1 and dtw & 1 and zr & 1, t
        assert "PASS - EL1 / 4K / RO CODE AND DTB\n" in text
        assert "HALTED - MMU ON / CACHES OFF / DAIF MASKED\n" in text

        # Independently walk actual guest tables: no extra RAM, no EL0 access,
        # no writable executable pages, and exact identity/attribute coverage.
        raw = read(root, 48 * PAGE, "page-tables")
        entries = struct.unpack("<" + "Q" * (48 * 512), raw)
        leaves, seen = {}, set()

        def walk(index, level, prefix):
            assert index < tables and index not in seen
            seen.add(index)
            for i in range(512):
                d = entries[index * 512 + i]
                if not d:
                    continue
                assert d & 3 == 3
                va = prefix | (i << (39 - level * 9))
                if level < 3:
                    child = d & MASK
                    assert child >= root
                    walk((child - root) // PAGE, level + 1, va)
                else:
                    assert d & MASK == va
                    leaves[va] = d & ~MASK

        walk(0, 0, 0)
        expected = {}
        normal = (1 << 10) | (3 << 8) | UXN
        device = (1 << 10) | (2 << 8) | (1 << 2) | PXN | UXN
        for start, end, attrs in (
            (image, image + syms["apple_probe_text_end"], normal | RO),
            (image + syms["apple_probe_text_end"], image + syms["apple_probe_ro_end"], normal | RO | PXN),
            (image + syms["apple_probe_ro_end"], image + syms["apple_probe_end"], normal | PXN),
            (dtb, dtb + report[7], normal | RO | PXN),
            (fb, fb + size, device),
        ):
            for address in range(start & -PAGE, (end + PAGE - 1) & -PAGE, PAGE):
                expected[address] = attrs | 3
        assert leaves == expected and len(leaves) == pages and len(seen) == tables
        assert 0 not in leaves

        if fault:
            captured = struct.unpack("<9Q", read(
                image + syms["apple_probe_fault_report"], 72, "fatal"))
            valid, vector, el, esr, elr, far, spsr, sp, boot_stage = captured
            assert valid == 1 and vector == 4 and el == 1 and boot_stage == 8, captured
            assert spsr & 0xf == 5 and spsr & 0xc0 == 0xc0
            assert image + syms["apple_probe_stack_bottom"] <= sp < image + syms["apple_probe_end"]
            if fault == 1:
                assert esr >> 26 == 0x25 and (esr & 63) in (4, 5, 6, 7)
                assert far == 0 and elr == image + syms["apple_probe_translation_fault"], captured
            else:
                assert esr >> 26 == 0x21 and (esr & 63) == 15
                assert far == root and elr == root, captured
            assert "AEGIS FATAL EXCEPTION\n" in text
        else:
            assert "FATAL EXCEPTION" not in text

    run_case(image, build=build, el2=el2, version=3, stage=255 if fault else 8,
             post_check=check, dtb_address=dtb, arena_address=arena, sparse_high_ram=high,
             fmt=fmt, width=width, height=height, stride=stride, size=size,
             preview=preview)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normal", type=Path, required=True)
    parser.add_argument("--unmapped", type=Path, required=True)
    parser.add_argument("--nx", type=Path, required=True)
    args = parser.parse_args()
    normal, unmapped, nx = args.normal.resolve(), args.unmapped.resolve(), args.nx.resolve()
    image = (normal / "Image").read_bytes()
    assert struct.unpack_from("<Q", image, 24)[0] == 2  # 4 KiB Image header
    for el2 in (False, True):
        check_case(normal, 0x40200000, el2)
        check_case(normal, 0x41200000, el2, fmt="x8r8g8b8")
        check_case(unmapped, 0x41200000, el2, fault=1)
        check_case(nx, 0x41200000, el2, fault=2)
    check_case(normal, 0x10000200000, True, high=True, native_geometry=True,
               preview=normal / "translation-preview.png")
    check_case(unmapped, 0x10000200000, True, fault=1, high=True)
    check_case(nx, 0x10000200000, True, fault=2, high=True)
