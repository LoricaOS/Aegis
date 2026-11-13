#!/usr/bin/env python3
"""Execute the real kernel through the Apple bridge. No target/device access."""
from pathlib import Path
import json
import re
import struct
import subprocess
import tempfile

from apple_probe_test import run_case, check_panel, write_preview, symbols_for

BUILD = Path("build/applekernel/loader").resolve()
KERNEL = Path("build/applekernel/kernel/aegis-arm64.elf").resolve()
BASE = 0xffffffff80200000
# TCG does not establish permission checking for native cache maintenance.
# Guard the actual emitted opcode as well as walking the RO code mappings.
disassembly = subprocess.check_output(
    ["aarch64-linux-gnu-objdump", "-d", str(BUILD / "kernel_bridge.o")], text=True)
assert re.search(r"\bdc\s+civac\b", disassembly)
assert not re.search(r"\bdc\s+ivac\b", disassembly)
syms = {}
for line in subprocess.check_output(["aarch64-linux-gnu-nm", str(KERNEL)], text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        syms[fields[2]] = int(fields[0], 16)


def case(el2, high=False, pan_cpu=False, native_geometry=False, refuse=False, build=BUILD):
    image = 0x10000200000 if high else 0x40200000
    dtb = 0x10003000000 if high else 0x43000000
    arena = 0x10004000000 if high else 0x44000000
    width, height, stride = (3024, 1964, 12096) if native_geometry else (320, 160, 1280)

    def ready(command, tmp, loader):
        # Bootstrap stage 8 precedes the higher-half jump. Do not stop QEMU
        # mid-frame while the real kernel resets/repaints its console.
        physical = image + loader["apple_kernel_blob"]
        command("pmemsave", val=physical + syms["apple_kernel_report"] - BASE,
                size=8, filename=str(tmp / "kernel-ready"))
        return struct.unpack("<Q", (tmp / "kernel-ready").read_bytes())[0] == (3 if refuse else 2)

    def check(command, tmp, loader, report, text):
        physical = image + loader["apple_kernel_blob"]

        def read(pa, count):
            command("pmemsave", val=pa, size=count, filename=str(tmp / "read"))
            return (tmp / "read").read_bytes()

        def kernel(symbol, count):
            return read(physical + syms[symbol] - BASE, count)

        qr_text = kernel("apple_qr_text", 512).split(b"\0")[0]
        qr = json.loads(qr_text)
        assert qr["schema"] == "aegis.apple.qr1" and qr["build"] == "wb-qr2"
        assert qr["phase"] == ("atomic-failed" if refuse else "shared-complete"), qr
        assert int(qr["el"], 16) == 1 and int(qr["sctlr"], 16) & 0x1005 == 5
        matrix = kernel("apple_qr_matrix", 1178)
        assert matrix[0] == 97

        def qr_gray(zoom):
            values = bytearray()
            for y in range(105 * zoom):
                for x in range(105 * zoom):
                    mx, my = x // zoom - 4, y // zoom - 4
                    bit = my * 97 + mx
                    dark = 0 <= mx < 97 and 0 <= my < 97 and \
                        matrix[1 + bit // 8] & (1 << (bit & 7))
                    values.append(0 if dark else 255)
            return bytes(values)

        def decode_pgm(gray, width):
            pgm = tmp / "qr.pgm"
            pgm.write_bytes(f"P5\n{width} {width}\n255\n".encode() + gray)
            decoded = subprocess.check_output(
                ["zbarimg", "--nodbus", "--quiet", "--raw", str(pgm)]).strip()
            assert decoded == qr_text, (decoded, qr_text)
            return pgm

        decode_pgm(qr_gray(4), 420)
        status = struct.unpack("<9Q", kernel("apple_kernel_report", 72))
        stage, pc, sp, el, sctlr, daif, vbar, percpu, pan = status
        if refuse:
            assert stage == 3
            attempts, store_status, final, lock = struct.unpack(
                "<4Q", kernel("apple_kernel_atomic_report", 32))
            assert 1 <= attempts <= 128 and (store_status, final, lock) == (0, 2, 0)
            assert tuple(int(qr[key], 16) for key in ("status", "value", "lock")) == (0, 2, 0)
            text = kernel("apple_probe_console_text", 8192).split(b"\0")[0].decode()
            assert "HALTED - ATOMIC PREFLIGHT FAILED\n" in text
            assert "NO SHARED LOCKS BYPASSED - PREFLIGHT HALTED\n" in text
            assert "[SMP]" not in text and "[APPLE] SHARED INIT CHECKPOINT" not in text
            assert struct.unpack("<I", kernel("klog_used", 4))[0] == 0
            assert struct.unpack("<Q", kernel("g_percpu", 8))[0] == 0
            print("REAL KERNEL PASS: bad initial atomic state refused before shared init")
            return
        assert stage == 2, status
        if pan_cpu:
            assert pan, "PAN-capable CPU test did not exercise PAN"
        assert pc == syms["apple_kernel_checkpoint"] and el == 4, status
        assert BASE < sp <= syms["apple_kernel_stack_top"] and sp % 16 == 0, status
        assert sctlr & 0x1005 == 5 and daif & 0x3c0 == 0x3c0, status
        assert vbar == syms["exception_vectors"] and percpu == syms["g_percpu"], status
        assert struct.unpack("<Q", kernel("g_percpu", 8))[0] == percpu
        attempts, store_status, final, lock = struct.unpack(
            "<4Q", kernel("apple_kernel_atomic_report", 32))
        assert 1 <= attempts <= 128 and (store_status, final, lock) == (0, 1, 0)
        assert tuple(int(qr[key], 16) for key in ("attempts", "status", "value", "lock")) == \
            (attempts, store_status, final, lock)
        text = kernel("apple_probe_console_text", 8192).split(b"\0")[0].decode()
        for wanted in (
            "AEGIS - REAL ARM64 KERNEL ENTRY\n",
            "DATA CACHE ON - INSTRUCTION CACHE OFF\n",
            "ATOMIC PREFLIGHT PASSED - ENTERING SHARED INIT\n",
            "[SMP] OK: per-CPU data initialized\n",
            "[IDT] OK: EL1 vector table installed\n",
            "[UACCESS] OK: EL1 fault fixup (8/8 uncopied)\n",
            "[CAP] OK: capability subsystem initialized\n",
            "[APPLE] SHARED INIT CHECKPOINT:",
            "[APPLE] HALTED: no PMM, no IRQ controller, no timer, no device probes\n",
        ):
            assert wanted in text, (wanted, text)
        assert "[PAN] OK:" in text if pan else "[PAN] WARN:" in text
        assert not any(word in text for word in ("[PMM]", "[GIC]", "[TIMER]", "[PCIE]", "[PANIC]"))
        # The existing kernel printk ring, not just the bootstrap transcript.
        used = struct.unpack("<I", kernel("klog_used", 4))[0]
        assert 0 < used < 4096  # no wrap in this bounded checkpoint
        ring = kernel("klog_buf", used)
        assert b"[UACCESS] OK: EL1 fault fixup (8/8 uncopied)\n" in ring
        assert b"[APPLE] SHARED INIT CHECKPOINT:" in ring
        pixels = read(arena, height * stride + 128)
        check_panel(pixels, bytes([0xa5]) * len(pixels), width, height, stride, 0x3fffffff, qr=True)
        if native_geometry:
            (BUILD / "checkpoint-preview.txt").write_text(text)
            write_preview(pixels, width, height, stride, 0x3fffffff,
                          BUILD / "checkpoint-preview.png")
            x0, y0, w, h = struct.unpack("<4I", kernel("apple_probe_qr_rect", 16))
            assert (x0, y0, w, h) == (1448, 16, 840, 840)
            actual = bytearray()
            for y in range(y0, y0 + h):
                for x in range(x0, x0 + w):
                    value = struct.unpack_from("<I", pixels, 64 + y * stride + x * 4)[0]
                    assert value in (0, 0x3fffffff)
                    actual.append(0 if value == 0 else 255)
            assert bytes(actual) == qr_gray(8)
            pgm = decode_pgm(actual, w)
            (BUILD / "checkpoint-qr.pgm").write_bytes(pgm.read_bytes())
            (BUILD / "checkpoint-qr.json").write_bytes(qr_text + b"\n")
            print("QR PASS: actual native-size framebuffer independently decoded to exact JSON")
        # Walk actual TTBR1 tables independently and check every high leaf.
        root = image + loader["tables"]
        seen, leaves = set(), {}

        def walk(pa, level, prefix):
            assert pa not in seen and root <= pa < root + 16 * 4096
            seen.add(pa)
            for index, value in enumerate(struct.unpack("<512Q", read(pa, 4096))):
                if not value:
                    continue
                assert value & 3 == 3
                va = prefix | (index << (39 - 9 * level))
                if level < 3:
                    walk(value & 0x0000fffffffff000, level + 1, va)
                else:
                    leaves[va | 0xffff000000000000] = value

        walk(root, 0, 0)
        assert len(leaves) == (syms["_kernel_end"] - BASE) // 4096
        low_tables = {}

        def low_leaf(address):
            table = image + loader["pool"]
            for level in range(4):
                if table not in low_tables:
                    low_tables[table] = struct.unpack("<512Q", read(table, 4096))
                entries = low_tables[table]
                descriptor = entries[(address >> (39 - 9 * level)) & 511]
                if not descriptor:
                    return 0
                assert descriptor & 3 == 3
                if level == 3:
                    return descriptor
                table = descriptor & 0x0000fffffffff000
            raise AssertionError("invalid low walk")

        for va, descriptor in leaves.items():
            assert descriptor & 0x0000fffffffff000 == physical + va - BASE
            assert (descriptor >> 2) & 7 == 2  # Normal WB, no low NC alias
            assert low_leaf(physical + va - BASE) == 0
            ro = va < syms["apple_kernel_ro_end"]
            xn = va >= syms["apple_kernel_text_end"]
            assert bool(descriptor & (1 << 7)) == ro
            assert bool(descriptor & (1 << 53)) == xn
            assert descriptor & (1 << 54) and not descriptor & (1 << 6)
        print(f"REAL KERNEL PASS: high PA={high}, EL2 entry={el2}, "
              f"PC={pc:#x}, SP={sp:#x}, {len(leaves)} W^X pages")

    run_case(image, build=build, el2=el2, version=3, stage=8,
             dtb_address=dtb, arena_address=arena, sparse_high_ram=high,
             post_check=check, cpu="cortex-a76" if pan_cpu else "cortex-a72",
             width=width, height=height, stride=stride, size=height * stride,
             ready=ready, bridge=True)


if __name__ == "__main__":
    for incoming_el2 in (False, True):
        case(incoming_el2)
        case(incoming_el2, high=True, native_geometry=incoming_el2)
    case(True, pan_cpu=True)
    # Test-only changed initial state in an ephemeral image. Never packaged
    # for USB or written over the qualified build's Image.
    with tempfile.TemporaryDirectory(prefix="aegis-atomic-refusal-") as directory:
        build = Path(directory)
        (build / "probe.elf").symlink_to(BUILD / "probe.elf")
        image = bytearray((BUILD / "Image").read_bytes())
        offset = symbols_for(BUILD)["apple_kernel_blob"] + syms["exclusive_probe"] - BASE
        struct.pack_into("<H", image, offset, 1)
        (build / "Image").write_bytes(image)
        case(True, refuse=True, build=build)
