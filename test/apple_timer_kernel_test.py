#!/usr/bin/env python3
"""Real kernel memory + physical timer FIQ + full exception return under QEMU."""
from pathlib import Path
import json
import struct
import subprocess

from apple_probe_test import run_case, check_panel
from apple_timer_fixture import prepare_entry

BUILD = Path("build/appletimer/loader").resolve()
ELF = Path("build/appletimer/kernel/aegis-arm64.elf").resolve()
BASE = 0xffffffff80200000
syms = {}
for line in subprocess.check_output(["aarch64-linux-gnu-nm", str(ELF)], text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        syms[fields[2]] = int(fields[0], 16)


def case(el2=True, high=False, pan=False, native=False, route=True):
    image = 0x10000200000 if high else 0x40200000
    dtb = 0x10003000000 if high else 0x43000000
    fb = 0x10004000000 if high else 0x44000000
    width, height, stride = (3024, 1964, 12096) if native else (320, 160, 1280)

    def ready(command, tmp, loader):
        physical = image + loader["apple_kernel_blob"]
        command("pmemsave", val=physical + syms["apple_timer_report"] - BASE,
                size=8, filename=str(tmp / "timer-ready"))
        stage, = struct.unpack("<Q", (tmp / "timer-ready").read_bytes())
        command("pmemsave", val=physical + syms["apple_memory_report"] - BASE,
                size=8, filename=str(tmp / "memory-ready"))
        memory_stage, = struct.unpack("<Q", (tmp / "memory-ready").read_bytes())
        return stage in (3, 255) or memory_stage == 255

    def check(command, tmp, loader, boot_report, text):
        physical = image + loader["apple_kernel_blob"]

        def read(pa, n):
            command("pmemsave", val=pa, size=n, filename=str(tmp / "read"))
            return (tmp / "read").read_bytes()

        def kernel(symbol, n):
            return read(physical + syms[symbol] - BASE, n)

        values = struct.unpack("<18Q", kernel("apple_timer_report", 144))
        stage, frequency, start, end, delivered, returned, failure, before, entry, final, spsr, elr, frame, daif, hcr, gate_before, gate_after, cnthctl = values
        qr_text = kernel("apple_qr_text", 768).split(b"\0")[0]
        qr = json.loads(qr_text)
        text = kernel("apple_probe_console_text", 8192).split(b"\0")[0].decode()
        assert struct.unpack("<Q", kernel("apple_memory_report", 8))[0] == 5, text
        assert qr["build"] == "timer-qr1"
        assert 1000 <= frequency <= 1000000000 and end >= start
        assert final & 3 == 2 and daif & 0x3c0 == 0x3c0
        if route:
            assert (stage, delivered, returned, failure) == (3, 1, 1, 0), (values, qr, text)
            assert entry & 7 == 5 and spsr & 15 == 5 and spsr & 0xc0 == 0x80
            assert syms["apple_timer_wait_begin"] <= elr < syms["apple_timer_wait_end"]
            assert syms["apple_kernel_stack_top"] - 32768 <= frame <= syms["apple_kernel_stack_top"] - 272
            assert qr["phase"] == "timer-complete"
            assert "[APPLE] TIMER CHECKPOINT: physical FIQ + register return passed\n" in text
        else:
            assert (stage, delivered, returned, failure) == (255, 0, 0, 9), (values, qr, text)
            assert qr["phase"] == "timer-timeout"
        assert tuple(int(qr[key], 16) for key in ("freq", "fiq", "returned", "reason")) == \
            (frequency, delivered, returned, failure)
        assert int(qr["sctlr"], 16) & 0x1005 == 5
        matrix = kernel("apple_qr_matrix", 1380)
        assert matrix[0] == 105
        gray = bytearray()
        for y in range(452):
            for x in range(452):
                mx, my = x // 4 - 4, y // 4 - 4
                bit = my * 105 + mx
                dark = 0 <= mx < 105 and 0 <= my < 105 and matrix[1 + bit // 8] & (1 << (bit & 7))
                gray.append(0 if dark else 255)
        pgm = tmp / "timer.pgm"
        pgm.write_bytes(b"P5\n452 452\n255\n" + gray)
        assert subprocess.check_output(
            ["zbarimg", "--nodbus", "--quiet", "--raw", str(pgm)]).strip() == qr_text
        pixels = read(fb, height * stride + 128)
        check_panel(pixels, bytes([0xa5]) * len(pixels), width, height, stride, 0x3fffffff,
                    qr=True, qr_modules=105)
        if native:
            x0, y0, w, h = struct.unpack("<4I", kernel("apple_probe_qr_rect", 16))
            assert (x0, y0, w, h) == (1448, 16, 904, 904)
            actual = bytearray()
            for y in range(y0, y0 + h):
                for x in range(x0, x0 + w):
                    color = struct.unpack_from("<I", pixels, 64 + y * stride + x * 4)[0]
                    assert color in (0, 0x3fffffff)
                    actual.append(0 if color == 0 else 255)
            pgm.write_bytes(b"P5\n904 904\n255\n" + actual)
            assert subprocess.check_output(
                ["zbarimg", "--nodbus", "--quiet", "--raw", str(pgm)]).strip() == qr_text
            (BUILD / "timer-qr.json").write_bytes(qr_text + b"\n")
            (BUILD / "timer-qr.pgm").write_bytes(pgm.read_bytes())
        print(f"TIMER PASS: EL2={el2}, high={high}, actual FIQ route={route}, "
              f"delivered={delivered}, returned={returned}, reason={failure}")

    run_case(image, build=BUILD, el2=el2, version=3, stage=8,
             dtb_address=dtb, arena_address=fb, sparse_high_ram=high,
             width=width, height=height, stride=stride, size=height * stride,
             cpu="cortex-a76" if pan else "cortex-a72", ready=ready, bridge=True,
             prepare_entry=prepare_entry if route else None, gic_version=2, qr_modules=105,
             post_check=check)


if __name__ == "__main__":
    case()
    case(el2=False)
    case(high=True, native=True)
    case(pan=True)
    case(route=False)
