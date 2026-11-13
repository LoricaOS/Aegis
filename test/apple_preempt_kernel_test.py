#!/usr/bin/env python3
"""Real timer FIQ preemption of non-yielding kernel threads in QEMU."""
from pathlib import Path
import json
import struct
import subprocess
import tempfile

from apple_probe_test import run_case, check_panel
from apple_preempt_fixture import prepare_entry, adapt

BUILD = Path("build/applepreempt/loader").resolve()
ELF = Path("build/applepreempt/kernel/aegis-arm64.elf").resolve()
BASE = 0xffffffff80200000
SYMS = {}
for line in subprocess.check_output(["aarch64-linux-gnu-nm", str(ELF)], text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        SYMS[fields[2]] = int(fields[0], 16)


def case(el2=True, high=False, pan=False, native=False, eoi=True):
    image = 0x10000200000 if high else 0x40200000
    dtb = 0x10003000000 if high else 0x43000000
    fb = 0x10004000000 if high else 0x44000000
    width, height, stride = (3024, 1964, 12096) if native else (320, 160, 1280)

    def ready(command, tmp, loader):
        physical = image + loader["apple_kernel_blob"]
        for name in ("apple_preempt_report", "apple_timer_report", "apple_memory_report"):
            command("pmemsave", val=physical + SYMS[name] - BASE,
                    size=8, filename=str(tmp / "stage"))
            stage, = struct.unpack("<Q", (tmp / "stage").read_bytes())
            if stage == 255 or (name == "apple_preempt_report" and stage == 3):
                return True
        return False

    def check(command, tmp, loader, boot_report, text):
        physical = image + loader["apple_kernel_blob"]

        def read(pa, n):
            command("pmemsave", val=pa, size=n, filename=str(tmp / "read"))
            return (tmp / "read").read_bytes()

        def kernel(symbol, n):
            return read(physical + SYMS[symbol] - BASE, n)

        values = struct.unpack("<28Q", kernel("apple_preempt_report", 224))
        stage, reason, ticks, ia, ib, ra, rb, va, vb, ea, eb, ta, tb, sa, sb, freq, cpacr, daif, start, end, ctl, fa, fb_frame, ela, elb, psa, psb, ns = values
        qr_text = kernel("apple_qr_text", 1280).split(b"\0")[0]
        qr = json.loads(qr_text)
        if eoi:
            assert (stage, reason, va, vb, ea, eb) == (3, 0, 1, 1, 1, 1), (values, qr)
            assert ra >= 8 and rb >= 8 and ticks == ia + ib <= 128, values
            assert 0 <= ticks - ra - rb <= 1
            assert ta != tb and sa != sb
            assert cpacr & (3 << 20) == 3 << 20
            assert daif & 0x3c0 == 0x3c0 and ctl & 3 == 2
            assert end > start and ns > 0
            assert qr["phase"] == "preempt-complete"
            for elr, spsr in ((ela, psa), (elb, psb)):
                assert SYMS["apple_preempt_wait_begin"] <= elr < SYMS["apple_preempt_wait_end"]
                assert spsr & 15 == 5 and spsr & 0xc0 == 0x80
            assert int(qr["tasks"], 16) == 2
            assert int(qr["a"], 16) == int(qr["b"], 16) == 1
            # Shared scheduler timekeeping now advances, not just local proof counters.
            assert struct.unpack("<Q", kernel("s_ticks", 8))[0] == ticks
        else:
            assert stage == 255 and reason == 8, (values, qr)
            assert ticks == 1 and ra + rb <= 1
            assert qr["phase"] == "preempt-failed"
        assert qr["build"] == "preempt-qr1" and int(qr["reason"], 16) == reason
        assert tuple(int(qr[k], 16) for k in ("ticks", "fiq_a", "fiq_b", "ret_a", "ret_b", "freq")) == \
            (ticks, ia, ib, ra, rb, freq)
        timer = struct.unpack("<18Q", kernel("apple_timer_report", 144))
        assert timer[0] == 3 and timer[4:7] == (1, 1, 0)
        assert struct.unpack("<Q", kernel("apple_memory_report", 8))[0] == 5
        modules = 129
        matrix = kernel("apple_qr_matrix", (modules * modules + 7) // 8 + 1)
        assert matrix[0] == modules
        size = (modules + 8) * 4
        gray = bytearray()
        for y in range(size):
            for x in range(size):
                mx, my = x // 4 - 4, y // 4 - 4
                bit = my * modules + mx
                dark = 0 <= mx < modules and 0 <= my < modules and matrix[1 + bit // 8] & (1 << (bit & 7))
                gray.append(0 if dark else 255)
        pgm = tmp / "preempt.pgm"
        pgm.write_bytes(f"P5\n{size} {size}\n255\n".encode() + gray)
        assert subprocess.check_output(["zbarimg", "--nodbus", "--quiet", "--raw", str(pgm)]).strip() == qr_text
        pixels = read(fb, height * stride + 128)
        check_panel(pixels, bytes([0xa5]) * len(pixels), width, height, stride,
                    0x3fffffff, qr=True, qr_modules=modules)
        if native:
            x0, y0, w, h = struct.unpack("<4I", kernel("apple_probe_qr_rect", 16))
            assert (x0, y0, w, h) == (1448, 16, 1096, 1096)
            actual = bytearray()
            for y in range(y0, y0 + h):
                for x in range(x0, x0 + w):
                    color, = struct.unpack_from("<I", pixels, 64 + y * stride + x * 4)
                    assert color in (0, 0x3fffffff)
                    actual.append(0 if color == 0 else 255)
            pgm.write_bytes(f"P5\n{w} {h}\n255\n".encode() + actual)
            assert subprocess.check_output(["zbarimg", "--nodbus", "--quiet", "--raw", str(pgm)]).strip() == qr_text
            (BUILD / "preempt-qr.json").write_bytes(qr_text + b"\n")
            (BUILD / "preempt-qr.pgm").write_bytes(pgm.read_bytes())
        print(f"PREEMPT PASS: EL2={el2}, high={high}, PAN={pan}, EOI={eoi}; ticks={ticks}, resumes={ra}/{rb}, reason={reason}")

    with tempfile.TemporaryDirectory(prefix="aegis-preempt-gic-") as directory:
        build = Path(directory)
        adapt(BUILD, build, SYMS, eoi=eoi)
        run_case(image, build=build, el2=el2, version=3, stage=8,
                 dtb_address=dtb, arena_address=fb, sparse_high_ram=high,
                 width=width, height=height, stride=stride, size=height * stride,
                 cpu="cortex-a76" if pan else "cortex-a72", ready=ready, bridge=True,
                 prepare_entry=prepare_entry, gic_version=2, qr_modules=129, post_check=check)


if __name__ == "__main__":
    case()
    case(el2=False)
    case(high=True, native=True)
    case(pan=True)
    case(eoi=False)
