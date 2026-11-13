#!/usr/bin/env python3
"""Execute real scheduler, KVA thread stacks, FP/TLS switches and QR in QEMU."""
from pathlib import Path
import json
import shutil
import struct
import subprocess
import tempfile

from apple_probe_test import run_case, check_panel, symbols_for
from apple_timer_fixture import prepare_entry

BUILD = Path("build/applesched/loader").resolve()
ELF = Path("build/applesched/kernel/aegis-arm64.elf").resolve()
BASE = 0xffffffff80200000
SYMS = {}
for line in subprocess.check_output(["aarch64-linux-gnu-nm", str(ELF)], text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        SYMS[fields[2]] = int(fields[0], 16)


def case(el2=True, high=False, pan=False, native=False, build=BUILD, failure=0):
    image = 0x10000200000 if high else 0x40200000
    dtb = 0x10003000000 if high else 0x43000000
    fb = 0x10004000000 if high else 0x44000000
    width, height, stride = (3024, 1964, 12096) if native else (320, 160, 1280)

    def ready(command, tmp, loader):
        physical = image + loader["apple_kernel_blob"]
        for name in ("apple_sched_report", "apple_timer_report", "apple_memory_report"):
            command("pmemsave", val=physical + SYMS[name] - BASE,
                    size=8, filename=str(tmp / "stage"))
            stage, = struct.unpack("<Q", (tmp / "stage").read_bytes())
            if stage == 255 or (name == "apple_sched_report" and stage == 3):
                return True
        return False

    def check(command, tmp, loader, boot_report, text):
        physical = image + loader["apple_kernel_blob"]

        def read(pa, n):
            command("pmemsave", val=pa, size=n, filename=str(tmp / "read"))
            return (tmp / "read").read_bytes()

        def kernel(symbol, n):
            return read(physical + SYMS[symbol] - BASE, n)

        values = struct.unpack("<17Q", kernel("apple_sched_report", 136))
        stage, reason, a, b, ea, eb, ta, tb, sa, sb, cpacr, daif, before, after, masks, va, vb = values
        qr_text = kernel("apple_qr_text", 896).split(b"\0")[0]
        qr = json.loads(qr_text)
        if failure:
            assert (stage, reason) == (255, failure), (values, qr)
            assert qr["phase"] == "sched-failed" and int(qr["reason"], 16) == failure
            assert a < 32 or b < 32
            print(f"SCHED REFUSAL PASS: corrupted context caught, reason={failure}")
            return
        assert (stage, reason, a, b, ea, eb, masks, va, vb) == (3, 0, 32, 32, 1, 1, 1, 1, 1), (values, qr)
        assert ta != tb and sa != sb
        assert 0 < before - after < 32, (before, after)
        assert cpacr & (3 << 20) == 3 << 20 and daif & 0x3c0 == 0x3c0
        timer = struct.unpack("<18Q", kernel("apple_timer_report", 144))
        assert timer[0] == 3 and timer[4:7] == (1, 1, 0)
        assert timer[9] & 3 == 2
        assert struct.unpack("<Q", kernel("apple_memory_report", 8))[0] == 5
        assert qr["build"] == "sched-qr1" and qr["phase"] == "sched-complete"
        assert tuple(int(qr[k], 16) for k in ("a", "b", "rounds", "reason", "tasks")) == (32, 32, 32, 0, 2)
        assert int(qr["cpacr"], 16) == cpacr and int(qr["free_now"], 16) == after
        # Inspect actual task state as well as the foreground proof.
        root = int(qr["root"], 16)

        def translate(va):
            table = root
            for shift in (39, 30, 21, 12):
                pte, = struct.unpack("<Q", read(table + ((va >> shift) & 511) * 8, 8))
                assert pte & 1
                if shift == 12 or pte & 3 == 1:
                    return (pte & 0x0000fffffffff000 & ~((1 << shift) - 1)) | (va & ((1 << shift) - 1))
                table = pte & 0x0000fffffffff000
            raise AssertionError("bad translation")

        owners, tls = [], []
        for task in (ta, tb):
            raw = read(translate(task), 608)
            owners.append(struct.unpack_from("<i", raw, 8)[0])
            tls.append(struct.unpack_from("<Q", raw, 592)[0])
        assert sorted(owners) == [-1, 0], owners
        assert tls == [0x51510000, 0x51510001], tls
        modules = 113
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
        pgm = tmp / "sched.pgm"
        pgm.write_bytes(f"P5\n{size} {size}\n255\n".encode() + gray)
        assert subprocess.check_output(["zbarimg", "--nodbus", "--quiet", "--raw", str(pgm)]).strip() == qr_text
        pixels = read(fb, height * stride + 128)
        check_panel(pixels, bytes([0xa5]) * len(pixels), width, height, stride,
                    0x3fffffff, qr=True, qr_modules=modules)
        if native:
            x0, y0, w, h = struct.unpack("<4I", kernel("apple_probe_qr_rect", 16))
            assert (x0, y0, w, h) == (1448, 16, 968, 968)
            actual = bytearray()
            for y in range(y0, y0 + h):
                for x in range(x0, x0 + w):
                    color, = struct.unpack_from("<I", pixels, 64 + y * stride + x * 4)
                    assert color in (0, 0x3fffffff)
                    actual.append(0 if color == 0 else 255)
            pgm.write_bytes(f"P5\n{w} {h}\n255\n".encode() + actual)
            assert subprocess.check_output(["zbarimg", "--nodbus", "--quiet", "--raw", str(pgm)]).strip() == qr_text
            (BUILD / "sched-qr.json").write_bytes(qr_text + b"\n")
            (BUILD / "sched-qr.pgm").write_bytes(pgm.read_bytes())
        print(f"SCHED PASS: EL2={el2}, high={high}, PAN={pan}; two threads, 32 rounds each, integer/FP/TLS state")

    run_case(image, build=build, el2=el2, version=3, stage=8,
             dtb_address=dtb, arena_address=fb, sparse_high_ram=high,
             width=width, height=height, stride=stride, size=height * stride,
             cpu="cortex-a76" if pan else "cortex-a72", ready=ready, bridge=True,
             prepare_entry=prepare_entry, gic_version=2, qr_modules=113, post_check=check)


def corrupt_restore(instruction, reason, replacement=0xd503201f):
    """Omit one specific restore in a temporary Image, never the native build.

    Demonstrates detection of a missing FP/TLS restore, rather than
    merely trusting the checkpoint's success flags on a working switch.
    """
    loader = symbols_for(BUILD)
    image = bytearray((BUILD / "Image").read_bytes())
    start = loader["apple_kernel_blob"] + SYMS["ctx_switch"] - BASE
    end = loader["apple_kernel_blob"] + SYMS["arm64_fpu_save"] - BASE
    encoded = struct.pack("<I", instruction)
    offsets = [i for i in range(start, end, 4) if image[i:i + 4] == encoded]
    assert len(offsets) == 1, offsets
    image[offsets[0]:offsets[0] + 4] = struct.pack("<I", replacement)
    with tempfile.TemporaryDirectory(prefix="aegis-sched-corrupt-") as directory:
        build = Path(directory)
        shutil.copyfile(BUILD / "probe.elf", build / "probe.elf")
        (build / "Image").write_bytes(image)
        case(build=build, failure=reason)


if __name__ == "__main__":
    case()
    case(el2=False)
    case(high=True, native=True)
    case(pan=True)
    corrupt_restore(0xad4f7c5e, 11)  # ldp q30, q31, [x2, #480]
    corrupt_restore(0xd51bd043, 10) # msr tpidr_el0, x3
