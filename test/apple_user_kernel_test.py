#!/usr/bin/env python3
"""Real ELF/EL0/SVC/uaccess/capability/isolation test under QEMU."""
from pathlib import Path
import json
import shutil
import struct
import subprocess
import tempfile

from apple_probe_test import run_case, check_panel, symbols_for
from apple_timer_fixture import prepare_entry

BUILD = Path("build/appleuser/loader").resolve()
ELF = Path("build/appleuser/kernel/aegis-arm64.elf").resolve()
BASE = 0xffffffff80200000
TOP = 0x7fffffff000
SYMS = {}
for line in subprocess.check_output(["aarch64-linux-gnu-nm", str(ELF)], text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        SYMS[fields[2]] = int(fields[0], 16)
USER = {}
for line in subprocess.check_output(["aarch64-linux-gnu-nm", str(BUILD.parent / "user.elf")],
                                    text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        USER[fields[2]] = int(fields[0], 16)


def case(el2=True, high=False, pan=False, native=False, failure=0, build=BUILD):
    image = 0x10000200000 if high else 0x40200000
    dtb = 0x10003000000 if high else 0x43000000
    fb = 0x10004000000 if high else 0x44000000
    width, height, stride = (3024, 1964, 12096) if native else (320, 160, 1280)

    def ready(command, tmp, loader):
        physical = image + loader["apple_kernel_blob"]
        for name in ("apple_user_report", "apple_timer_report", "apple_memory_report"):
            command("pmemsave", val=physical + SYMS[name] - BASE,
                    size=8, filename=str(tmp / "stage"))
            stage, = struct.unpack("<Q", (tmp / "stage").read_bytes())
            if stage == 255 or (name == "apple_user_report" and stage == 3):
                return True
        return False

    def check(command, tmp, loader, boot_report, text):
        physical = image + loader["apple_kernel_blob"]

        def read(pa, n):
            command("pmemsave", val=pa, size=n, filename=str(tmp / "read"))
            return (tmp / "read").read_bytes()

        def kernel(symbol, n):
            return read(physical + SYMS[symbol] - BASE, n)

        values = struct.unpack("<22Q", kernel("apple_user_report", 176))
        stage, step, reason, pid, uid, svcs, kd, td, nx, cap, bad, proc, root, kstack, usp, frame, esr, far, elr, cpacr, entered, free = values
        qr_text = kernel("apple_qr_text", 1280).split(b"\0")[0]
        qr = json.loads(qr_text)
        if failure:
            assert (stage, reason) == (255, failure), (values, qr)
            assert qr["phase"] == "user-failed" and int(qr["reason"], 16) == failure
            print(f"EL0 REFUSAL PASS: reason={failure}")
            return
        assert (stage, step, reason, pid, uid, svcs, kd, td, nx, cap, bad, entered) == \
            (3, 8, 0, 1, 0, 5, 1, 1, 1, 1, 1, 1), (values, qr)
        assert usp == TOP - 512
        assert kstack - 16384 <= frame <= kstack - 272
        assert (esr >> 26) == 0x3c and esr & 0xffff == 0x5a and elr == USER["user_done"]
        assert cpacr & (3 << 20) == 3 << 20
        assert qr["phase"] == "user-complete" and qr["build"] == "user-qr1"
        assert int(qr["ttbr0"], 16) == root and root != int(qr["root"], 16)
        assert tuple(int(qr[k], 16) for k in
                     ("pid", "uid", "svcs", "kernel_deny", "text_deny", "nx_deny", "capdeny", "badptr", "reason", "entered")) == \
            (1, 0, 5, 1, 1, 1, 1, 1, 0, 1)

        def leaf(va):
            table = root
            for shift in (39, 30, 21, 12):
                pte, = struct.unpack("<Q", read(table + ((va >> shift) & 511) * 8, 8))
                assert pte & 3 == 3
                if shift == 12:
                    return pte
                table = pte & 0x0000fffffffff000

        text_pte = leaf(USER["_start"])
        stack_pte = leaf(TOP - 4096)
        assert text_pte & (1 << 6) and text_pte & (1 << 7) and text_pte & (1 << 53)
        assert not text_pte & (1 << 54)
        assert stack_pte & (1 << 6) and not stack_pte & (1 << 7)
        assert stack_pte & (1 << 53) and stack_pte & (1 << 54)
        assert (text_pte >> 2) & 7 == (stack_pte >> 2) & 7 == 2
        elf = (BUILD.parent / "user.elf").read_bytes()
        phoff, = struct.unpack_from("<Q", elf, 32)
        _, flags, offset, va, _, filesz, memsz, _ = struct.unpack_from("<II6Q", elf, phoff)
        assert flags == 5 and memsz <= 4096
        loaded = read((text_pte & 0x0000fffffffff000) + (va & 4095), filesz)
        assert loaded == elf[offset:offset + filesz], "RX text changed"
        stack = read(stack_pte & 0x0000fffffffff000, 4096)
        uts = stack[4096 - 512:4096 - 512 + 390]
        assert uts[:6] == b"Aegis\0" and uts[260:268] == b"aarch64\0"
        assert stack[-16:-12] == bytes.fromhex("c0035fd6")
        timer = struct.unpack("<18Q", kernel("apple_timer_report", 144))
        assert timer[0] == 3 and timer[4:7] == (1, 1, 0)
        assert struct.unpack("<Q", kernel("apple_memory_report", 8))[0] == 5
        # Independently decode the matrix and actual native framebuffer pixels.
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
        pgm = tmp / "user.pgm"
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
            (BUILD / "user-qr.json").write_bytes(qr_text + b"\n")
            (BUILD / "user-qr.pgm").write_bytes(pgm.read_bytes())
        print(f"EL0 PASS: EL2={el2}, high={high}, PAN={pan}; 5 real syscalls, no caps, kernel/RX/NX denials")

    run_case(image, build=build, el2=el2, version=3, stage=8,
             dtb_address=dtb, arena_address=fb, sparse_high_ram=high,
             width=width, height=height, stride=stride, size=height * stride,
             cpu="cortex-a76" if pan else "cortex-a72", ready=ready, bridge=True,
             prepare_entry=prepare_entry, gic_version=2, qr_modules=129, post_check=check)


def mutate(kind):
    loader = symbols_for(BUILD)
    data = bytearray((BUILD / "Image").read_bytes())
    blob = loader["apple_kernel_blob"] + SYMS["apple_user_elf"] - BASE
    elf = (BUILD.parent / "user.elf").read_bytes()
    phoff, = struct.unpack_from("<Q", elf, 32)
    _, _, offset, va, _, _, _, _ = struct.unpack_from("<II6Q", elf, phoff)
    if kind == "missing-fault":
        position = blob + offset + USER["user_kernel_read"] - va
        assert struct.unpack_from("<I", data, position)[0] == 0xf9400200
        struct.pack_into("<I", data, position, 0xd503201f)
        reason = 7
    else:
        assert kind == "wx-elf"
        struct.pack_into("<I", data, blob + phoff + 4, 7)
        reason = 10
    with tempfile.TemporaryDirectory(prefix="aegis-user-mutate-") as directory:
        build = Path(directory)
        shutil.copyfile(BUILD / "probe.elf", build / "probe.elf")
        (build / "Image").write_bytes(data)
        case(build=build, failure=reason)


if __name__ == "__main__":
    case()
    case(el2=False)
    case(high=True, native=True)
    case(pan=True)
    mutate("missing-fault")
    mutate("wx-elf")
