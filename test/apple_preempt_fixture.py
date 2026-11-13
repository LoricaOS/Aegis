"""QEMU-only GIC adapter for repeated direct-FIQ kernel tests.

Temporary Image only: use two unsupported AArch32 vector slots as adapters.
IAR is read before the native timer handler quiesces/rearms its source; EOI
is written after rearm but before sched_tick can suspend the handler stack.
The native Image contains neither adapter nor GIC access/mapping.
"""
from pathlib import Path
import shutil
import struct
import subprocess

from apple_probe_test import symbols_for
from apple_timer_fixture import prepare_entry as timer_entry


def prepare_entry(tmp, dtb, image, el2):
    timer_entry(tmp, dtb, image, el2)
    entry = bytearray((tmp / "entry.bin").read_bytes())
    entry.extend(bytes(0x6000 - len(entry)))
    struct.pack_into("<Q", entry, 0x4000, 0x40105003)
    # Temporary low device map, MAIR index 1 under the native memory profile.
    struct.pack_into("<Q", entry, 0x5000, 1 | (1 << 2) | (1 << 10) | (1 << 53) | (1 << 54))
    (tmp / "entry.bin").write_bytes(entry)


def adapt(build, destination, syms, eoi=True):
    destination = Path(destination)
    loader = symbols_for(build)
    data = bytearray((build / "Image").read_bytes())
    blob = loader["apple_kernel_blob"]
    base = 0xffffffff80200000

    def offset(va):
        return blob + va - base

    def patch_branch(function, target, adapter):
        address = syms[function]
        size = next(int(line.split()[1], 16) for line in subprocess.check_output(
            ["aarch64-linux-gnu-nm", "-S", str(build.parent / "kernel/aegis-arm64.elf")],
            text=True).splitlines() if line.split()[-1] == function)
        matches = []
        for pc in range(address, address + size, 4):
            word, = struct.unpack_from("<I", data, offset(pc))
            if word & 0x7c000000 != 0x14000000:
                continue
            delta = (word & 0x3ffffff) << 2
            if delta & (1 << 27):
                delta -= 1 << 28
            if pc + delta == syms[target]:
                matches.append((pc, word))
        assert len(matches) == 1, (function, target, matches)
        pc, word = matches[0]
        assert -(1 << 27) <= adapter - pc < (1 << 27)
        struct.pack_into("<I", data, offset(pc),
                         (word & 0xfc000000) | (((adapter - pc) >> 2) & 0x3ffffff))

    for slot, caller, target, acknowledge in (
        (12, "apple_timer_fiq", "apple_preempt_interrupt", True),
        (13, "apple_preempt_schedule", "sched_tick", False),
    ):
        address = syms["exception_vectors"] + slot * 128
        operation = """
    ldr w11, [x10, #12]
    cmp w11, #30
    b.ne bad
""" if acknowledge else ("""
    mov w11, #30
    str w11, [x10, #16]
""" if eoi else "nop\n")
        source = destination / f"adapter-{slot}.S"
        source.write_text(f"""
.text
.global _start
_start:
    mrs x9, ttbr0_el1
    mov x10, #0x4000
    movk x10, #0x4010, lsl #16
    msr ttbr0_el1, x10
    dsb ishst
    tlbi vmalle1is
    dsb ish
    isb
    mov x10, #0
    movk x10, #0x0801, lsl #16
{operation}
    dsb sy
    msr ttbr0_el1, x9
    tlbi vmalle1is
    dsb ish
    isb
    .inst 0x14000000 | ((({syms[target]:#x} - {address:#x} - (. - _start)) >> 2) & 0x3ffffff)
bad:
    brk #0x73
""")
        obj, elf, binary = (source.with_suffix(suffix) for suffix in (".o", ".elf", ".bin"))
        subprocess.run(["aarch64-linux-gnu-gcc", "-c", str(source), "-o", str(obj)], check=True)
        subprocess.run(["aarch64-linux-gnu-ld", f"-Ttext={address:#x}", str(obj), "-o", str(elf)], check=True)
        subprocess.run(["aarch64-linux-gnu-objcopy", "-O", "binary", str(elf), str(binary)], check=True)
        code = binary.read_bytes()
        assert len(code) <= 128
        data[offset(address):offset(address) + len(code)] = code
        patch_branch(caller, target, address)
    (destination / "Image").write_bytes(data)
    shutil.copyfile(build / "probe.elf", destination / "probe.elf")
