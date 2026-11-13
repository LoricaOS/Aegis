"""QEMU-only GICv2 fixture: deliver its physical timer through the FIQ pin.

These MMIO instructions are a separate QEMU entry stub, never part of a
native Image. Aegis neither maps nor touches this GIC. Its one-shot handler
quiesces the timer and returns with FIQ masked, so no controller EOI is needed
to test this single delivery/return.
"""
import subprocess


def prepare_entry(tmp, dtb, image, el2):
    (tmp / "entry.S").write_text(f"""
.text
.global _start
_start:
    msr daifset, #15
    ldr x4, =0x08000000
    str wzr, [x4]
    str wzr, [x4, #0x80]
    mov w5, #0x40000000
    str w5, [x4, #0x100]
    mov w5, #0xa0
    strb w5, [x4, #0x41e]
    ldr x4, =0x08010000
    mov w5, #0xff
    str w5, [x4, #4]
    mov w5, #9
    str w5, [x4]
    ldr x4, =0x08000000
    mov w5, #1
    str w5, [x4]
    dsb sy
    isb
    ldr x0, ={dtb:#x}
    ldr x1, ={image:#x}
    br x1
""")
    subprocess.run(["aarch64-linux-gnu-gcc", "-c", str(tmp / "entry.S"),
                    "-o", str(tmp / "entry.o")], check=True)
    subprocess.run(["aarch64-linux-gnu-ld", "-Ttext=0x40100000", str(tmp / "entry.o"),
                    "-o", str(tmp / "entry.elf")], check=True)
    subprocess.run(["aarch64-linux-gnu-objcopy", "-O", "binary", str(tmp / "entry.elf"),
                    str(tmp / "entry.bin")], check=True)
