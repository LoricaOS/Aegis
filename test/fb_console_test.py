#!/usr/bin/env python3
"""Build/run the production FB terminal with guarded RAM, plain and UBSan.

Only privileged arch hooks, hardware discovery and KVA allocation are mocked.
The production ticket spinlock, renderer, parser, scroll and panic code run.
No ASan: some development hosts hang in its runtime. Each process is bounded.
Run: python3 test/fb_console_test.py
"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ARCH = r"""
#ifndef ARCH_H
#define ARCH_H
#include <stdint.h>
typedef struct {
    uint64_t addr;
    uint32_t pitch, width, height;
    uint8_t bpp, type;
} arch_fb_info_t;
int arch_get_fb_info(arch_fb_info_t *);
unsigned long arch_irq_save(void);
void arch_irq_restore(unsigned long);
void arch_disable_irq(void);
void arch_halt(void);
void arch_pause(void);
#endif
"""


def main():
    with tempfile.TemporaryDirectory(prefix="aegis-fb-test-") as tmp:
        temp = Path(tmp)
        (temp / "arch.h").write_text(ARCH)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        common = [
            "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
            "-pthread", f"-I{temp}",
            *[f"-I{ROOT / 'kernel' / directory}" for directory in (
                "arch/x86_64", "core", "mm", "drivers")],
            str(ROOT / "test/fb_console_test.c"),
        ]
        for name, flags in (
            ("plain", []),
            ("ubsan", ["-fsanitize=undefined", "-fno-sanitize-recover=all"]),
        ):
            binary = temp / name
            subprocess.run(compiler + common + flags + ["-o", str(binary)],
                           check=True, timeout=60)
            subprocess.run([str(binary)], check=True, timeout=60)
            print(f"fb-console {name}: PASS", flush=True)


if __name__ == "__main__":
    main()
