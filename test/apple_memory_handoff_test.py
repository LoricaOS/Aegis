#!/usr/bin/env python3
"""Host-execute the actual arena validator/mapping policy with linker mocks."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    match = re.search(r"\b(?:static\s+)?(?:void|int)\s+" + name + r"\s*\(", source)
    assert match, name
    begin = source.index("{", match.start())
    depth, end = 1, begin + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


PREFIX = r'''
#define APPLE_MEMORY_CHECKPOINT 1
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kernel/arch/arm64/apple/kernel_memory.h"
#include "kernel/mm/pmm.h"
#include "kernel/mm/vmm.h"
#define BASE 0xffffffff80200000ULL
#define ARCH_KVA_BASE 0xffffffff84000000ULL
#define apple_kernel_base ((char *)(uintptr_t)BASE)
#define apple_kernel_text_end ((char *)(uintptr_t)(BASE + 2 * PAGE_SIZE))
#define apple_kernel_ro_end ((char *)(uintptr_t)(BASE + 4 * PAGE_SIZE))
#define _kernel_end ((char *)(uintptr_t)(BASE + 4 * 1024 * 1024))
static struct apple_kernel_handoff boot;
static struct apple_boot_mapping mappings[5];
static unsigned mapping_count, admitted;
volatile struct apple_memory_report apple_memory_report;
static _Noreturn void fail(const char *why) {
    fprintf(stderr, "%s\n", why);
    exit(admitted ? 78 : 77);
}
static void *arch_dmap(uint64_t p) { return (void *)(uintptr_t)(0xffff900000000000ULL + p); }
static void arch_mm_init_apple(uint64_t kernel, uint64_t arena, uint64_t n) {
    assert(kernel && arena > kernel && n == APPLE_BOOT_ARENA_SIZE); admitted++;
}
static void progress(const char *s) { assert(!strcmp(s, "memory-handoff")); }
'''
MAIN = r'''
int main(int argc, char **argv) {
    assert(argc == 2);
    uint64_t high = 1ULL << 40;
    struct apple_kernel_handoff h = {
        .magic = APPLE_KERNEL_HANDOFF_MAGIC,
        .loader_phys = high, .loader_size = 16 * 1024 * 1024,
        .kernel_phys = high + 2 * 1024 * 1024, .kernel_size = 4 * 1024 * 1024,
        .arena = high + 8 * 1024 * 1024, .arena_size = APPLE_BOOT_ARENA_SIZE,
        .fb = {high + 256 * 1024 * 1024, 640 * 480 * 4, 640, 480, 640 * 4, FDT_FB_XRGB8888},
    };
    const char *n = argv[1];
    if (!strcmp(n, "null")) { apple_memory_prepare(NULL); assert(0); }
    if (!strcmp(n, "bad-magic")) h.magic = 0;
    else if (!strcmp(n, "zero-loader")) h.loader_phys = 0;
    else if (!strcmp(n, "huge-loader")) h.loader_size = 25 * 1024 * 1024;
    else if (!strcmp(n, "wrap-loader")) h.loader_phys = UINT64_MAX - 4095;
    else if (!strcmp(n, "wrong-image-size")) h.kernel_size--;
    else if (!strcmp(n, "unaligned-image")) h.kernel_phys++;
    else if (!strcmp(n, "foreign-arena")) h.arena = high + h.loader_size;
    else if (!strcmp(n, "overlap-image")) h.arena = h.kernel_phys;
    else if (!strcmp(n, "short-arena")) h.arena_size -= 4096;
    else if (!strcmp(n, "unaligned-arena")) h.arena++;
    else if (!strcmp(n, "fb-overlap")) h.fb.base = h.loader_phys;
    else if (!strcmp(n, "fb-stride")) h.fb.stride = 4;
    else if (!strcmp(n, "fb-format")) h.fb.format = 99;
    else if (!strcmp(n, "fb-overflow")) h.fb.base = UINT64_MAX - 3;
    else if (!strcmp(n, "fb-high")) h.fb.base = 1ULL << 44;
    else assert(!strcmp(n, "valid"));
    apple_memory_prepare(&h);
    assert(!strcmp(n, "valid") && admitted == 1 && mapping_count == 5);
    assert(apple_memory_report.stage == 1 && boot.arena == h.arena);
    for (unsigned i = 0; i < 5; i++) {
        assert(!(mappings[i].flags & VMM_FLAG_USER));
        assert(mappings[i].size && !(mappings[i].size & 4095));
    }
    assert(mappings[0].va == BASE && mappings[0].pa == h.kernel_phys);
    assert(!(mappings[0].flags & (VMM_FLAG_WRITABLE | VMM_FLAG_NX)));
    assert(mappings[1].flags == VMM_FLAG_NX);
    assert(mappings[2].flags == (VMM_FLAG_WRITABLE | VMM_FLAG_NX));
    assert(mappings[3].pa == h.arena && mappings[3].size == h.arena_size);
    assert(mappings[4].flags == (VMM_FLAG_WRITABLE | VMM_FLAG_NX | VMM_FLAG_UCMINUS));
    puts("PASS");
    return 0;
}
'''


class HandoffTests(unittest.TestCase):
    def test_real_validator_and_exact_policy(self):
        source = (ROOT / "kernel/arch/arm64/apple/kernel_memory.c").read_text()
        body = "\n".join(function(source, name) for name in ("inside", "mapping", "apple_memory_prepare"))
        with tempfile.TemporaryDirectory(prefix="aegis-owned-map-") as directory:
            path = Path(directory) / "check.c"
            path.write_text(PREFIX + body + MAIN)
            binary = path.with_suffix("")
            subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-I", str(ROOT), str(path), "-o", str(binary)], check=True)
            cases = ("valid", "null", "bad-magic", "zero-loader", "huge-loader", "wrap-loader", "wrong-image-size",
                     "unaligned-image", "foreign-arena", "overlap-image", "short-arena",
                     "unaligned-arena", "fb-overlap", "fb-stride", "fb-format", "fb-overflow", "fb-high")
            for case in cases:
                with self.subTest(case=case):
                    result = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0 if case == "valid" else 77,
                                     result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
