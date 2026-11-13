#!/usr/bin/env python3
"""Exercise the complete production PMM with host IRQ/boot-map/KVA mocks.

No physical memory is dereferenced. Only includes and the linker end-symbol
binding are adapted; the allocator implementation is compiled unchanged.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "kernel/mm/pmm.h"
#define ARCH_KERNEL_PHYS_BASE 0x200000ULL
#define ARCH_KERNEL_VIRT_BASE 0x10000000ULL
typedef struct { uint64_t base, len; } aegis_mem_region_t;
typedef int spinlock_t;
typedef unsigned long irqflags_t;
#define SPINLOCK_INIT 0
#define LOCK_RANK_PMM 4
static aegis_mem_region_t map[8], exclusions[8];
static unsigned nr, nx;
static uint64_t slide;
static void *host_allocations[16];
static uint64_t host_frames[16384];
static unsigned host_count, host_nframes;
static uint64_t largest_request;
uint32_t arch_mm_region_count(void) { return nr; }
const aegis_mem_region_t *arch_mm_get_regions(void) { return map; }
uint32_t arch_mm_reserved_region_count(void) { return nx; }
const aegis_mem_region_t *arch_mm_get_reserved_regions(void) { return exclusions; }
uint64_t arch_kern_phys_slide(void) { return slide; }
static void lockrank_register(const void *p, unsigned rank) { (void)p; (void)rank; }
static irqflags_t spin_lock_irqsave(spinlock_t *p) { assert(!*p); *p = 1; return 0; }
static void spin_unlock_irqrestore(spinlock_t *p, irqflags_t f) { (void)f; assert(*p); *p = 0; }
static void printk(const char *fmt, ...) { (void)fmt; }
static void print_backtrace_from(uint64_t p, int n) { (void)p; (void)n; }
static _Noreturn void panic_halt(const char *s) { fprintf(stderr, "%s\n", s); exit(77); }
static void *kva_alloc_pages(uint64_t n) {
    assert(n && n < 4096 && host_count < 16);
    if (n > largest_request) largest_request = n;
    for (uint64_t i = 0; i < n; i++) {
        uint64_t pa = pmm_alloc_page();
        if (!pa) return NULL;
        assert(host_nframes < 16384);
        host_frames[host_nframes++] = pa;
    }
    void *p = calloc(n, PAGE_SIZE);
    assert(p);
    host_allocations[host_count++] = p;
    return p;
}
'''
SUFFIX = r'''
static void reset(void) {
    for (unsigned i = 0; i < host_count; i++) free(host_allocations[i]);
    host_count = host_nframes = 0; largest_request = 0;
    memset(map, 0, sizeof(map)); memset(exclusions, 0, sizeof(exclusions));
    nr = nx = 0; slide = 0;
    test_kernel_end = ARCH_KERNEL_VIRT_BASE + ARCH_KERNEL_PHYS_BASE + 8 * PAGE_SIZE;
    s_bitmap = pmm_boot_bitmap; s_bitmap_pages = PMM_BOOT_PAGES; s_bitmap_base = 0;
    s_refcount = NULL; s_refcount_pages = 0; s_high_pref = 0;
    s_scan_max_pages = s_ram_max_pages = s_managed_pages = 0;
    s_alloc_hint_byte = 0; s_pmm_debug = s_pmm_acct = 0; pmm_lock = 0;
}
static int allowed(uint64_t pa) {
    if (!pa || (pa & (PAGE_SIZE - 1))) return 0;
    int ram = 0;
    for (unsigned i = 0; i < nr; i++)
        if (pa >= map[i].base && pa + PAGE_SIZE <= map[i].base + map[i].len) ram = 1;
    if (!ram) return 0;
    uint64_t kernel = ARCH_KERNEL_PHYS_BASE + slide;
    if (pa < kernel + 8 * PAGE_SIZE && kernel < pa + PAGE_SIZE) return 0;
    for (unsigned i = 0; i < nx; i++)
        if (exclusions[i].len && pa < exclusions[i].base + exclusions[i].len &&
            exclusions[i].base < pa + PAGE_SIZE) return 0;
    for (unsigned i = 0; i < host_nframes; i++)
        if (host_frames[i] == pa) return 0;
    return 1;
}
static void drain(void) {
    uint64_t before = pmm_free_pages(), *pages = calloc(before + 1, sizeof(uint64_t));
    assert(pages && before < 16384);
    for (uint64_t i = 0; i < before; i++) {
        pages[i] = pmm_alloc_page();
        assert(allowed(pages[i]));
        for (uint64_t j = 0; j < i; j++) assert(pages[j] != pages[i]);
    }
    assert(pmm_alloc_page() == 0 && pmm_free_pages() == 0);
    for (uint64_t i = 0; i < before; i++) pmm_free_page(pages[i]);
    assert(pmm_free_pages() == before);
    free(pages);
}
static unsigned rng = 6030;
static unsigned random32(void) { rng = rng * 1664525u + 1013904223u; return rng; }
int main(int argc, char **argv) {
    assert(argc == 2);
    reset();
    const uint64_t high = (1ULL << 40) + 0x345000;
    if (!strcmp(argv[1], "low")) {
        nr = nx = 1; map[0] = (aegis_mem_region_t){0, 16 * 1024 * 1024};
        exclusions[0] = (aegis_mem_region_t){0, 1024 * 1024};
        pmm_init(); assert(s_bitmap_base == 0 && pmm_free_pages() == 4096 - 256 - 8);
        drain();
    } else if (!strcmp(argv[1], "high")) {
        nr = 1; map[0] = (aegis_mem_region_t){high, 8 * 1024 * 1024};
        pmm_init(); assert(s_bitmap_base == high && pmm_free_pages() == 2048);
        assert(pmm_ram_max_page() == (high + 8 * 1024 * 1024) / PAGE_SIZE);
        assert(!pmm_alloc_page_low() && !pmm_alloc_contig_low(2));
        pmm_init_late(); assert(largest_request == 1 && pmm_free_pages() == 2047);
        uint64_t p = pmm_alloc_page();
        assert(p >= high && pmm_page_refcount(p) == 1);
        for (unsigned i = 1; i < 65535; i++) assert(pmm_ref_page(p) == 0);
        assert(pmm_page_refcount(p) == 65535 && pmm_ref_page(p) == -1);
        for (unsigned i = 1; i < 65535; i++) pmm_free_page(p);
        assert(pmm_page_refcount(p) == 1);
        pmm_free_page(p); assert(pmm_free_pages() == 2047);
        drain();
    } else if (!strcmp(argv[1], "reservations")) {
        nr = nx = 1; map[0] = (aegis_mem_region_t){high, 64 * PAGE_SIZE};
        slide = high - ARCH_KERNEL_PHYS_BASE;
        exclusions[0] = (aegis_mem_region_t){high + 16 * PAGE_SIZE + 1, 2 * PAGE_SIZE};
        pmm_init(); assert(pmm_free_pages() == 64 - 8 - 3); drain();
        assert(pmm_unreserve_region(exclusions[0].base, exclusions[0].len) == 1);
        assert(pmm_unreserve_region(high + 16 * PAGE_SIZE, 3 * PAGE_SIZE) == 2);
        assert(pmm_unreserve_region(high + 16 * PAGE_SIZE, 3 * PAGE_SIZE) == 0);
        assert(pmm_unreserve_region(0, PAGE_SIZE) == 0);
        uint64_t count = pmm_free_pages();
        pmm_reserve_region(0x100000, 0x100000); pmm_free_page(high - PAGE_SIZE);
        assert(pmm_page_refcount(high - PAGE_SIZE) == 0);
        assert(pmm_ref_page(high - PAGE_SIZE) == 0 && pmm_free_pages() == count);
    } else if (!strcmp(argv[1], "holes")) {
        nr = 2; map[0] = (aegis_mem_region_t){high, 8 * PAGE_SIZE};
        map[1] = (aegis_mem_region_t){high + 32 * PAGE_SIZE, 8 * PAGE_SIZE};
        pmm_init(); assert(pmm_free_pages() == 16);
        uint64_t hole = high + 16 * PAGE_SIZE;
        pmm_free_page(hole); assert(pmm_ref_page(hole) == 0 && pmm_page_refcount(hole) == 0);
        assert(pmm_unreserve_region(high, 40 * PAGE_SIZE) == 0);
        assert(pmm_free_pages() == 16); drain();
    } else if (!strcmp(argv[1], "dma-boundary")) {
        nr = 1; map[0] = (aegis_mem_region_t){(1ULL << 32) - 4 * PAGE_SIZE, 8 * PAGE_SIZE};
        pmm_init(); assert(s_bitmap_base == 0 && pmm_free_pages() == 4);
        uint64_t p = pmm_alloc_contig_low(2);
        assert(p && p + 2 * PAGE_SIZE <= (1ULL << 32));
        p = pmm_alloc_page_low(); assert(p && p < (1ULL << 32));
        p = pmm_alloc_page_low(); assert(p && p < (1ULL << 32));
        assert(!pmm_alloc_page_low() && !pmm_alloc_contig_low(1));
    } else if (!strcmp(argv[1], "late-high") || !strcmp(argv[1], "late-low")) {
        uint64_t base = !strcmp(argv[1], "late-high") ? high : 0x100000;
        uint64_t second = base + (1ULL << 32) + 0x100000;
        nr = 2; nx = 1; map[0] = (aegis_mem_region_t){base, 32 * 1024 * 1024};
        map[1] = (aegis_mem_region_t){second, 8 * PAGE_SIZE};
        exclusions[0] = (aegis_mem_region_t){second + PAGE_SIZE, PAGE_SIZE};
        slide = second + 4 * PAGE_SIZE - ARCH_KERNEL_PHYS_BASE;
        pmm_init(); pmm_init_late();
        assert(largest_request < 1024);
        assert(pmm_ram_max_page() == (second + 8 * PAGE_SIZE) / PAGE_SIZE);
        uint64_t wanted = 0;
        for (unsigned i = 0; i < 8192; i++) wanted += allowed(base + i * PAGE_SIZE);
        for (unsigned i = 0; i < 8; i++) wanted += allowed(second + i * PAGE_SIZE);
        assert(pmm_free_pages() == wanted);
        drain(); /* also checks reservations beyond the old bitmap window */
    } else if (!strcmp(argv[1], "zero")) {
        nr = 1; map[0] = (aegis_mem_region_t){0, 16 * PAGE_SIZE};
        pmm_init(); assert(pmm_free_pages() == 15);
        pmm_free_page(0); assert(pmm_ref_page(0) == 0 && pmm_page_refcount(0) == 0);
        assert(pmm_unreserve_region(0, PAGE_SIZE) == 0 && pmm_free_pages() == 15); drain();
    } else if (!strcmp(argv[1], "wrap-ram")) {
        nr = 1; map[0] = (aegis_mem_region_t){UINT64_MAX - 3, 8}; pmm_init(); assert(0);
    } else if (!strcmp(argv[1], "wrap-reserved")) {
        pmm_reserve_region(UINT64_MAX - 3, 8); assert(0);
    } else if (!strcmp(argv[1], "random")) {
        for (unsigned trial = 0; trial < 200; trial++) {
            reset();
            uint64_t base = (trial & 1) ? high : 0x100000;
            nr = 3; nx = 2;
            for (unsigned i = 0; i < nr; i++) {
                uint64_t off = random32() % 40, len = random32() % 8 + 2;
                map[i] = (aegis_mem_region_t){base + off * PAGE_SIZE + random32() % 8,
                                             len * PAGE_SIZE + random32() % 8};
            }
            for (unsigned i = 0; i < nx; i++)
                exclusions[i] = (aegis_mem_region_t){base + (random32() % 48) * PAGE_SIZE + 1,
                                                    (random32() % 4 + 1) * PAGE_SIZE};
            pmm_init();
            uint64_t wanted = 0;
            for (unsigned i = 0; i < 64; i++) wanted += allowed(base + i * PAGE_SIZE);
            assert(pmm_free_pages() == wanted); drain();
        }
    } else assert(0);
    puts("PASS");
    reset();
    return 0;
}
'''


class PmmBaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="aegis-pmm-")
        source = (ROOT / "kernel/mm/pmm.c").read_text()
        source = re.sub(r"^#include[^\n]*", "", source, flags=re.M)
        assert source.count("extern char _kernel_end[];") == 1
        assert source.count("(uint64_t)(uintptr_t)_kernel_end") == 1
        source = source.replace("extern char _kernel_end[];", "static uintptr_t test_kernel_end;")
        source = source.replace("(uint64_t)(uintptr_t)_kernel_end", "test_kernel_end")
        path = Path(cls.tmp.name) / "pmm.c"
        path.write_text(PREFIX + source + SUFFIX)
        cls.binary = path.with_suffix("")
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-I", str(ROOT), str(path), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_physical_bases_and_lifetimes(self):
        for name in ("low", "high", "reservations", "holes", "dma-boundary",
                     "late-high", "late-low", "zero", "random"):
            with self.subTest(name=name):
                result = subprocess.run([str(self.binary), name], capture_output=True,
                                        text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_wrapping_metadata_refuses(self):
        for name in ("wrap-ram", "wrap-reserved"):
            with self.subTest(name=name):
                result = subprocess.run([str(self.binary), name], capture_output=True,
                                        text=True, timeout=5)
                self.assertEqual(result.returncode, 77)
                self.assertIn("wrapping", result.stderr)


if __name__ == "__main__":
    unittest.main()
