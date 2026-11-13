/* Bounded real-kernel memory checkpoint. The only admitted RAM is an arena
 * explicitly included in our loader's allocation, not a DTB candidate list. */
#include "kernel_memory.h"
#include "probe_console.h"
#include "qr_report.h"
#include "../arch.h"
#include "../arch_vmm.h"
#include "pmm.h"
#include "vmm.h"
#include "kva.h"
#include "printk.h"
#ifdef APPLE_TIMER_CHECKPOINT
#include "kernel_timer.h"
#endif

extern char apple_kernel_base[], apple_kernel_text_end[], apple_kernel_ro_end[], _kernel_end[];
extern volatile uint64_t apple_kernel_atomic_report[4];
extern int uaccess_selftest(void);

static struct apple_kernel_handoff boot;
static struct apple_boot_mapping mappings[5];
static unsigned mapping_count;
volatile struct apple_memory_report apple_memory_report;

static __attribute__((noreturn)) void fail(const char *why)
{
    probe_puts("MEMORY CHECKPOINT REFUSED\n");
    probe_puts(why);
    probe_puts("\nNO DEVICES OR USERLAND STARTED\n");
    apple_qr_progress("memory-refused", apple_kernel_atomic_report);
    __asm__ volatile("dsb sy" ::: "memory");
    apple_memory_report.stage = 255;
    for (;;) __asm__ volatile("wfe");
}

static int inside(uint64_t base, uint64_t size, uint64_t p, uint64_t n)
{
    return p >= base && n <= size && p - base <= size - n;
}

static int owned(uint64_t p, uint64_t n)
{
    return !(p & (PAGE_SIZE - 1)) && inside(boot.arena, boot.arena_size, p, n);
}

static void progress(const char *phase)
{
    apple_qr_memory[0] = boot.arena;
    apple_qr_memory[1] = boot.arena_size;
    apple_qr_memory[2] = apple_memory_report.stage >= 2 ? pmm_free_pages() : 0;
    apple_qr_memory[3] = apple_memory_report.ttbr1;
    apple_qr_progress(phase, apple_kernel_atomic_report);
}

static void mapping(uint64_t va, uint64_t pa, uint64_t size, uint64_t flags)
{
    if (!size || ((va | pa | size) & (PAGE_SIZE - 1)) ||
        size > UINT64_MAX - va || size > UINT64_MAX - pa ||
        va < 0xffff800000000000ULL ||
        mapping_count == 5 || flags & VMM_FLAG_USER)
        fail("INVALID OWNED MAPPING");
    mappings[mapping_count++] = (struct apple_boot_mapping){va, pa, size, flags};
}

void apple_memory_prepare(const struct apple_kernel_handoff *h)
{
    if (!h || mapping_count || apple_memory_report.stage)
        fail("MISSING OR REPEATED MEMORY HANDOFF");
    uint64_t size = (uintptr_t)_kernel_end - (uintptr_t)apple_kernel_base;
    if (h->magic != APPLE_KERNEL_HANDOFF_MAGIC ||
        h->kernel_size != size || h->loader_size > 24 * 1024 * 1024 ||
        !h->loader_phys || !h->loader_size || h->loader_phys >= (1ULL << 44) ||
        h->loader_size > (1ULL << 44) - h->loader_phys ||
        ((h->loader_phys | h->loader_size | h->kernel_phys) & (PAGE_SIZE - 1)) ||
        !inside(h->loader_phys, h->loader_size, h->kernel_phys, size) ||
        !inside(h->loader_phys, h->loader_size, h->arena, h->arena_size) ||
        h->arena < h->kernel_phys + size || h->arena_size != APPLE_BOOT_ARENA_SIZE ||
        (h->arena & (PAGE_SIZE - 1)) ||
        !h->fb.base || !h->fb.size || h->fb.size > 64 * 1024 * 1024 ||
        h->fb.base >= (1ULL << 44) || h->fb.size > (1ULL << 44) - h->fb.base ||
        (h->fb.base & 3) || !h->fb.width || !h->fb.height ||
        h->fb.width > 8192 || h->fb.height > 8192 || (h->fb.stride & 3) ||
        h->fb.stride < (uint64_t)h->fb.width * 4 ||
        (uint64_t)h->fb.stride * h->fb.height > h->fb.size ||
        (h->fb.format != FDT_FB_XRGB8888 && h->fb.format != FDT_FB_XRGB2101010) ||
        h->fb.size > UINT64_MAX - h->fb.base ||
        h->fb.base + h->fb.size > UINT64_MAX - (PAGE_SIZE - 1) ||
        (h->fb.base < h->loader_phys + h->loader_size &&
         h->loader_phys < h->fb.base + h->fb.size) ||
        (uintptr_t)_kernel_end >= ARCH_KVA_BASE)
        fail("INVALID LOADER-OWNED ARENA HANDOFF");
    boot = *h;
    arch_mm_init_apple(boot.kernel_phys, boot.arena, boot.arena_size);
    uint64_t base = (uintptr_t)apple_kernel_base;
    uint64_t text = (uintptr_t)apple_kernel_text_end;
    uint64_t ro = (uintptr_t)apple_kernel_ro_end;
    mapping(base, boot.kernel_phys, text - base, 0);
    mapping(text, boot.kernel_phys + text - base, ro - text, VMM_FLAG_NX);
    mapping(ro, boot.kernel_phys + ro - base, (uintptr_t)_kernel_end - ro,
            VMM_FLAG_WRITABLE | VMM_FLAG_NX);
    mapping((uintptr_t)arch_dmap(boot.arena), boot.arena, boot.arena_size,
            VMM_FLAG_WRITABLE | VMM_FLAG_NX);
    uint64_t fb = boot.fb.base & ~(PAGE_SIZE - 1);
    uint64_t end = (boot.fb.base + boot.fb.size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    mapping((uintptr_t)arch_dmap(fb), fb, end - fb,
            VMM_FLAG_WRITABLE | VMM_FLAG_NX | VMM_FLAG_UCMINUS);
    apple_memory_report.arena = boot.arena;
    apple_memory_report.arena_size = boot.arena_size;
    apple_memory_report.stage = 1;
    progress("memory-handoff");
}

const struct apple_boot_mapping *apple_memory_mappings(unsigned *count)
{
    if (mapping_count != 5) fail("MEMORY HANDOFF NOT PREPARED");
    *count = mapping_count;
    return mappings;
}

void apple_memory_vmm_ready(uint64_t root)
{
    if (!owned(root, PAGE_SIZE)) fail("NEW ROOT OUTSIDE OWNED ARENA");
    apple_memory_report.ttbr1 = root;
    progress("memory-vmm-switch");
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uint64_t line = 4ULL << ((ctr >> 16) & 15);
    if (line < 16 || line > 2048) fail("UNSUPPORTED CACHE LINE");
    /* New table pages were written through the WB identity arena. Publish
     * them to PoC as well as ordering their stores, so even a transitional
     * walk using the old NC walk policy sees complete table contents. */
    for (uint64_t off = 0; off < boot.arena_size; off += line)
        __asm__ volatile("dc civac, %0" : : "r"(boot.arena + off) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}

void apple_memory_rebase_console(void)
{
    probe_console_rebase((uintptr_t)arch_dmap(boot.fb.base));
}

static uint64_t leaf(uint64_t va)
{
    uint64_t table;
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(table));
    for (unsigned level = 0; level < 4; level++) {
        table = ARCH_PTE_ADDR(table);
        if (!owned(table, PAGE_SIZE)) fail("TABLE OUTSIDE OWNED ARENA");
        const uint64_t *p = arch_dmap(table);
        uint64_t descriptor = p[(va >> (39 - level * 9)) & 511];
        if ((descriptor & 3) != 3) fail("MISSING PAGE OR UNEXPECTED BLOCK");
        if (level == 3) return descriptor;
        table = descriptor;
    }
    fail("INVALID TABLE WALK");
}

static void attributes(uint64_t va, uint64_t pa, int ro, int nx, unsigned attr)
{
    uint64_t pte = leaf(va);
    if (ARCH_PTE_ADDR(pte) != pa || (pte & A64_PTE_USER) ||
        !(pte & A64_PTE_AF) || !(pte & A64_PTE_UXN) ||
        !!(pte & A64_PTE_RO) != ro || !!(pte & A64_PTE_PXN) != nx ||
        ((pte >> 2) & 7) != attr)
        fail("MAPPING PERMISSION OR MEMORY TYPE MISMATCH");
}

static uint64_t translate(uint64_t va, int write)
{
    uint64_t par;
    if (write)
        __asm__ volatile("at s1e1w, %1\nisb\nmrs %0, par_el1"
                         : "=r"(par) : "r"(va) : "memory");
    else
        __asm__ volatile("at s1e1r, %1\nisb\nmrs %0, par_el1"
                         : "=r"(par) : "r"(va) : "memory");
    return par;
}

static void pattern(volatile uint64_t *p, uint64_t salt)
{
    for (unsigned i = 0; i < PAGE_SIZE / 8; i++)
        p[i] = 0xa3615000c0ffee00ULL ^ salt ^ i;
    for (unsigned i = 0; i < PAGE_SIZE / 8; i++)
        if (p[i] != (0xa3615000c0ffee00ULL ^ salt ^ i))
            fail("PAGE WRITE READBACK MISMATCH");
}

__attribute__((noreturn))
void apple_memory_run(void)
{
    probe_console_reset();
    probe_puts("AEGIS - REAL KERNEL MEMORY CHECKPOINT\n");
    progress("memory-before-pmm");
    pmm_init();
    apple_memory_report.stage = 2;
    apple_memory_report.initial_free = pmm_free_pages();
    if (apple_memory_report.initial_free != boot.arena_size / PAGE_SIZE)
        fail("INITIAL FREE POOL DOES NOT MATCH OWNED ARENA");
    uint64_t frame = pmm_alloc_page();
    if (!owned(frame, PAGE_SIZE)) fail("PMM ALLOCATION OUTSIDE ARENA");
    apple_memory_report.test_phys = frame;
    pattern((volatile uint64_t *)(uintptr_t)frame, frame);
    pmm_free_page(frame);
    if (pmm_free_pages() != apple_memory_report.initial_free)
        fail("PMM RELEASE ACCOUNTING MISMATCH");
    apple_memory_report.checks |= 1;

    frame = pmm_alloc_page_low();
    if (boot.arena >= (1ULL << 32)) {
        if (frame || pmm_alloc_contig_low(2)) fail("FABRICATED LOW DMA MEMORY");
    } else {
        if (!owned(frame, PAGE_SIZE) || frame >= (1ULL << 32))
            fail("LOW DMA ADDRESS VIOLATION");
        pmm_free_page(frame);
    }
    if (pmm_free_pages() != apple_memory_report.initial_free)
        fail("DMA PROBE CHANGED FREE COUNT");
    apple_memory_report.checks |= 16;
    progress("memory-before-vmm");
    vmm_init();
    apple_memory_report.stage = 3;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(apple_memory_report.ttbr0));
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(apple_memory_report.ttbr1));
    __asm__ volatile("mrs %0, mair_el1" : "=r"(apple_memory_report.mair));
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(apple_memory_report.tcr));
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(apple_memory_report.sctlr));
    __asm__ volatile("mrs %0, daif" : "=r"(apple_memory_report.daif));
    uint64_t walks = (1ULL << 8) | (1ULL << 10) | (3ULL << 12) |
                     (1ULL << 24) | (1ULL << 26) | (3ULL << 28);
    uint64_t walk_mask = (15ULL << 8) | (3ULL << 12) | (15ULL << 24) | (3ULL << 28);
    if (apple_memory_report.mair != 0xff0044 ||
        (apple_memory_report.tcr & walk_mask) != walks ||
        (apple_memory_report.sctlr & 0x1005) != 5 ||
        (apple_memory_report.daif & 0x3c0) != 0x3c0)
        fail("VMM MEMORY TYPE OR CPU STATE MISMATCH");
    if (!owned(apple_memory_report.ttbr0, PAGE_SIZE) ||
        !owned(apple_memory_report.ttbr1, PAGE_SIZE))
        fail("VMM ROOT OWNERSHIP MISMATCH");
    const uint64_t *empty = arch_dmap(apple_memory_report.ttbr0);
    for (unsigned i = 0; i < 512; i++)
        if (empty[i]) fail("IDENTITY OR USER MAPPINGS SURVIVED");
    if (!(translate(0, 0) & 1) || !(translate(boot.arena, 0) & 1) ||
        !(translate((uintptr_t)arch_dmap(boot.loader_phys), 0) & 1) ||
        !(translate((uintptr_t)apple_kernel_base, 1) & 1))
        fail("UNEXPECTED LOW, FOREIGN OR WRITABLE CODE MAPPING");
    for (unsigned i = 0; i < mapping_count; i++) {
        const struct apple_boot_mapping *m = &mappings[i];
        attributes(m->va, m->pa, !(m->flags & VMM_FLAG_WRITABLE),
                   !!(m->flags & VMM_FLAG_NX),
                   m->flags & VMM_FLAG_UCMINUS ? A64_ATTR_DEVICE : A64_ATTR_NORMAL_WB);
    }
    if (!uaccess_selftest()) fail("UACCESS FAILED AFTER VMM HANDOVER");
    apple_memory_report.checks |= 2;
    progress("memory-vmm-live");
    kva_init();
    pmm_init_late();
    pmm_set_alloc_high_pref(1);
    arch_set_master_pml4(vmm_get_master_pml4());
    /* Warm permanent page-table metadata before testing frame accounting. */
    void *warm = kva_alloc_pages(1);
    if (!warm) fail("KVA WARMUP FAILED");
    kva_free_pages(warm, 1);
    apple_memory_report.stage = 4;
    apple_memory_report.baseline_free = pmm_free_pages();
    progress("memory-before-kva-test");
    void *pages = kva_alloc_pages(3);
    if (!pages) fail("KVA ALLOCATION FAILED");
    apple_memory_report.test_va = (uintptr_t)pages;
    for (unsigned i = 0; i < 3; i++) {
        uint64_t va = (uintptr_t)pages + i * PAGE_SIZE;
        uint64_t pa = kva_page_phys((void *)(uintptr_t)va);
        if (!owned(pa, PAGE_SIZE)) fail("KVA FRAME OUTSIDE ARENA");
        attributes(va, pa, 0, 1, A64_ATTR_NORMAL_WB);
        pattern((volatile uint64_t *)(uintptr_t)va, pa);
    }
    apple_memory_report.checks |= 4;
    kva_free_pages(pages, 3);
    if (pmm_free_pages() != apple_memory_report.baseline_free)
        fail("KVA RELEASE ACCOUNTING MISMATCH");
    pages = kva_alloc_pages(3);
    if (!pages) fail("KVA REALLOCATION FAILED");
    for (unsigned i = 0; i < 3; i++)
        pattern((volatile uint64_t *)pages + i * (PAGE_SIZE / 8), i);
    kva_free_pages(pages, 3);
    apple_memory_report.final_free = pmm_free_pages();
    if (apple_memory_report.final_free != apple_memory_report.baseline_free)
        fail("REALLOCATION RELEASE ACCOUNTING MISMATCH");
    apple_memory_report.checks |= 8;
    printk("[APPLE] MEMORY CHECKPOINT: existing PMM/VMM/KVA passed\n");
    printk("[APPLE] OWNED ARENA ONLY: no firmware reclaim, IRQs or devices\n");
#ifdef APPLE_TIMER_CHECKPOINT
    printk("[APPLE] MEMORY COMPLETE - NEXT: TIMER FIQ RETURN TEST\n");
#else
    printk("[APPLE] HALTED - MEMORY CHECKPOINT COMPLETE\n");
#endif
    progress("memory-complete");
    __asm__ volatile("dsb sy" ::: "memory");
    apple_memory_report.stage = 5;
#ifdef APPLE_TIMER_CHECKPOINT
    apple_timer_run();
#endif
    for (;;) __asm__ volatile("wfe");
}
