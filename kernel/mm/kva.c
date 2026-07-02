#include "kva.h"
#include "vmm.h"
#include "pmm.h"
#include "printk.h"
#include "arch.h"
#include "spinlock.h"
#include "tlb.h"
#include "fb.h"
#include "../lib/va_freelist.h"
#include <stdint.h>
#include <stddef.h>

/* KVA_BASE: start of the bump-allocated kernel VA range.
 * Each architecture defines ARCH_KVA_BASE in arch.h to place this past
 * the kernel image, window allocator, and any other fixed-VA regions.
 * x86-64: pd_hi[5] = VIRT_BASE + 0xA00000  (window moved to pd_hi[4]; kernel
 *         image now occupies pd_hi[0..3] = 8MB)
 * ARM64:  L2[5]    = VIRT_BASE + 0xA00000 */
#ifdef ARCH_KVA_BASE
#define KVA_BASE ARCH_KVA_BASE
#else
#define KVA_BASE (ARCH_KERNEL_VIRT_BASE + 0xA00000UL)
#endif

static uint64_t s_kva_next;
static spinlock_t kva_lock = SPINLOCK_INIT;

/* ---- VA freelist: recycle freed kva ranges ----
 * Best-fit search over a fixed-size array, now backed by the shared
 * coalescing allocator in kernel/lib/va_freelist.{h,c} (the same primitive
 * the mmap VA freelist uses). Freed VA ranges are inserted; kva_alloc_pages
 * checks the freelist before bumping s_kva_next. Adjacent entries are
 * coalesced on insert, and a full-but-uncoalescable insert now WARNs instead
 * of silently leaking.
 *
 * UNIT NOTE: va_freelist is unit-agnostic but treats base and len in the SAME
 * unit (its coalesce/carve do `base + len` and `base += want`). The KVA range
 * is {byte VA, page count}, a MIXED unit, so we store and operate in PAGE units
 * end to end: the backing array's `base` field holds a PAGE NUMBER (va >> 12),
 * `len` holds npages. The freelist_alloc/insert wrappers convert at the byte<->
 * page boundary (every kva VA is page-aligned — s_kva_next only ever advances by
 * n*4096 — so `>> 12` is exact). This is why the spec's "cast s_free directly,
 * base=va bytes" shortcut would be WRONG: byte base + page len mixes units. */
#define KVA_FREE_MAX 128

typedef struct {
    uint64_t va;       /* page number (byte VA >> 12), per the UNIT NOTE above */
    uint64_t npages;
} kva_free_t;

_Static_assert(sizeof(kva_free_t) == sizeof(va_region_t),
               "kva_free_t must alias va_region_t for the freelist view cast");

static kva_free_t s_free[KVA_FREE_MAX];
static int        s_nfree;

void
kva_init(void)
{
    s_kva_next = KVA_BASE;
    s_nfree = 0;
    lockrank_register(&kva_lock, LOCK_RANK_KVA);   /* debug lock-order check */
    printk("[KVA] OK: kernel virtual allocator active\n");
}

/* Try to allocate from the freelist.  Returns byte VA or 0 on miss.
 * Operates in PAGE units (see UNIT NOTE): the view's base is a page number;
 * convert the returned page number back to a byte VA. */
static uint64_t
freelist_alloc(uint64_t n)
{
    va_freelist_t fl = { (va_region_t *)s_free, KVA_FREE_MAX, (uint32_t)s_nfree };
    uint64_t base_page;
    bool ok = va_freelist_alloc(&fl, n, &base_page);
    s_nfree = (int)fl.count;
    return ok ? (base_page << 12) : 0;
}

/* Insert a freed range, coalescing with neighbors.  `va` is a byte VA, `n` a
 * page count; store as {page number, npages} (see UNIT NOTE). */
static void
freelist_insert(uint64_t va, uint64_t n)
{
    va_freelist_t fl = { (va_region_t *)s_free, KVA_FREE_MAX, (uint32_t)s_nfree };
    va_freelist_insert(&fl, va >> 12, n);   /* WARN-on-overflow now inside */
    s_nfree = (int)fl.count;
}

void *
kva_alloc_pages(uint64_t n)
{
    if (n == 0) return NULL;

    /* Try freelist first (under kva_lock), fall back to bump. */
    irqflags_t fl = spin_lock_irqsave(&kva_lock);
    uint64_t base = freelist_alloc(n);
    if (!base) {
        base = s_kva_next;
        s_kva_next += n * 4096UL;
    }
    spin_unlock_irqrestore(&kva_lock, fl);

    uint64_t i;
    for (i = 0; i < n; i++) {
        uint64_t phys = pmm_alloc_page();
        if (!phys) {
            printk("[KVA] FAIL: PMM exhausted (kva_next=0x%x, free=%u)\n",
                   (unsigned)(base >> 12), (unsigned)pmm_free_pages());
            panic_halt("[KVA] FAIL: out of memory");
        }
        vmm_map_page(base + i * 4096UL, phys, VMM_FLAG_WRITABLE);
    }
    return (void *)base;
}

void *
kva_alloc_pages_low(uint64_t n)
{
    if (n == 0) return NULL;

    /* Try freelist first (under kva_lock), fall back to bump. */
    irqflags_t fl = spin_lock_irqsave(&kva_lock);
    uint64_t base = freelist_alloc(n);
    if (!base) {
        base = s_kva_next;
        s_kva_next += n * 4096UL;
    }
    spin_unlock_irqrestore(&kva_lock, fl);

    for (uint64_t i = 0; i < n; i++) {
        uint64_t phys = pmm_alloc_page_low();   /* guaranteed < 4GB (DMA-safe) */
        if (!phys) {
            /* Low (<4GB) pool exhausted. Unlike kva_alloc_pages this does NOT
             * panic — DMA callers handle NULL (a device simply fails to init).
             * Fully unwind: unmap + free the pages mapped so far, then return
             * the reserved VA range [base, base+n) to the freelist so a partial
             * failure leaks nothing and the allocator stays consistent.
             *
             * Pages [0, i) were all mapped by earlier iterations of this loop;
             * vmm_map_page panics on its own failure (never returns), so every
             * one is present and vmm_phys_of cannot fault here.
             *
             * Lock order: vmm_window_lock > pmm_lock > kva_lock (canonical).
             * The unmap/free loop takes vmm_window_lock and pmm_lock; the
             * freelist insert takes kva_lock. They must NOT nest, so the
             * freelist_insert runs AFTER the loop with no other lock held —
             * identical to the kva_free_pages discipline below. */
            for (uint64_t j = 0; j < i; j++) {
                uint64_t p = vmm_phys_of(base + j * 4096UL);
                vmm_unmap_page(base + j * 4096UL);
                if (p) pmm_free_page(p);
            }
            irqflags_t ufl = spin_lock_irqsave(&kva_lock);
            freelist_insert(base, n);
            spin_unlock_irqrestore(&kva_lock, ufl);
            return NULL;
        }
        vmm_map_page(base + i * 4096UL, phys, VMM_FLAG_WRITABLE);
    }
    return (void *)base;
}

void *
kva_map_phys_pages(uint64_t phys_base, uint32_t num_pages)
{
    if (num_pages == 0) return NULL;

    irqflags_t fl = spin_lock_irqsave(&kva_lock);
    uint64_t base = s_kva_next;
    s_kva_next += (uint64_t)num_pages * 4096UL;
    spin_unlock_irqrestore(&kva_lock, fl);

    uint32_t i;
    for (i = 0; i < num_pages; i++) {
        vmm_map_page(base + (uint64_t)i * 4096UL,
                     phys_base + (uint64_t)i * 4096UL,
                     VMM_FLAG_WRITABLE);
    }
    return (void *)base;
}

void *
kva_map_mmio(uint64_t phys_base, uint32_t num_pages)
{
    if (num_pages == 0) return NULL;

    irqflags_t fl = spin_lock_irqsave(&kva_lock);
    uint64_t base = s_kva_next;
    s_kva_next += (uint64_t)num_pages * 4096UL;
    spin_unlock_irqrestore(&kva_lock, fl);

    /* Map the device BAR directly into fresh KVA as uncached MMIO
     * (WC|UC-). Unlike the old per-driver map_mmio(), this never allocates
     * a real frame first, so there is no "unmap the present mapping then
     * remap to the BAR" dance (vmm_map_page panics on a double-map) — the
     * VA is virgin, mapped straight to phys. */
    uint32_t i;
    for (i = 0; i < num_pages; i++) {
        vmm_map_page(base + (uint64_t)i * 4096UL,
                     phys_base + (uint64_t)i * 4096UL,
                     VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS);
    }
    return (void *)base;
}

uint64_t
kva_page_phys(void *va)
{
    return vmm_phys_of((uint64_t)(uintptr_t)va);
}

void
kva_free_pages(void *va, uint64_t n)
{
    uint64_t addr = (uint64_t)(uintptr_t)va;
    uint64_t i;
    /* Clear all PTEs first, then ONE ranged cross-CPU shootdown — the old
     * per-page vmm_unmap_page broadcast an IPI + ack spin per page, so a
     * 14-page task teardown cost 14 shootdowns. */
    for (i = 0; i < n; i++) {
        uint64_t page_va = addr + i * 4096UL;
        uint64_t phys    = vmm_phys_of(page_va);
        vmm_unmap_page_noshoot(page_va);
        pmm_free_page(phys);
    }
    tlb_shootdown_kernel(addr, addr + n * 4096UL);

    /* Return VA range to freelist for reuse */
    irqflags_t fl = spin_lock_irqsave(&kva_lock);
    freelist_insert(addr, n);
    spin_unlock_irqrestore(&kva_lock, fl);
}

void
kva_unmap_keep_frames(void *va, uint64_t n)
{
    uint64_t addr = (uint64_t)(uintptr_t)va;
    uint64_t i;
    /* Clear the kva PTEs but DO NOT pmm_free_page — the frames' ownership has
     * been transferred to another mapping (see the header).  Batch the
     * cross-CPU shootdown into one ranged call, as in kva_free_pages. */
    for (i = 0; i < n; i++)
        vmm_unmap_page_noshoot(addr + i * 4096UL);
    tlb_shootdown_kernel(addr, addr + n * 4096UL);

    /* Reclaim the VA range for reuse. */
    irqflags_t fl = spin_lock_irqsave(&kva_lock);
    freelist_insert(addr, n);
    spin_unlock_irqrestore(&kva_lock, fl);
}
