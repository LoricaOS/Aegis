/*
 * kernel/arch/arm64/vmm.c — ARM64 virtual memory manager.
 *
 * Implements the arch-neutral vmm.h interface (same contract as
 * kernel/mm/vmm.c on x86-64) for aarch64 stage-1 4K-granule paging.
 *
 * Design differences from the x86 implementation:
 *
 *  - Kernel mappings live in TTBR1 (built here, once); user address spaces
 *    are standalone TTBR0 tables. There is no "copy kernel half into every
 *    user table" step: vmm_create_user_pml4 returns an EMPTY table, and
 *    the user walks cover table indices for VAs < 2^48 (user half only).
 *
 *  - Instead of the x86 identity map + single-PTE mapped window, ALL of
 *    physical RAM (plus the QEMU-virt device window) is permanently
 *    direct-mapped at ARCH_DMAP_BASE in TTBR1. vmm_window_map(phys) is
 *    just arch_dmap(phys); unmap is a no-op. This removes the window
 *    lock's map/invlpg churn wholesale.
 *
 *  - FLAG CONTRACT: every vmm.h entry point speaks the abstract
 *    VMM_FLAG_* encoding. Hardware descriptors never escape this file —
 *    query functions reverse-translate via arch_pte_to_flags().
 *
 * The COW/fork/teardown semantics (SHARED exemption, COW+WRITABLE never
 * coexisting, refcount discipline) are ported 1:1 from the x86 vmm.c —
 * they are the security model's memory-side invariants.
 */

#ifndef __aarch64__
#error "kernel/arch/arm64/vmm.c is aarch64 only"
#endif

#include "vmm.h"
#include "arch.h"
#include "arch_vmm.h"
#include "pmm.h"
#include "printk.h"
#include "spinlock.h"
#include "fb.h"       /* panic_halt lives here */
#include "sched.h"
#include "proc.h"
#include <stdint.h>
#include <stddef.h>

#define VMM_PAGE_SIZE   AEGIS_PAGE_SIZE
#define VMM_PAGE_MASK   (~(VMM_PAGE_SIZE - 1))

/* Table descriptor (levels 0-2 pointing at a next-level table). */
#define A64_TABLE (3UL)                 /* valid | table */
/* Block descriptor bits (level 1 = 1GB, level 2 = 2MB). */
#define A64_BLOCK_NORMAL (A64_PTE_VALID | A64_PTE_AF | A64_PTE_SH_IS | \
                          A64_PTE_ATTR(A64_ATTR_NORMAL_WB) | A64_PTE_UXN)
#define A64_BLOCK_DEVICE (A64_PTE_VALID | A64_PTE_AF | \
                          A64_PTE_ATTR(A64_ATTR_DEVICE) | \
                          A64_PTE_UXN | A64_PTE_PXN)

static uint64_t s_ttbr1_phys;     /* kernel table root (never switched)   */
static uint64_t s_empty_user;     /* the "master" TTBR0: an empty table   */

/* One lock serializes all PTE mutations (the x86 vmm_window_lock role). */
static spinlock_t vmm_lock = SPINLOCK_INIT;

/* Early phys→virt: bootloader HHDM until our TTBR1 is live, DMAP after. */
static int s_dmap_live = 0;
static inline uint64_t *
pv(uint64_t phys)
{
    if (s_dmap_live)
        return (uint64_t *)arch_dmap(phys);
    return (uint64_t *)(uintptr_t)(phys + arch_early_pv_off());
}

static uint64_t
alloc_table(void)
{
    uint64_t phys = pmm_alloc_page();
    if (phys == 0)
        return 0;
    uint64_t *t = pv(phys);
    for (int i = 0; i < 512; i++)
        t[i] = 0;
    return phys;
}

static uint64_t
alloc_table_or_panic(void)
{
    uint64_t phys = alloc_table();
    if (phys == 0) {
        printk("[VMM] FAIL: out of memory allocating page table\n");
        panic_halt("[VMM] FAIL: out of memory allocating page table");
    }
    return phys;
}

/* ensure_table — walk one level down from table_phys[idx], allocating a
 * child table if absent. Returns the child's physical address (0 on OOM).
 * ARM64 has no per-level USER bit (table descriptors don't gate EL0
 * access the way x86's USER bit does), so no extra_flags parameter. */
static uint64_t
ensure_table(uint64_t table_phys, uint64_t idx)
{
    uint64_t *t = pv(table_phys);
    uint64_t  e = t[idx];
    if (!(e & A64_PTE_VALID)) {
        uint64_t child = alloc_table();
        if (child == 0)
            return 0;
        t[idx] = child | A64_TABLE;
        /* This table is already live (root_phys may be s_ttbr1_phys, in use
         * by other cores/paths) — without this, a table walk started right
         * after we return can race the write and see a stale invalid entry.
         * TCG's in-order model never exposed this; real hardware (HVF, and
         * Cortex cores on target boards) does. */
        __asm__ volatile("dsb ishst" ::: "memory");
        return child;
    }
    return ARCH_PTE_ADDR(e);
}

/* walk_to_pte — return a pointer (via DMAP) to the level-3 PTE for va in
 * root_phys, or NULL if any level is absent. No allocation. */
static uint64_t *
walk_to_pte(uint64_t root_phys, uint64_t va)
{
    uint64_t l0i = (va >> 39) & 0x1FF;
    uint64_t l1i = (va >> 30) & 0x1FF;
    uint64_t l2i = (va >> 21) & 0x1FF;
    uint64_t l3i = (va >> 12) & 0x1FF;

    uint64_t *l0 = pv(root_phys);
    if (!(l0[l0i] & A64_PTE_VALID)) return NULL;
    uint64_t *l1 = pv(ARCH_PTE_ADDR(l0[l0i]));
    if (!(l1[l1i] & A64_PTE_VALID)) return NULL;
    if (!(l1[l1i] & A64_PTE_PAGE))  return NULL;   /* 1GB block — no L3 PTE */
    uint64_t *l2 = pv(ARCH_PTE_ADDR(l1[l1i]));
    if (!(l2[l2i] & A64_PTE_VALID)) return NULL;
    if (!(l2[l2i] & A64_PTE_PAGE))  return NULL;   /* 2MB block */
    uint64_t *l3 = pv(ARCH_PTE_ADDR(l2[l2i]));
    return &l3[l3i];
}

/* map_page_in — install a 4K mapping for va→phys in root_phys.
 * flags are ABSTRACT. Returns 0 ok, -1 OOM, 1 already-present (when
 * tolerate_present). Caller holds vmm_lock. */
static int
map_page_in(uint64_t root_phys, uint64_t va, uint64_t phys,
            uint64_t flags, int tolerate_present)
{
    uint64_t l1p = ensure_table(root_phys, (va >> 39) & 0x1FF);
    if (!l1p) return -1;
    uint64_t l2p = ensure_table(l1p, (va >> 30) & 0x1FF);
    if (!l2p) return -1;
    uint64_t l3p = ensure_table(l2p, (va >> 21) & 0x1FF);
    if (!l3p) return -1;

    uint64_t *l3 = pv(l3p);
    uint64_t  i  = (va >> 12) & 0x1FF;
    if (l3[i] & A64_PTE_VALID) {
        if (tolerate_present)
            return 1;
        printk("[VMM] FAIL: double-map va=0x%lx\n", va);
        panic_halt("[VMM] FAIL: vmm map double-map");
    }
    l3[i] = phys | arch_pte_from_flags(flags | VMM_FLAG_PRESENT);
    /* Same reasoning as ensure_table: this leaf may be used (by this core
     * or another) the instant we return, so the write must be ordered
     * before any subsequent access through it — a fresh valid entry needs
     * no TLBI (nothing stale to invalidate), just this store barrier. */
    __asm__ volatile("dsb ishst" ::: "memory");
    return 0;
}

/* ── Bootstrap ─────────────────────────────────────────────────────────── */

extern char _kernel_end[];

void
vmm_init(void)
{
    lockrank_register(&vmm_lock, LOCK_RANK_VMM);

    uint64_t slide = arch_kern_phys_slide();
    uint64_t root  = alloc_table_or_panic();

    /* 1. Kernel image: KERN_VMA+PHYS_BASE .. _kernel_end → slide'd phys,
     *    4K pages (Limine guarantees contiguity, not 2MB alignment).
     *    Kernel RWX per page table (W^X refinement is a follow-up; the
     *    image was mapped rwx by boot.asm's huge pages on x86 too). */
    {
        uint64_t va  = ARCH_KERNEL_VIRT_BASE + ARCH_KERNEL_PHYS_BASE;
        uint64_t end = ((uint64_t)(uintptr_t)_kernel_end + 0xFFF) & ~0xFFFUL;
        for (; va < end; va += 4096) {
            uint64_t pa = va - ARCH_KERNEL_VIRT_BASE + slide;
            uint64_t l1p = ensure_table(root, (va >> 39) & 0x1FF);
            uint64_t l2p = ensure_table(l1p, (va >> 30) & 0x1FF);
            uint64_t l3p = ensure_table(l2p, (va >> 21) & 0x1FF);
            if (!l1p || !l2p || !l3p)
                panic_halt("[VMM] FAIL: OOM mapping kernel image");
            uint64_t *l3 = pv(l3p);
            /* valid | page | AF | SH | WB | writable | EL1-only | UXN,
             * PXN clear (kernel text executes from here). */
            l3[(va >> 12) & 0x1FF] = pa | A64_PTE_VALID | A64_PTE_PAGE |
                A64_PTE_AF | A64_PTE_SH_IS |
                A64_PTE_ATTR(A64_ATTR_NORMAL_WB) | A64_PTE_UXN;
        }
    }

    /* 2. Device window: PA [0 .. 1GB) → DMAP_BASE, one 1GB Device block.
     *    Covers the QEMU-virt MMIO space (GICv3 0x080xxxxx, PL011
     *    0x09000000, RTC/fw-cfg/virtio-mmio, ...). */
    {
        uint64_t va  = ARCH_DMAP_BASE;
        uint64_t l1p = ensure_table(root, (va >> 39) & 0x1FF);
        if (!l1p) panic_halt("[VMM] FAIL: OOM mapping device window");
        uint64_t *l1 = pv(l1p);
        l1[(va >> 30) & 0x1FF] = 0UL | A64_BLOCK_DEVICE;
    }

    /* 3. RAM direct map: every usable/reserved-RAM region (incl. the
     *    kernel image and boot modules) → DMAP_BASE + PA, 2MB Normal-WB
     *    blocks. Ranges round out to 2MB; overshoot maps at most 2MB of
     *    hole past the end of RAM (benign on QEMU virt: nothing lives
     *    between RAM-end and the high PCIe window). */
    {
        uint32_t n = arch_mm_region_count();
        const aegis_mem_region_t *r = arch_mm_get_regions();
        uint32_t nr = arch_mm_reserved_region_count();
        const aegis_mem_region_t *rr = arch_mm_get_reserved_regions();
        uint64_t lo = ~0UL, hi = 0;
        for (uint32_t i = 0; i < n; i++) {
            if (r[i].len == 0) continue;
            if (r[i].base < lo) lo = r[i].base;
            if (r[i].base + r[i].len > hi) hi = r[i].base + r[i].len;
        }
        for (uint32_t i = 0; i < nr; i++) {   /* kernel image + modules */
            if (rr[i].len == 0) continue;
            if (rr[i].base < lo) lo = rr[i].base;
            if (rr[i].base + rr[i].len > hi) hi = rr[i].base + rr[i].len;
        }
        if (lo == ~0UL)
            panic_halt("[VMM] FAIL: no RAM regions");
        lo &= ~0x1FFFFFUL;
        hi  = (hi + 0x1FFFFF) & ~0x1FFFFFUL;
        for (uint64_t pa = lo; pa < hi; pa += 0x200000UL) {
            uint64_t va  = ARCH_DMAP_BASE + pa;
            uint64_t l1p = ensure_table(root, (va >> 39) & 0x1FF);
            uint64_t l2p = ensure_table(l1p, (va >> 30) & 0x1FF);
            if (!l1p || !l2p)
                panic_halt("[VMM] FAIL: OOM mapping direct map");
            uint64_t *l2 = pv(l2p);
            l2[(va >> 21) & 0x1FF] = pa | A64_BLOCK_NORMAL;
        }
    }

    /* 4. Empty user table — the "master pml4" loaded while no user task
     *    runs (fail closed: kernel-only context has NO user mappings). */
    s_empty_user = alloc_table_or_panic();

    /* 5. Go live: load TTBR1, nuke every stale entry. TTBR0 is left on
     * start.c's early device idmap — the PL011 printks below still go
     * through it (main.c repoints serial at the DMAP right after we
     * return, and the first vmm_switch_to replaces TTBR0 for good). */
    s_ttbr1_phys = root;
    __asm__ volatile(
        "msr ttbr1_el1, %0\n\t"
        "dsb ish\n\t"
        "tlbi vmalle1\n\t"
        "dsb ish\n\t"
        "isb"
        : : "r"(root) : "memory");
    s_dmap_live = 1;

    printk("[VMM] OK: kernel mapped to 0xFFFFFFFF80000000\n");
    printk("[VMM] OK: mapped-window allocator active\n");
}

/* ── Kernel (TTBR1) mappings — kva backend ─────────────────────────────── */

void
vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags)
{
    if ((virt & ~VMM_PAGE_MASK) || (phys & ~VMM_PAGE_MASK))
        panic_halt("[VMM] FAIL: vmm_map_page misaligned");

    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    int r = map_page_in(s_ttbr1_phys, virt, phys, flags, 0);
    spin_unlock_irqrestore(&vmm_lock, fl);
    if (r < 0)
        panic_halt("[VMM] FAIL: out of memory in vmm_map_page");
}

void
vmm_unmap_page(uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *pte = walk_to_pte(s_ttbr1_phys, virt);
    if (!pte || !(*pte & A64_PTE_VALID)) {
        spin_unlock_irqrestore(&vmm_lock, fl);
        panic_halt("[VMM] FAIL: vmm_unmap_page not mapped");
    }
    *pte = 0;
    arch_vmm_invlpg(virt);
    spin_unlock_irqrestore(&vmm_lock, fl);
}

/* On arm64 the TLBI in vmm_unmap_page is already inner-shareable (broadcast
 * to all cores in hardware) — there is no per-page IPI to batch away. */
void
vmm_unmap_page_noshoot(uint64_t virt)
{
    vmm_unmap_page(virt);
}

uint64_t
vmm_phys_of(uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *pte = walk_to_pte(s_ttbr1_phys, virt);
    if (!pte || !(*pte & A64_PTE_VALID)) {
        spin_unlock_irqrestore(&vmm_lock, fl);
        panic_halt("[VMM] FAIL: vmm_phys_of not mapped");
    }
    uint64_t pa = ARCH_PTE_ADDR(*pte);
    spin_unlock_irqrestore(&vmm_lock, fl);
    return pa;
}

void
vmm_teardown_identity(void)
{
    /* Nothing to tear down: there is no boot identity map (the early
     * TTBR0 device idmap was replaced by the empty user table when
     * vmm_init went live). Keep the x86 boot-oracle line. */
    printk("[VMM] OK: identity map removed\n");
}

void
vmm_switch_to(uint64_t pml4_phys)
{
    arch_vmm_load_pml4(pml4_phys);
}

uint64_t
vmm_get_master_pml4(void)
{
    return s_empty_user;
}

/* ── User (TTBR0) address spaces ───────────────────────────────────────── */

uint64_t
vmm_create_user_pml4(void)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t p = alloc_table();
    spin_unlock_irqrestore(&vmm_lock, fl);
    return p;   /* empty: kernel lives in TTBR1, nothing to copy */
}

void
vmm_map_user_page(uint64_t pml4_phys, uint64_t virt,
                  uint64_t phys, uint64_t flags)
{
    if ((virt & ~VMM_PAGE_MASK) || (phys & ~VMM_PAGE_MASK))
        panic_halt("[VMM] FAIL: vmm_map_user_page misaligned");

    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    int r = map_page_in(pml4_phys, virt, phys, flags, 0);
    spin_unlock_irqrestore(&vmm_lock, fl);
    if (r < 0)
        panic_halt("[VMM] FAIL: out of memory in vmm_map_user_page");
}

int
vmm_try_map_user_page(uint64_t pml4_phys, uint64_t virt,
                      uint64_t phys, uint64_t flags)
{
    if ((virt & ~VMM_PAGE_MASK) || (phys & ~VMM_PAGE_MASK))
        panic_halt("[VMM] FAIL: vmm_try_map_user_page misaligned");

    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    int r = map_page_in(pml4_phys, virt, phys, flags, 1);
    spin_unlock_irqrestore(&vmm_lock, fl);
    return r;
}

uint64_t
vmm_phys_of_user(uint64_t pml4_phys, uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *pte = walk_to_pte(pml4_phys, virt);
    uint64_t pa = (pte && (*pte & A64_PTE_VALID)) ? ARCH_PTE_ADDR(*pte) : 0;
    spin_unlock_irqrestore(&vmm_lock, fl);
    return pa;
}

int
vmm_user_range_mapped(uint64_t pml4_phys, uint64_t addr, uint64_t len)
{
    if (len == 0)
        return 1;
    uint64_t va   = addr & ~0xFFFULL;
    uint64_t last = (addr + len - 1) & ~0xFFFULL;
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    for (;;) {
        uint64_t *pte = walk_to_pte(pml4_phys, va);
        if (!pte || !(*pte & A64_PTE_VALID)) {
            spin_unlock_irqrestore(&vmm_lock, fl);
            return 0;
        }
        if (va == last)
            break;
        va += 4096;
    }
    spin_unlock_irqrestore(&vmm_lock, fl);
    return 1;
}

uint64_t
vmm_phys_of_user_raw(uint64_t pml4_phys, uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *pte = walk_to_pte(pml4_phys, virt);
    uint64_t pa = (pte && *pte) ? ARCH_PTE_ADDR(*pte) : 0;
    spin_unlock_irqrestore(&vmm_lock, fl);
    return pa;
}

uint64_t
vmm_pte_of_user_raw(uint64_t pml4_phys, uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *pte = walk_to_pte(pml4_phys, virt);
    uint64_t hw = pte ? *pte : 0;
    spin_unlock_irqrestore(&vmm_lock, fl);
    /* Boundary contract: return the ABSTRACT form (callers test
     * VMM_FLAG_SHARED etc. against this). */
    return hw ? arch_pte_to_flags(hw) : 0;
}

void
vmm_unmap_user_page(uint64_t pml4_phys, uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *pte = walk_to_pte(pml4_phys, virt);
    if (pte && *pte) {
        *pte = 0;
        arch_vmm_invlpg(virt);
    }
    spin_unlock_irqrestore(&vmm_lock, fl);
}

int
vmm_set_user_prot(uint64_t pml4_phys, uint64_t virt, uint64_t flags)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *pte = walk_to_pte(pml4_phys, virt);
    if (!pte) {
        spin_unlock_irqrestore(&vmm_lock, fl);
        return -1;
    }
    uint64_t old = *pte;

    if (!(old & A64_PTE_VALID) && flags == 0) {
        spin_unlock_irqrestore(&vmm_lock, fl);
        return 0;   /* PROT_NONE on unmapped page is a no-op */
    }

    uint64_t phys   = ARCH_PTE_ADDR(old);
    uint64_t old_sw = old & (A64_PTE_SW_COW | A64_PTE_SW_SHARED);

    if (!(old & A64_PTE_VALID)) {
        /* PROT_NONE-stored page: phys retained with VALID clear. */
        if (!phys) {
            spin_unlock_irqrestore(&vmm_lock, fl);
            return -1;
        }
        uint64_t newpte = phys | arch_pte_from_flags(flags) | old_sw;
        /* COW+writable must never coexist: keep COW pages read-only so
         * the first write still faults into vmm_cow_fault_handle. */
        if ((old_sw & A64_PTE_SW_COW) && (flags & VMM_FLAG_WRITABLE))
            newpte |= A64_PTE_RO;
        *pte = newpte;
        arch_vmm_invlpg(virt);
        spin_unlock_irqrestore(&vmm_lock, fl);
        return 0;
    }

    if (flags == 0) {
        /* PROT_NONE: keep phys + software bits, clear VALID. */
        *pte = phys | old_sw;
    } else {
        uint64_t newpte = phys | arch_pte_from_flags(flags) | old_sw;
        if ((old_sw & A64_PTE_SW_COW) && (flags & VMM_FLAG_WRITABLE))
            newpte |= A64_PTE_RO;
        *pte = newpte;
    }
    arch_vmm_invlpg(virt);
    spin_unlock_irqrestore(&vmm_lock, fl);
    return 0;
}

/* ── Physical page helpers (window equivalents) ────────────────────────── */

void *
vmm_window_map(uint64_t phys)
{
    return arch_dmap(phys);
}

void
vmm_window_unmap(void)
{
}

void
vmm_zero_page(uint64_t phys)
{
    __builtin_memset(arch_dmap(phys), 0, 4096);
}

void
vmm_write_phys_bytes(uint64_t phys, uint32_t off, const void *src, uint32_t len)
{
    if ((uint64_t)off + len > 4096)
        return;
    __builtin_memcpy((uint8_t *)arch_dmap(phys) + off, src, len);
}

void
vmm_copy_from_phys(void *dst, uint64_t phys, uint32_t off, uint32_t len)
{
    if ((uint64_t)off + len > 4096)
        return;
    __builtin_memcpy(dst, (const uint8_t *)arch_dmap(phys) + off, len);
}

int
vmm_write_user_bytes(uint64_t pml4_phys, uint64_t va,
                     const void *src, uint64_t len)
{
    const uint8_t *s = (const uint8_t *)src;
    uint64_t done = 0;
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    while (done < len) {
        uint64_t cur   = va + done;
        uint64_t pg    = cur & ~0xFFFULL;
        uint64_t off   = cur & 0xFFFULL;
        uint64_t chunk = 4096ULL - off;
        if (chunk > len - done) chunk = len - done;

        uint64_t *pte = walk_to_pte(pml4_phys, pg);
        if (!pte || !(*pte & A64_PTE_VALID)) {
            spin_unlock_irqrestore(&vmm_lock, fl);
            return -1;
        }
        __builtin_memcpy((uint8_t *)arch_dmap(ARCH_PTE_ADDR(*pte)) + off,
                         s + done, chunk);
        done += chunk;
    }
    spin_unlock_irqrestore(&vmm_lock, fl);
    return 0;
}

int
vmm_write_user_u64(uint64_t pml4_phys, uint64_t va, uint64_t val)
{
    return vmm_write_user_bytes(pml4_phys, va, &val, sizeof(val));
}

/* ── Address-space duplication / teardown (fork, execve, exit) ─────────── */

/* for_each_user_leaf — shared iteration for the fork/teardown walks.
 * Calls fn(l3 slot pointer, va) for every non-zero level-3 slot reachable
 * from root. Caller holds vmm_lock. */

int
vmm_copy_user_pages(uint64_t src_pml4, uint64_t dst_pml4)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *l0 = pv(src_pml4);
    for (uint64_t i0 = 0; i0 < 512; i0++) {
        if (!(l0[i0] & A64_PTE_VALID)) continue;
        uint64_t *l1 = pv(ARCH_PTE_ADDR(l0[i0]));
        for (uint64_t i1 = 0; i1 < 512; i1++) {
            if (!(l1[i1] & A64_PTE_VALID)) continue;
            uint64_t *l2 = pv(ARCH_PTE_ADDR(l1[i1]));
            for (uint64_t i2 = 0; i2 < 512; i2++) {
                if (!(l2[i2] & A64_PTE_VALID)) continue;
                uint64_t *l3 = pv(ARCH_PTE_ADDR(l2[i2]));
                for (uint64_t i3 = 0; i3 < 512; i3++) {
                    uint64_t pte = l3[i3];
                    if (!(pte & A64_PTE_VALID)) continue;
                    if (!(pte & A64_PTE_USER)) continue;
                    /* Skip device/NC (MMIO) mappings. */
                    if ((pte & A64_PTE_ATTR(7)) != A64_PTE_ATTR(A64_ATTR_NORMAL_WB))
                        continue;

                    uint64_t src_phys = ARCH_PTE_ADDR(pte);
                    uint64_t dst_phys = pmm_alloc_page();
                    if (!dst_phys) {
                        spin_unlock_irqrestore(&vmm_lock, fl);
                        return -1;
                    }
                    __builtin_memcpy(arch_dmap(dst_phys),
                                     arch_dmap(src_phys), 4096);
                    uint64_t va = (i0 << 39) | (i1 << 30) |
                                  (i2 << 21) | (i3 << 12);
                    uint64_t aflags = arch_pte_to_flags(pte) &
                                      ~0x0000FFFFFFFFF000UL;
                    if (map_page_in(dst_pml4, va, dst_phys, aflags, 0) < 0) {
                        pmm_free_page(dst_phys);
                        spin_unlock_irqrestore(&vmm_lock, fl);
                        return -1;
                    }
                }
            }
        }
    }
    spin_unlock_irqrestore(&vmm_lock, fl);
    return 0;
}

int
vmm_cow_user_pages(uint64_t src_pml4, uint64_t dst_pml4)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *l0 = pv(src_pml4);
    for (uint64_t i0 = 0; i0 < 512; i0++) {
        if (!(l0[i0] & A64_PTE_VALID)) continue;
        uint64_t *l1 = pv(ARCH_PTE_ADDR(l0[i0]));
        for (uint64_t i1 = 0; i1 < 512; i1++) {
            if (!(l1[i1] & A64_PTE_VALID)) continue;
            uint64_t *l2 = pv(ARCH_PTE_ADDR(l1[i1]));
            for (uint64_t i2 = 0; i2 < 512; i2++) {
                if (!(l2[i2] & A64_PTE_VALID)) continue;
                uint64_t *l3 = pv(ARCH_PTE_ADDR(l2[i2]));
                for (uint64_t i3 = 0; i3 < 512; i3++) {
                    uint64_t pte = l3[i3];
                    if (!(pte & A64_PTE_VALID)) continue;
                    if (!(pte & A64_PTE_USER)) continue;
                    if ((pte & A64_PTE_ATTR(7)) != A64_PTE_ATTR(A64_ATTR_NORMAL_WB))
                        continue;

                    uint64_t phys = ARCH_PTE_ADDR(pte);
                    uint64_t va = (i0 << 39) | (i1 << 30) |
                                  (i2 << 21) | (i3 << 12);
                    uint64_t aflags = arch_pte_to_flags(pte) &
                                      ~0x0000FFFFFFFFF000UL;

                    if (aflags & VMM_FLAG_SHARED) {
                        /* Driver-owned shared RAM: inherit as-is, no ref,
                         * no COW (see the x86 vmm.c rationale). */
                        if (map_page_in(dst_pml4, va, phys, aflags, 0) < 0)
                            goto oom;
                    } else if (aflags & VMM_FLAG_WRITABLE) {
                        uint64_t cow = (aflags & ~VMM_FLAG_WRITABLE)
                                       | VMM_FLAG_COW;
                        l3[i3] = phys | arch_pte_from_flags(cow);
                        if (map_page_in(dst_pml4, va, phys, cow, 0) < 0)
                            goto oom;
                        pmm_ref_page(phys);
                    } else {
                        if (map_page_in(dst_pml4, va, phys, aflags, 0) < 0)
                            goto oom;
                        pmm_ref_page(phys);
                    }
                }
            }
        }
    }
    spin_unlock_irqrestore(&vmm_lock, fl);
    /* Parent PTEs were write-protected above; drop every stale TLB entry. */
    __asm__ volatile("dsb ishst\n\ttlbi vmalle1is\n\tdsb ish\n\tisb" ::: "memory");
    return 0;
oom:
    spin_unlock_irqrestore(&vmm_lock, fl);
    return -1;
}

int
vmm_cow_fault_handle(uint64_t pml4_phys, uint64_t fault_va)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *pte = walk_to_pte(pml4_phys, fault_va);
    if (!pte) {
        spin_unlock_irqrestore(&vmm_lock, fl);
        return -1;
    }
    uint64_t hw = *pte;

    /* Spurious stale-TLB write fault: page already writable. */
    if ((hw & A64_PTE_VALID) && (hw & A64_PTE_USER) && !(hw & A64_PTE_RO)) {
        arch_vmm_invlpg(fault_va);
        spin_unlock_irqrestore(&vmm_lock, fl);
        return 0;
    }

    if (!(hw & A64_PTE_VALID) || !(hw & A64_PTE_USER) ||
        !(hw & A64_PTE_SW_COW)) {
        spin_unlock_irqrestore(&vmm_lock, fl);
        return -1;
    }

    uint64_t old_phys = ARCH_PTE_ADDR(hw);
    uint64_t aflags   = arch_pte_to_flags(hw) & ~0x0000FFFFFFFFF000UL;
    uint64_t nflags   = (aflags & ~VMM_FLAG_COW) | VMM_FLAG_WRITABLE;
    /* Reuse-in-place fast path: singly-owned frame → flip to writable. */
    if (pmm_page_refcount(old_phys) == 1) {
        *pte = old_phys | arch_pte_from_flags(nflags);
        arch_vmm_invlpg(fault_va);
        spin_unlock_irqrestore(&vmm_lock, fl);
        return 0;
    }

    uint64_t new_phys = pmm_alloc_page();
    if (!new_phys) {
        spin_unlock_irqrestore(&vmm_lock, fl);
        return -2;
    }
    __builtin_memcpy(arch_dmap(new_phys), arch_dmap(old_phys), 4096);
    *pte = new_phys | arch_pte_from_flags(nflags);
    arch_vmm_invlpg(fault_va);
    spin_unlock_irqrestore(&vmm_lock, fl);

    pmm_free_page(old_phys);   /* drop this sharer's reference */
    return 0;
}

void
vmm_free_user_pages(uint64_t pml4_phys)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *l0 = pv(pml4_phys);
    for (uint64_t i0 = 0; i0 < 512; i0++) {
        if (!(l0[i0] & A64_PTE_VALID)) continue;
        uint64_t *l1 = pv(ARCH_PTE_ADDR(l0[i0]));
        for (uint64_t i1 = 0; i1 < 512; i1++) {
            if (!(l1[i1] & A64_PTE_VALID) || !(l1[i1] & A64_PTE_PAGE)) continue;
            uint64_t *l2 = pv(ARCH_PTE_ADDR(l1[i1]));
            for (uint64_t i2 = 0; i2 < 512; i2++) {
                if (!(l2[i2] & A64_PTE_VALID) || !(l2[i2] & A64_PTE_PAGE)) continue;
                uint64_t *l3 = pv(ARCH_PTE_ADDR(l2[i2]));
                for (uint64_t i3 = 0; i3 < 512; i3++) {
                    uint64_t pte = l3[i3];
                    if (pte == 0) continue;
                    l3[i3] = 0;
                    if (pte & A64_PTE_SW_SHARED)
                        continue;   /* driver-owned — never free */
                    uint64_t phys = ARCH_PTE_ADDR(pte);
                    if (phys)
                        pmm_free_page(phys);
                }
            }
        }
    }
    spin_unlock_irqrestore(&vmm_lock, fl);
}

void
vmm_free_user_pml4(uint64_t pml4_phys)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_lock);
    uint64_t *l0 = pv(pml4_phys);
    for (uint64_t i0 = 0; i0 < 512; i0++) {
        if (!(l0[i0] & A64_PTE_VALID)) continue;
        uint64_t l1p = ARCH_PTE_ADDR(l0[i0]);
        uint64_t *l1 = pv(l1p);
        for (uint64_t i1 = 0; i1 < 512; i1++) {
            if (!(l1[i1] & A64_PTE_VALID) || !(l1[i1] & A64_PTE_PAGE)) continue;
            uint64_t l2p = ARCH_PTE_ADDR(l1[i1]);
            uint64_t *l2 = pv(l2p);
            for (uint64_t i2 = 0; i2 < 512; i2++) {
                if (!(l2[i2] & A64_PTE_VALID) || !(l2[i2] & A64_PTE_PAGE)) continue;
                uint64_t l3p = ARCH_PTE_ADDR(l2[i2]);
                uint64_t *l3 = pv(l3p);
                for (uint64_t i3 = 0; i3 < 512; i3++) {
                    uint64_t pte = l3[i3];
                    if (pte == 0) continue;
                    if (pte & A64_PTE_SW_SHARED)
                        continue;   /* driver-owned — never free */
                    uint64_t phys = ARCH_PTE_ADDR(pte);
                    if (phys)
                        pmm_free_page(phys);
                }
                pmm_free_page(l3p);
            }
            pmm_free_page(l2p);
        }
        pmm_free_page(l1p);
    }
    pmm_free_page(pml4_phys);
    spin_unlock_irqrestore(&vmm_lock, fl);

    /* Freed frames will be recycled: drop every stale translation. */
    __asm__ volatile("dsb ishst\n\ttlbi vmalle1is\n\tdsb ish\n\tisb" ::: "memory");

    if (pmm_acct_enabled())
        pmm_acct_dump("teardown");
}
