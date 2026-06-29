/*
 * kernel/mm/vmm.c — x86-64 virtual memory manager.
 *
 * Arch isolation note (2026-04-12): This file hardcodes the x86-64
 * 4-level paging layout (PML4/PDPT/PD/PT, higher-half base
 * 0xFFFFFFFF80000000, pml4[511]/pdpt_hi[510]) and is x86-64 only.
 * It is NOT built by kernel/arch/arm64/Makefile — the ARM64 port has
 * its own VMM at kernel/arch/arm64/vmm_arm64.c that mirrors the same
 * public interface (vmm.h). Keep the public signatures in vmm.h
 * arch-neutral; anything x86-specific stays inside this file.
 */
#ifndef __x86_64__
#error "kernel/mm/vmm.c is x86-64 only; arm64 uses kernel/arch/arm64/vmm_arm64.c"
#endif

#include "vmm.h"
#include "arch.h"     /* arch_vmm_load_pml4, arch_vmm_invlpg */
#include "arch_vmm.h" /* arch_pte_from_flags, ARCH_PTE_ADDR */
#include "pmm.h"
#include "printk.h"
#include "spinlock.h"
#include "tlb.h"
#include "fb.h"
#include "lapic.h"   /* lapic_id() — window-race diag */
#include "smp.h"     /* g_hwwatch — window-race diag gate */
#include <stdint.h>
#include <stddef.h>

/* VMM_PAGE_SIZE kept as the local alias; value single-sourced in limits.h
 * (AEGIS_PAGE_SIZE), reached transitively via pmm.h above. */
#define VMM_PAGE_SIZE   AEGIS_PAGE_SIZE
#define VMM_PAGE_MASK   (~(VMM_PAGE_SIZE - 1))
/* PTE_ADDR removed — use ARCH_PTE_ADDR from arch_vmm.h instead. */

/* Physical address of the active PML4 table. */
static uint64_t s_pml4_phys;

/* Mapped-window allocator (Phase 6).
 * A single virtual address whose PTE is permanently allocated in BSS.
 * vmm_window_map(phys) installs phys into the PTE and flushes TLB.
 * vmm_window_unmap() clears the PTE and flushes TLB.
 * The window is non-reentrant: never hold it across any call that may
 * itself call vmm_window_map (e.g. alloc_table). */
#define VMM_WINDOW_VA (ARCH_KERNEL_VIRT_BASE + 0x800000UL)

/* s_window_pt must be 4KB-aligned: pd_hi[4] stores its physical address as a
 * page-table pointer.  An unaligned address would set the PS bit (bit 7) in
 * the PDE, causing the CPU to interpret it as a huge-page entry with reserved
 * bits set — producing a #PF RSVD fault on first window access. */
static uint64_t           s_window_pt[512] __attribute__((aligned(4096))); /* BSS — PT for window range */
static volatile uint64_t *s_window_pte;     /* → s_window_pt[0], set at init   *
                                             * volatile: prevents the compiler  *
                                             * from caching the PTE value; each *
                                             * write must reach memory before   *
                                             * the __asm__ volatile invlpg.     */
static volatile uint64_t *s_window_pte2;    /* → s_window_pt[1], second window slot */

/*
 * Lock ordering invariant (canonical):
 *
 *   vmm_window_lock > pmm_lock > kva_lock
 *
 * Any code path holding vmm_window_lock MAY acquire pmm_lock / kva_lock
 * while holding it (e.g. to allocate a backing frame before updating the
 * window PTE).  The reverse is forbidden: never acquire vmm_window_lock
 * while holding pmm_lock or kva_lock — doing so risks deadlock with a
 * concurrent mapping operation.
 *
 * This ordering is documented globally in .claude/CLAUDE.md §"Lock
 * Ordering (Canonical)".  Match it here because vmm.c is the most common
 * place where the relationship gets reversed by accident.
 *
 * (Audit item M3 — 2026-03-29.)
 */
static spinlock_t vmm_window_lock = SPINLOCK_INIT;

/*
 * vmm_window_map — map an arbitrary physical page into the window slot.
 * Returns a pointer to VMM_WINDOW_VA, now backed by phys.
 *
 * Write ordering: the write to *s_window_pte must reach memory before the
 * invlpg asm barrier. volatile on s_window_pte ensures the compiler does not
 * hoist the write. arch_vmm_invlpg is __asm__ volatile, which also acts as
 * a compiler barrier — so the write-then-invlpg ordering is guaranteed.
 *
 * Do NOT call this while a previous vmm_window_map result is still in use
 * unless you are intentionally overwriting the mapping (walk-overwrite pattern).
 */
/* DIAG (hwwatch): detect concurrent CROSS-CPU use of the single global window.
 * The window (VMM_WINDOW_VA) is the prime wrong-physical-frame suspect: if two
 * CPUs map it at once, one CPU's write (page-table entries / copied page data)
 * lands in the other CPU's mapped frame → sprays kernel memory.  Every window
 * user holds vmm_window_lock, so g_win_owner must only ever be ONE cpu; a
 * mismatch proves the lock failed to serialize.  Uses lapic_id() (GS-independent
 * — robust even if percpu/GS is corrupted).  Owner set on slot-1/slot-2 map,
 * cleared on slot-1 unmap (held across the fork copy's map+map2). */
static volatile int g_win_owner = -1;
static inline void win_enter(void)
{
    if (!g_hwwatch) return;
    int me = (int)lapic_id();
    int prev = g_win_owner;
    if (prev != -1 && prev != me)
        printk("[WINRACE] VMM window: cpu%d entered while cpu%d already owns it "
               "(lock failed to serialize)\n", me, prev);
    g_win_owner = me;
}
static inline void win_exit(void)
{
    if (g_hwwatch) g_win_owner = -1;
}

void *
vmm_window_map(uint64_t phys)
{
    win_enter();
    *s_window_pte = phys | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
    arch_vmm_invlpg(VMM_WINDOW_VA);
    return (void *)VMM_WINDOW_VA;
}

/*
 * vmm_window_unmap — clear the window PTE and flush TLB.
 * Call this after the last use of any vmm_window_map result.
 */
void
vmm_window_unmap(void)
{
    *s_window_pte = 0;
    arch_vmm_invlpg(VMM_WINDOW_VA);
    win_exit();
}

/* vmm_window_map2 — map phys into the second window slot (VMM_WINDOW_VA + 4096).
 * Returns the VA of the mapped page.
 * Non-reentrant with vmm_window_map: never hold both simultaneously
 * across any call that may call vmm_window_map/map2 internally. */
static void *
vmm_window_map2(uint64_t phys)
{
    win_enter();
    *s_window_pte2 = phys | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
    arch_vmm_invlpg(VMM_WINDOW_VA + 4096);
    return (void *)(VMM_WINDOW_VA + 4096);
}

/* vmm_window_unmap2 — clear the second window PTE and flush TLB. */
static void
vmm_window_unmap2(void)
{
    *s_window_pte2 = 0;
    arch_vmm_invlpg(VMM_WINDOW_VA + 4096);
}

/*
 * alloc_table — allocate a page-table page from the PMM and zero it.
 * Uses vmm_window_map/unmap to zero the page without the identity map.
 * Panics if the PMM is exhausted.
 *
 * Requires the window allocator to be active (s_window_pte != NULL).
 * vmm_init uses alloc_table_early() instead for the five bootstrap tables.
 */
static uint64_t
alloc_table(void)
{
    uint64_t phys = pmm_alloc_page();
    if (phys == 0)
        return 0;   /* OOM — caller must handle gracefully */
    uint64_t *t = vmm_window_map(phys);
    int i;
    for (i = 0; i < 512; i++)
        t[i] = 0;
    vmm_window_unmap();
    return phys;
}

/*
 * alloc_table_early — allocate and zero a page-table page using the identity
 * map.  Valid only during vmm_init(), before arch_vmm_load_pml4() switches
 * to the new PML4 and before the window allocator is wired up.
 * After vmm_init() returns, call alloc_table() instead.
 */
static uint64_t
alloc_table_early(void)
{
    uint64_t phys = pmm_alloc_page();
    if (phys == 0) {
        printk("[VMM] FAIL: out of memory allocating page table\n");
        panic_halt("[VMM] FAIL: out of memory allocating page table");
    }
    /* SAFETY: identity map [0..1GB) is active (boot.asm pd_lo fills 512 entries);
     * phys must be within that range. PMM starts above _kernel_end. */
    uint64_t *p = (uint64_t *)(uintptr_t)phys;
    int i;
    for (i = 0; i < 512; i++)
        p[i] = 0;
    return phys;
}

/*
 * ensure_table_phys — if parent_table[idx] has no present child, allocate one.
 * Returns the physical address of the (possibly newly created) child table.
 *
 * Takes parent_phys (physical address) rather than a pointer, so it can
 * safely call alloc_table (which uses the window) without a stale-pointer
 * hazard: parent is unmapped before alloc_table is called, then re-mapped
 * to install the new child entry.
 *
 * extra_flags: 0 for kernel tables, VMM_FLAG_USER for user-accessible tables.
 * CRITICAL for user tables: ALL intermediate entries in a user walk must have
 * VMM_FLAG_USER set. The MMU checks USER at every level (PML4, PDPT, PD).
 */
static uint64_t
ensure_table_phys(uint64_t parent_phys, uint64_t idx, uint64_t extra_flags)
{
    uint64_t *parent = vmm_window_map(parent_phys);
    uint64_t  entry  = parent[idx];
    vmm_window_unmap();                   /* unmap before potential alloc_table */

    if (!(entry & VMM_FLAG_PRESENT)) {
        uint64_t child = alloc_table();   /* uses window internally */
        if (child == 0)
            return 0;                     /* OOM — propagate to caller */
        parent = vmm_window_map(parent_phys);
        parent[idx] = child | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | extra_flags);
        vmm_window_unmap();
        return child;
    }
    return ARCH_PTE_ADDR(entry);
}

void
vmm_init(void)
{
    lockrank_register(&vmm_window_lock, LOCK_RANK_VMM); /* debug lock-order check */
    /* Allocate the five initial page tables using the identity-map-based
     * early allocator.  The window allocator is not yet active here.
     * All five PMM pages are below 4MB so the identity cast is safe. */
    uint64_t pml4_phys    = alloc_table_early();
    uint64_t pdpt_lo_phys = alloc_table_early();
    uint64_t pd_lo_phys   = alloc_table_early();
    uint64_t pdpt_hi_phys = alloc_table_early();
    uint64_t pd_hi_phys   = alloc_table_early();

    /* SAFETY: identity map [0..4MB) is active for all five tables. */
    uint64_t *pml4    = (uint64_t *)(uintptr_t)pml4_phys;
    uint64_t *pdpt_lo = (uint64_t *)(uintptr_t)pdpt_lo_phys;
    uint64_t *pd_lo   = (uint64_t *)(uintptr_t)pd_lo_phys;
    uint64_t *pdpt_hi = (uint64_t *)(uintptr_t)pdpt_hi_phys;
    uint64_t *pd_hi   = (uint64_t *)(uintptr_t)pd_hi_phys;

    /* Identity map: VA [0..1GB) → PA [0..1GB) via PML4[0].
     * PML4[0] → pdpt_lo[0] → pd_lo with 512 × 2MB huge pages.
     * Covers all physical RAM that GRUB modules or PMM pages may occupy.
     * Torn down by vmm_teardown_identity() at end of boot. */
    pml4[0]    = pdpt_lo_phys | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
    pdpt_lo[0] = pd_lo_phys   | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
    {
        uint32_t i;
        for (i = 0; i < 512; i++)
            pd_lo[i] = ((uint64_t)i << 21) | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE) | (1UL << 7);
    }

    /* Higher-half map: VA [KERN_VMA..KERN_VMA+4MB) → PA [0..4MB).
     * KERN_VMA = 0xFFFFFFFF80000000 → PML4[511], PDPT[510].
     * PML4[511] → pdpt_hi[510] → pd_hi with two 2MB huge pages. */
    pml4[511]    = pdpt_hi_phys | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
    pdpt_hi[510] = pd_hi_phys   | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
    pd_hi[0]     = 0x000000UL   | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE) | (1UL << 7);
    pd_hi[1]     = 0x200000UL   | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE) | (1UL << 7);
    pd_hi[2]     = 0x400000UL   | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE) | (1UL << 7);
    pd_hi[3]     = 0x600000UL   | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE) | (1UL << 7);

    /* Install the mapped-window PT into pd_hi[4].
     * pd_hi is a local pointer (identity-cast of pd_hi_phys) in scope here.
     * pd_hi[0..3] are the four 2MB kernel huge pages — an 8MB kernel-image window
     * (matches boot.asm's early map; raised from 6MB so the BSS-heavy limits fit).
     * pd_hi[4] covers 0xFFFFFFFF80800000 (VMM_WINDOW_VA); kva now starts at pd_hi[5]
     * (0xFFFFFFFF80A00000) — currently NULL. */
    {
        /* Physical address of s_window_pt: PA = VA - KERN_VMA.
         * All higher-half symbols have PA = VA - ARCH_KERNEL_VIRT_BASE
         * (the linker AT() directive sets LMA = VMA - KERN_VMA).
         * Adding ARCH_KERNEL_PHYS_BASE would be wrong: PHYS_BASE is just
         * where the first section starts, not an additive offset. */
        uint64_t win_phys = (uint64_t)(uintptr_t)s_window_pt
                            - ARCH_KERNEL_VIRT_BASE;
        pd_hi[4]      = win_phys | arch_pte_from_flags(VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
        s_window_pte  = &s_window_pt[0];
        s_window_pte2 = &s_window_pt[1];
    }

    s_pml4_phys = pml4_phys;
    arch_vmm_load_pml4(pml4_phys);

    printk("[VMM] OK: kernel mapped to 0xFFFFFFFF80000000\n");
    printk("[VMM] OK: mapped-window allocator active\n");
}

void
vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags)
{
    if (virt & ~VMM_PAGE_MASK) {
        printk("[VMM] FAIL: vmm_map_page virt not aligned\n");
        panic_halt("[VMM] FAIL: vmm_map_page virt not aligned");
    }
    if (phys & ~VMM_PAGE_MASK) {
        printk("[VMM] FAIL: vmm_map_page phys not aligned\n");
        panic_halt("[VMM] FAIL: vmm_map_page phys not aligned");
    }

    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    uint64_t pdpt_phys = ensure_table_phys(s_pml4_phys, pml4_idx, 0);
    if (pdpt_phys == 0) goto oom;
    uint64_t pd_phys   = ensure_table_phys(pdpt_phys,   pdpt_idx, 0);
    if (pd_phys == 0) goto oom;
    uint64_t pt_phys   = ensure_table_phys(pd_phys,     pd_idx,   0);
    if (pt_phys == 0) goto oom;

    uint64_t *pt = vmm_window_map(pt_phys);
    if (pt[pt_idx] & VMM_FLAG_PRESENT) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_map_page double-map\n");
        panic_halt("[VMM] FAIL: vmm_map_page double-map");
    }
    pt[pt_idx] = phys | arch_pte_from_flags(flags | VMM_FLAG_PRESENT);
    vmm_window_unmap();

    spin_unlock_irqrestore(&vmm_window_lock, fl);
    return;

oom:
    spin_unlock_irqrestore(&vmm_window_lock, fl);
    printk("[VMM] FAIL: out of memory in vmm_map_page\n");
    panic_halt("[VMM] FAIL: out of memory in vmm_map_page");
}

void
vmm_unmap_page(uint64_t virt)
{
    if (virt & ~VMM_PAGE_MASK) {
        printk("[VMM] FAIL: vmm_unmap_page virt not aligned\n");
        panic_halt("[VMM] FAIL: vmm_unmap_page virt not aligned");
    }

    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    /* Walk-overwrite pattern: each vmm_window_map call overwrites the PTE
     * from the previous level without an intervening unmap. Only one
     * vmm_window_unmap call at the very end. This halves the invlpg count
     * (4 maps + 1 unmap = 5 vs. 4 maps + 4 unmaps = 8) and eliminates the
     * window between unmap and remap where a stale TLB entry could yield
     * a silent wrong read if any interleaved code runs between them. */
    uint64_t *pml4  = vmm_window_map(s_pml4_phys);
    uint64_t  pml4e = pml4[pml4_idx];
    if (!(pml4e & VMM_FLAG_PRESENT)) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_unmap_page not mapped (pml4)\n");
        panic_halt("[VMM] FAIL: vmm_unmap_page not mapped (pml4)");
    }

    uint64_t *pdpt  = vmm_window_map(ARCH_PTE_ADDR(pml4e));  /* overwrites PTE */
    uint64_t  pdpte = pdpt[pdpt_idx];
    if (!(pdpte & VMM_FLAG_PRESENT)) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_unmap_page not mapped (pdpt)\n");
        panic_halt("[VMM] FAIL: vmm_unmap_page not mapped (pdpt)");
    }

    uint64_t *pd  = vmm_window_map(ARCH_PTE_ADDR(pdpte));    /* overwrites PTE */
    uint64_t  pde = pd[pd_idx];
    if (!(pde & VMM_FLAG_PRESENT)) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_unmap_page not mapped (pd)\n");
        panic_halt("[VMM] FAIL: vmm_unmap_page not mapped (pd)");
    }
    if (pde & (1UL << 7)) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_unmap_page called on huge-page-backed address\n");
        panic_halt("[VMM] FAIL: vmm_unmap_page called on huge-page-backed address");
    }

    uint64_t *pt  = vmm_window_map(ARCH_PTE_ADDR(pde));      /* overwrites PTE */
    uint64_t  pte = pt[pt_idx];
    if (!(pte & VMM_FLAG_PRESENT)) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_unmap_page not mapped (pt)\n");
        panic_halt("[VMM] FAIL: vmm_unmap_page not mapped (pt)");
    }
    int did_unmap = (pt[pt_idx] != 0);
    pt[pt_idx] = 0;
    vmm_window_unmap();          /* single unmap at the end of the walk */
    arch_vmm_invlpg(virt);

    spin_unlock_irqrestore(&vmm_window_lock, fl);

    /* Cross-CPU TLB shootdown for the kernel (KVA) range.  KVA lives in the
     * shared higher-half mapping present in EVERY address space, so other
     * CPUs that touched this VA still hold stale entries after the local
     * invlpg above.  When kva_alloc_pages recycles this VA (freelist) and a
     * different CPU maps it to a new frame, that CPU would otherwise read
     * through its stale translation → memory corruption (the SMP
     * concurrent-startup image-corruption bug).  Use TLB_TARGET_ALL because
     * the range is global, not bound to one pml4.  Called after releasing
     * vmm_window_lock (shootdown deadlock rule). */
    if (did_unmap)
        tlb_shootdown_kernel(virt, virt + VMM_PAGE_SIZE);
}

uint64_t
vmm_phys_of(uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    /* Walk-overwrite pattern: overwrite window PTE at each level without
     * an intervening unmap. Single vmm_window_unmap at the end. */
    uint64_t *pml4  = vmm_window_map(s_pml4_phys);
    uint64_t  pml4e = pml4[pml4_idx];
    if (!(pml4e & VMM_FLAG_PRESENT)) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_phys_of not mapped (pml4)\n");
        panic_halt("[VMM] FAIL: vmm_phys_of not mapped (pml4)");
    }

    uint64_t *pdpt  = vmm_window_map(ARCH_PTE_ADDR(pml4e));
    uint64_t  pdpte = pdpt[pdpt_idx];
    if (!(pdpte & VMM_FLAG_PRESENT)) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_phys_of not mapped (pdpt)\n");
        panic_halt("[VMM] FAIL: vmm_phys_of not mapped (pdpt)");
    }

    uint64_t *pd  = vmm_window_map(ARCH_PTE_ADDR(pdpte));
    uint64_t  pde = pd[pd_idx];
    if (!(pde & VMM_FLAG_PRESENT)) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_phys_of not mapped (pd)\n");
        panic_halt("[VMM] FAIL: vmm_phys_of not mapped (pd)");
    }
    if (pde & (1UL << 7)) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_phys_of called on huge-page-backed address\n");
        panic_halt("[VMM] FAIL: vmm_phys_of called on huge-page-backed address");
    }

    uint64_t *pt  = vmm_window_map(ARCH_PTE_ADDR(pde));
    uint64_t  pte = pt[pt_idx];
    vmm_window_unmap();

    if (!(pte & VMM_FLAG_PRESENT)) {
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: vmm_phys_of not mapped (pt)\n");
        panic_halt("[VMM] FAIL: vmm_phys_of not mapped (pt)");
    }
    uint64_t result = ARCH_PTE_ADDR(pte);
    spin_unlock_irqrestore(&vmm_window_lock, fl);
    return result;
}

void
vmm_teardown_identity(void)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    /* Clear pml4[0]: removes the entire [0..512GB) low identity range.
     * pdpt_lo and pd_lo pages remain allocated but are now unreachable;
     * they will be reclaimed when a kernel page-table free path exists. */
    uint64_t *pml4 = vmm_window_map(s_pml4_phys);
    pml4[0] = 0;
    vmm_window_unmap();
    /* Full CR3 reload for a complete TLB flush. invlpg of each individual
     * huge page would work but CR3 reload is simpler and more complete. */
    arch_vmm_load_pml4(s_pml4_phys);
    spin_unlock_irqrestore(&vmm_window_lock, fl);
    printk("[VMM] OK: identity map removed\n");
}

uint64_t
vmm_create_user_pml4(void)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    uint64_t new_pml4_phys = alloc_table();   /* zeroed by alloc_table */
    if (new_pml4_phys == 0) {
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return 0;   /* OOM — caller must handle gracefully */
    }

    /* Copy kernel high entries [256..511] from master PML4.
     * This makes the kernel higher-half accessible in every user process's
     * address space, so syscall handlers can execute after SYSCALL without
     * a CR3 switch.
     * Two window map/unmap pairs: first to read from master, then to write
     * to new PML4.  A local array holds the 256 entries between the two
     * maps to avoid holding the window across a second map call. */
    uint64_t tmp[256];
    uint64_t *master = vmm_window_map(s_pml4_phys);
    int i;
    for (i = 0; i < 256; i++)
        tmp[i] = master[256 + i];
    vmm_window_unmap();

    uint64_t *newpml = vmm_window_map(new_pml4_phys);
    for (i = 0; i < 256; i++)
        newpml[256 + i] = tmp[i];
    vmm_window_unmap();

    spin_unlock_irqrestore(&vmm_window_lock, fl);
    return new_pml4_phys;
}

/* vmm_map_user_page_nolock — internal helper, caller must hold vmm_window_lock.
 * Returns 0 on success, -1 on OOM (page table allocation failure). */
static int
vmm_map_user_page_nolock(uint64_t pml4_phys, uint64_t virt,
                         uint64_t phys, uint64_t flags)
{
    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    uint64_t pdpt_phys = ensure_table_phys(pml4_phys,  pml4_idx, VMM_FLAG_USER);
    if (pdpt_phys == 0) return -1;
    uint64_t pd_phys   = ensure_table_phys(pdpt_phys,  pdpt_idx, VMM_FLAG_USER);
    if (pd_phys == 0) return -1;
    uint64_t pt_phys   = ensure_table_phys(pd_phys,    pd_idx,   VMM_FLAG_USER);
    if (pt_phys == 0) return -1;

    uint64_t *pt = vmm_window_map(pt_phys);
    if (pt[pt_idx] & VMM_FLAG_PRESENT) {
        vmm_window_unmap();
        printk("[VMM] FAIL: vmm_map_user_page double-map\n");
        panic_halt("[VMM] FAIL: vmm_map_user_page double-map");
    }
    pt[pt_idx] = phys | arch_pte_from_flags(flags | VMM_FLAG_PRESENT);
    vmm_window_unmap();
    return 0;
}

void
vmm_map_user_page(uint64_t pml4_phys, uint64_t virt,
                  uint64_t phys, uint64_t flags)
{
    if (virt & ~VMM_PAGE_MASK) {
        printk("[VMM] FAIL: vmm_map_user_page virt not aligned\n");
        panic_halt("[VMM] FAIL: vmm_map_user_page virt not aligned");
    }
    if (phys & ~VMM_PAGE_MASK) {
        printk("[VMM] FAIL: vmm_map_user_page phys not aligned\n");
        panic_halt("[VMM] FAIL: vmm_map_user_page phys not aligned");
    }

    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    if (vmm_map_user_page_nolock(pml4_phys, virt, phys, flags) < 0) {
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        printk("[VMM] FAIL: out of memory in vmm_map_user_page\n");
        panic_halt("[VMM] FAIL: out of memory in vmm_map_user_page");
    }
    spin_unlock_irqrestore(&vmm_window_lock, fl);
}

/* vmm_try_map_user_page — like vmm_map_user_page but TOLERATES an already-present
 * PTE instead of panicking. Returns 0 if it installed the mapping, 1 if the PTE
 * was already present (someone else mapped this VA — caller should free its frame
 * and treat the page as populated), -1 on OOM allocating a page table.
 *
 * This is the SMP-safe demand-fault primitive: the PTE check+set runs under
 * vmm_window_lock, so when two CLONE_VM threads fault the SAME lazy page on
 * different CPUs and each allocates a frame, the window lock serializes their
 * try-maps — the first installs its frame (0), the second sees it present (1) and
 * frees its own. No new lock or lock-ordering is introduced: the existing window
 * lock already serializes every PTE mutation. (Replaces an earlier attempt to add
 * an address-space lock around the whole populate, which deadlocked.) */
int
vmm_try_map_user_page(uint64_t pml4_phys, uint64_t virt,
                      uint64_t phys, uint64_t flags)
{
    if ((virt & ~VMM_PAGE_MASK) || (phys & ~VMM_PAGE_MASK)) {
        printk("[VMM] FAIL: vmm_try_map_user_page misaligned\n");
        panic_halt("[VMM] FAIL: vmm_try_map_user_page misaligned");
    }

    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    uint64_t pdpt_phys = ensure_table_phys(pml4_phys, pml4_idx, VMM_FLAG_USER);
    if (pdpt_phys == 0) { spin_unlock_irqrestore(&vmm_window_lock, fl); return -1; }
    uint64_t pd_phys   = ensure_table_phys(pdpt_phys, pdpt_idx, VMM_FLAG_USER);
    if (pd_phys == 0)   { spin_unlock_irqrestore(&vmm_window_lock, fl); return -1; }
    uint64_t pt_phys   = ensure_table_phys(pd_phys,   pd_idx,   VMM_FLAG_USER);
    if (pt_phys == 0)   { spin_unlock_irqrestore(&vmm_window_lock, fl); return -1; }

    uint64_t *pt = vmm_window_map(pt_phys);
    int already = (pt[pt_idx] & VMM_FLAG_PRESENT) ? 1 : 0;
    if (!already)
        pt[pt_idx] = phys | arch_pte_from_flags(flags | VMM_FLAG_PRESENT);
    vmm_window_unmap();

    spin_unlock_irqrestore(&vmm_window_lock, fl);
    return already;   /* 0 = we mapped it; 1 = lost the race (already present) */
}

void
vmm_switch_to(uint64_t pml4_phys)
{
    arch_vmm_load_pml4(pml4_phys);
}

uint64_t
vmm_get_master_pml4(void)
{
    return s_pml4_phys;
}

/* PTE_PS — Page Size bit. Set in a PDE indicates a 2MB huge page (the entry
 * maps a 2MB frame directly, not a PT). Set in a PDPTE indicates a 1GB page.
 * vmm_map_user_page only creates 4KB PTEs, so no user mapping should ever
 * have PS set. If encountered, skip (leak) rather than misinterpret as a
 * page-table pointer and double-free 512 ghost frames. */
#define PTE_PS (1UL << 7)

void
vmm_free_user_pml4(uint64_t pml4_phys)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    int i, j, k, l;

    /* Read all 256 user-half PML4 entries in one window mapping. */
    uint64_t pml4_entries[256];
    uint64_t *pml4 = vmm_window_map(pml4_phys);
    for (i = 0; i < 256; i++)
        pml4_entries[i] = pml4[i];
    vmm_window_unmap();

    for (i = 0; i < 256; i++) {
        uint64_t pml4e = pml4_entries[i];
        if (!(pml4e & VMM_FLAG_PRESENT)) continue;
        uint64_t pdpt_phys = ARCH_PTE_ADDR(pml4e);

        /* Read all 512 PDPT entries in one window mapping. */
        uint64_t pdpt_entries[512];
        uint64_t *pdpt = vmm_window_map(pdpt_phys);
        for (j = 0; j < 512; j++)
            pdpt_entries[j] = pdpt[j];
        vmm_window_unmap();

        for (j = 0; j < 512; j++) {
            uint64_t pdpte = pdpt_entries[j];
            if (!(pdpte & VMM_FLAG_PRESENT)) continue;
            if (pdpte & PTE_PS) continue; /* 1GB page — unexpected, skip */
            uint64_t pd_phys = ARCH_PTE_ADDR(pdpte);

            /* Read all 512 PD entries in one window mapping. */
            uint64_t pd_entries[512];
            uint64_t *pd = vmm_window_map(pd_phys);
            for (k = 0; k < 512; k++)
                pd_entries[k] = pd[k];
            vmm_window_unmap();

            for (k = 0; k < 512; k++) {
                uint64_t pde = pd_entries[k];
                if (!(pde & VMM_FLAG_PRESENT)) continue;
                if (pde & PTE_PS) continue; /* 2MB page — unexpected, skip */
                uint64_t pt_phys = ARCH_PTE_ADDR(pde);

                /* Hold window open across all 512 PT entries.
                 * pmm_free_page does not use vmm_window_map. */
                uint64_t *pt = vmm_window_map(pt_phys);
                for (l = 0; l < 512; l++) {
                    uint64_t pte = pt[l];
                    if (pte == 0) continue;
                    /* VMM_FLAG_SHARED: driver-owned RAM (sys_fb_map fb backing).
                     * The process maps it but does not own it — freeing it here
                     * recycled the live framebuffer (graphical #GP). Leave it. */
                    if (pte & VMM_FLAG_SHARED) continue;
                    uint64_t phys = ARCH_PTE_ADDR(pte);
                    if (phys) pmm_free_page(phys);
                }
                vmm_window_unmap();
                pmm_free_page(pt_phys);
            }
            pmm_free_page(pd_phys);
        }
        pmm_free_page(pdpt_phys);
    }
    pmm_free_page(pml4_phys);
    spin_unlock_irqrestore(&vmm_window_lock, fl);

    /* SMP: every page-table + leaf frame above was returned to the PMM and will
     * be reused.  Other CPUs may still hold stale TLB entries or cached
     * paging-structure walk nodes for this dead address space; once a freed
     * frame is reallocated, such a CPU would access it through the stale
     * translation → wrong-physical-frame corruption.  Flush all CPUs (CR3
     * reload) so no stale node survives.  Called after dropping vmm_window_lock
     * (shootdown deadlock rule); single-CPU degrades to a local flush. */
    tlb_flush_all_cpus();

    /* T1 diagnostic: per-teardown PMM ref/unref scoreboard (off unless the
     * `pmm_acct` cmdline token is set → oracle-safe). Done after the shootdown,
     * no lock held — pmm_acct_dump takes pmm_lock itself. */
    if (pmm_acct_enabled())
        pmm_acct_dump("teardown");
}

void
vmm_zero_page(uint64_t phys)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    uint8_t *p = (uint8_t *)vmm_window_map(phys);
    /* __builtin_memset of constant 4096 → fast `rep stos` memset. The kernel is
     * built -O0, so a hand byte loop here compiled to 4096 single-byte stores
     * (~100x slower) — and this runs on EVERY anon page fault / brk / mmap. */
    __builtin_memset(p, 0, 4096);
    vmm_window_unmap();
    spin_unlock_irqrestore(&vmm_window_lock, fl);
}

/* vmm_write_phys_bytes — copy `len` bytes from `src` into the physical page
 * `phys` at byte offset `off` (off+len must stay within one 4096-byte page).
 * Used by lazy file-backed mmap to fill a freshly-allocated frame with file
 * data BEFORE it is mapped user-visible, so a sibling CPU faulting the same
 * page never observes a half-populated frame. */
void
vmm_write_phys_bytes(uint64_t phys, uint32_t off, const void *src, uint32_t len)
{
    if ((uint64_t)off + len > 4096)
        return;   /* caller bug — never cross a page */
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    uint8_t *p = (uint8_t *)vmm_window_map(phys) + off;
    __builtin_memcpy(p, src, len);
    vmm_window_unmap();
    spin_unlock_irqrestore(&vmm_window_lock, fl);
}

/* vmm_copy_from_phys — copy `len` bytes from offset `off` within the physical
 * page `phys` into `dst`.  Brackets the window map/copy/unmap under
 * vmm_window_lock so callers outside vmm.c (which cannot take the static lock)
 * use the single shared window VA safely.  off+len must stay within one page
 * (<= 4096).  Used by memfd reads. */
void
vmm_copy_from_phys(void *dst, uint64_t phys, uint32_t off, uint32_t len)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    const uint8_t *src = (const uint8_t *)vmm_window_map(phys);
    uint8_t *d = (uint8_t *)dst;
    for (uint32_t i = 0; i < len; i++)
        d[i] = src[off + i];
    vmm_window_unmap();
    spin_unlock_irqrestore(&vmm_window_lock, fl);
}

/* vmm_phys_of_user_nolock — internal helper, caller must hold vmm_window_lock. */
static uint64_t
vmm_phys_of_user_nolock(uint64_t pml4_phys, uint64_t virt)
{
    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    /* Walk-overwrite pattern: overwrite window PTE at each level, single unmap. */
    uint64_t *pml4  = vmm_window_map(pml4_phys);
    uint64_t  pml4e = pml4[pml4_idx];
    if (!(pml4e & VMM_FLAG_PRESENT)) { vmm_window_unmap(); return 0; }

    uint64_t *pdpt  = vmm_window_map(ARCH_PTE_ADDR(pml4e));
    uint64_t  pdpte = pdpt[pdpt_idx];
    if (!(pdpte & VMM_FLAG_PRESENT)) { vmm_window_unmap(); return 0; }

    uint64_t *pd  = vmm_window_map(ARCH_PTE_ADDR(pdpte));
    uint64_t  pde = pd[pd_idx];
    if (!(pde & VMM_FLAG_PRESENT) || (pde & PTE_PS)) {
        vmm_window_unmap(); return 0;
    }

    uint64_t *pt  = vmm_window_map(ARCH_PTE_ADDR(pde));
    uint64_t  pte = pt[pt_idx];
    vmm_window_unmap();

    /* Return phys for PRESENT pages. PROT_NONE pages (phys without PRESENT)
     * are not found here — munmap leaks them. Acceptable: PROT_NONE guard
     * pages are rare and small. */
    return (pte & VMM_FLAG_PRESENT) ? ARCH_PTE_ADDR(pte) : 0;
}

uint64_t
vmm_phys_of_user(uint64_t pml4_phys, uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    uint64_t result = vmm_phys_of_user_nolock(pml4_phys, virt);
    spin_unlock_irqrestore(&vmm_window_lock, fl);
    return result;
}

/* vmm_user_range_mapped — return 1 if every page of [addr, addr+len) is
 * mapped (present leaf PTE) in pml4_phys, else 0.
 *
 * Backs user_ptr_valid's mapped-check: copy_from_user/copy_to_user have no
 * fault fixup table, so a kernel-mode #PF on an unmapped-but-in-range user
 * pointer panics the kernel.  Walking here closes that hole.  The check is
 * race-free against munmap today: syscalls run single-core with IF=0
 * (IA32_SFMASK clears IF on SYSCALL entry), so no other task can unmap
 * between this walk and the copy.  Revisit if SMP scheduling lands.
 *
 * Caller must have range-checked addr/len (no overflow) first. */
int
vmm_user_range_mapped(uint64_t pml4_phys, uint64_t addr, uint64_t len)
{
    if (len == 0)
        return 1;
    uint64_t va   = addr & ~0xFFFULL;
    uint64_t last = (addr + len - 1) & ~0xFFFULL;
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    for (;;) {
        if (!vmm_phys_of_user_nolock(pml4_phys, va)) {
            spin_unlock_irqrestore(&vmm_window_lock, fl);
            return 0;
        }
        if (va == last)
            break;
        va += 4096;
    }
    spin_unlock_irqrestore(&vmm_window_lock, fl);
    return 1;
}

/* H4: vmm_phys_of_user_raw — like vmm_phys_of_user but returns the physical
 * address for ANY non-zero leaf PTE regardless of PRESENT bit. This finds
 * physical frames backing PROT_NONE pages (PRESENT cleared by mprotect) so
 * munmap can free them instead of leaking. */
uint64_t
vmm_phys_of_user_raw(uint64_t pml4_phys, uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    uint64_t *pml4  = vmm_window_map(pml4_phys);
    uint64_t  pml4e = pml4[pml4_idx];
    if (!(pml4e & VMM_FLAG_PRESENT)) { vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return 0; }

    uint64_t *pdpt  = vmm_window_map(ARCH_PTE_ADDR(pml4e));
    uint64_t  pdpte = pdpt[pdpt_idx];
    if (!(pdpte & VMM_FLAG_PRESENT)) { vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return 0; }

    uint64_t *pd  = vmm_window_map(ARCH_PTE_ADDR(pdpte));
    uint64_t  pde = pd[pd_idx];
    if (!(pde & VMM_FLAG_PRESENT) || (pde & PTE_PS)) {
        vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return 0;
    }

    uint64_t *pt  = vmm_window_map(ARCH_PTE_ADDR(pde));
    uint64_t  pte = pt[pt_idx];
    vmm_window_unmap();

    spin_unlock_irqrestore(&vmm_window_lock, fl);

    /* Return phys for any non-zero PTE, even if PRESENT is clear (PROT_NONE). */
    return pte ? ARCH_PTE_ADDR(pte) : 0;
}

/* vmm_pte_of_user_raw — like vmm_phys_of_user_raw but returns the FULL leaf PTE
 * (flags included) so callers can inspect software bits such as VMM_FLAG_SHARED.
 * Returns 0 if no leaf PTE maps the VA. Used by sys_munmap to avoid freeing
 * driver-owned (VMM_FLAG_SHARED) frames — same guard the teardown walks apply. */
uint64_t
vmm_pte_of_user_raw(uint64_t pml4_phys, uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    uint64_t *pml4  = vmm_window_map(pml4_phys);
    uint64_t  pml4e = pml4[pml4_idx];
    if (!(pml4e & VMM_FLAG_PRESENT)) { vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return 0; }

    uint64_t *pdpt  = vmm_window_map(ARCH_PTE_ADDR(pml4e));
    uint64_t  pdpte = pdpt[pdpt_idx];
    if (!(pdpte & VMM_FLAG_PRESENT)) { vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return 0; }

    uint64_t *pd  = vmm_window_map(ARCH_PTE_ADDR(pdpte));
    uint64_t  pde = pd[pd_idx];
    if (!(pde & VMM_FLAG_PRESENT) || (pde & PTE_PS)) {
        vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return 0;
    }

    uint64_t *pt  = vmm_window_map(ARCH_PTE_ADDR(pde));
    uint64_t  pte = pt[pt_idx];
    vmm_window_unmap();

    spin_unlock_irqrestore(&vmm_window_lock, fl);
    return pte;
}

void
vmm_unmap_user_page(uint64_t pml4_phys, uint64_t virt)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    /* Walk-overwrite pattern. Silent no-op if any level is absent. */
    uint64_t *pml4  = vmm_window_map(pml4_phys);
    uint64_t  pml4e = pml4[pml4_idx];
    if (!(pml4e & VMM_FLAG_PRESENT)) { vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return; }

    uint64_t *pdpt  = vmm_window_map(ARCH_PTE_ADDR(pml4e));
    uint64_t  pdpte = pdpt[pdpt_idx];
    if (!(pdpte & VMM_FLAG_PRESENT)) { vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return; }

    uint64_t *pd  = vmm_window_map(ARCH_PTE_ADDR(pdpte));
    uint64_t  pde = pd[pd_idx];
    if (!(pde & VMM_FLAG_PRESENT) || (pde & PTE_PS)) {
        vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return;
    }

    uint64_t *pt  = vmm_window_map(ARCH_PTE_ADDR(pde));
    int did_unmap = 0;
    /* Clear ANY non-zero leaf PTE, not only PRESENT ones. A PROT_NONE page
     * (mprotect stored its phys in the PTE with PRESENT cleared — see
     * vmm_set_user_prot) is non-zero but not present. Every caller pairs this
     * with vmm_phys_of_user_raw()+pmm_free_page(phys): if we leave the PTE
     * holding the (now-freed) phys, the exit-time teardown (vmm_free_user_pml4,
     * which frees every pte != 0) frees that frame a SECOND time — a double-free
     * of a possibly-reallocated frame (heap corruption). Reachable via
     * mmap → mprotect(PROT_NONE) → munmap → exit. */
    if (pt[pt_idx] != 0) {
        pt[pt_idx] = 0;
        did_unmap = 1;
    }
    vmm_window_unmap();
    arch_vmm_invlpg(virt);

    spin_unlock_irqrestore(&vmm_window_lock, fl);

    /* TLB shootdown: other CPUs may have this VA cached.
     * Called outside vmm_window_lock to avoid deadlock. */
    if (did_unmap)
        tlb_shootdown(pml4_phys, virt, virt + VMM_PAGE_SIZE);
}

int
vmm_set_user_prot(uint64_t pml4_phys, uint64_t virt, uint64_t flags)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    uint64_t pml4_idx = (virt >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt >> 30) & 0x1FF;
    uint64_t pd_idx   = (virt >> 21) & 0x1FF;
    uint64_t pt_idx   = (virt >> 12) & 0x1FF;

    /* Walk-overwrite pattern. Return -1 if any level is absent. */
    uint64_t *pml4  = vmm_window_map(pml4_phys);
    uint64_t  pml4e = pml4[pml4_idx];
    if (!(pml4e & VMM_FLAG_PRESENT)) { vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return -1; }

    uint64_t *pdpt  = vmm_window_map(ARCH_PTE_ADDR(pml4e));
    uint64_t  pdpte = pdpt[pdpt_idx];
    if (!(pdpte & VMM_FLAG_PRESENT)) { vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return -1; }

    uint64_t *pd  = vmm_window_map(ARCH_PTE_ADDR(pdpte));
    uint64_t  pde = pd[pd_idx];
    if (!(pde & VMM_FLAG_PRESENT) || (pde & PTE_PS)) {
        vmm_window_unmap(); spin_unlock_irqrestore(&vmm_window_lock, fl); return -1;
    }

    uint64_t *pt  = vmm_window_map(ARCH_PTE_ADDR(pde));
    uint64_t  old = pt[pt_idx];

    /* If page was never mapped (no physical address), skip. */
    if (!(old & VMM_FLAG_PRESENT) && flags == 0) {
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return 0;  /* PROT_NONE on unmapped page is a no-op */
    }
    if (!(old & VMM_FLAG_PRESENT)) {
        /* PROT_NONE-stored page: a prior mprotect(PROT_NONE) cleared PRESENT
         * but kept the physical frame recorded in the PTE (pt[pt_idx] = phys
         * with no PRESENT bit). A non-zero PTE here means the frame is still
         * present and can be re-enabled with the new accessible flags. */
        uint64_t saved_phys = old ? ARCH_PTE_ADDR(old) : 0;
        if (saved_phys) {
            /* Rebuild the PTE from the stored phys with the new flags and
             * re-enable PRESENT (flags already carry VMM_FLAG_PRESENT here,
             * since flags == 0 was handled above).
             *
             * Preserve the software bits (VMM_FLAG_COW / VMM_FLAG_SHARED)
             * recorded in the stored PROT_NONE PTE — they identify a still-
             * shared COW frame or driver-owned shared RAM and must survive an
             * mprotect (see the matching comment in the normal rebuild below).
             * If the frame is COW and the caller now requests write access, the
             * page must stay read-only so the first write still faults into
             * vmm_cow_fault_handle (a writable+COW PTE would never fault → the
             * copy would never happen → cross-process aliasing). SHARED frames
             * are genuinely shared and stay writable (they are never COW). */
            uint64_t old_sw = old & (VMM_FLAG_COW | VMM_FLAG_SHARED);
            uint64_t newpte = saved_phys | arch_pte_from_flags(flags) | old_sw;
            if ((old_sw & VMM_FLAG_COW) && (flags & VMM_FLAG_WRITABLE))
                newpte &= ~(uint64_t)VMM_FLAG_WRITABLE;
            pt[pt_idx] = newpte;
            vmm_window_unmap();
            arch_vmm_invlpg(virt);
            spin_unlock_irqrestore(&vmm_window_lock, fl);
            tlb_shootdown(pml4_phys, virt, virt + VMM_PAGE_SIZE);
            return 0;
        }
        vmm_window_unmap();
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return -1;  /* genuinely no frame — can't set real prot */
    }

    /* Preserve physical address AND the software flags. arch_pte_from_flags
     * only builds the hardware PROT_* bits from the new prot, so without this
     * the rebuild would silently drop VMM_FLAG_COW (still-shared post-fork
     * frame) and VMM_FLAG_SHARED (driver-owned fb/memfd RAM). Dropping COW lets
     * mprotect(PROT_WRITE) make a still-shared frame writable without faulting
     * → two address spaces alias one live frame. Dropping SHARED makes the
     * teardown guards free driver RAM (fb double-free). Keep both. */
    uint64_t phys   = ARCH_PTE_ADDR(old);
    uint64_t old_sw = old & (VMM_FLAG_COW | VMM_FLAG_SHARED);
    if (flags == 0) {
        /* PROT_NONE: store phys with no PRESENT bit (CPU ignores the PTE) but
         * keep the address for munmap and the software bits so a later
         * mprotect that re-enables the page recovers its COW/SHARED status. */
        pt[pt_idx] = phys | old_sw;
    } else {
        uint64_t newpte = phys | arch_pte_from_flags(flags) | old_sw;
        /* A writable+COW PTE would never fault, so the copy-on-write break
         * would never run. Keep a still-shared COW page read-only; the first
         * write faults into vmm_cow_fault_handle, which copies and then makes
         * the new private frame writable. SHARED (genuinely shared driver RAM,
         * never COW) stays writable. */
        if ((old_sw & VMM_FLAG_COW) && (flags & VMM_FLAG_WRITABLE))
            newpte &= ~(uint64_t)VMM_FLAG_WRITABLE;
        pt[pt_idx] = newpte;
    }
    vmm_window_unmap();
    arch_vmm_invlpg(virt);
    spin_unlock_irqrestore(&vmm_window_lock, fl);

    /* TLB shootdown: other CPUs may have stale permissions cached.
     * Called outside vmm_window_lock to avoid deadlock. */
    tlb_shootdown(pml4_phys, virt, virt + VMM_PAGE_SIZE);
    return 0;
}

/* vmm_copy_user_pages — full copy of all user-half (PML4 entries 0-255) pages
 * from src_pml4 to dst_pml4.
 * For each present user leaf PTE in src_pml4: allocates a new frame via pmm,
 * copies contents via the two-window-slot mechanism, maps into dst_pml4.
 * Returns 0 on success, -1 on OOM.
 * Called by sys_fork to create the child address space. */
int
vmm_copy_user_pages(uint64_t src_pml4, uint64_t dst_pml4)
{
    uint64_t pml4i, pdpti, pdi, pti;
    uint32_t batch = 0;
    #define FORK_BATCH_SIZE 32

    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    for (pml4i = 0; pml4i < 256; pml4i++) {
        uint64_t *pml4 = vmm_window_map(src_pml4);
        uint64_t pml4e = pml4[pml4i];
        vmm_window_unmap();
        if (!(pml4e & VMM_FLAG_PRESENT)) continue;

        uint64_t pdpt_phys = ARCH_PTE_ADDR(pml4e);
        for (pdpti = 0; pdpti < 512; pdpti++) {
            uint64_t *pdpt = vmm_window_map(pdpt_phys);
            uint64_t pdpte = pdpt[pdpti];
            vmm_window_unmap();
            if (!(pdpte & VMM_FLAG_PRESENT)) continue;

            uint64_t pd_phys = ARCH_PTE_ADDR(pdpte);
            for (pdi = 0; pdi < 512; pdi++) {
                uint64_t *pd = vmm_window_map(pd_phys);
                uint64_t pde = pd[pdi];
                vmm_window_unmap();
                if (!(pde & VMM_FLAG_PRESENT)) continue;

                uint64_t pt_phys = ARCH_PTE_ADDR(pde);
                for (pti = 0; pti < 512; pti++) {
                    uint64_t *pgtbl = vmm_window_map(pt_phys);
                    uint64_t pte = pgtbl[pti];
                    vmm_window_unmap();
                    if (!(pte & VMM_FLAG_PRESENT)) continue;
                    if (!(pte & VMM_FLAG_USER)) continue;
                    /* Skip MMIO pages (WC/UC) — framebuffer, device MMIO.
                     * Copying MMIO via memcpy is extremely slow or can
                     * stall the CPU.  Child doesn't need these. */
                    if (pte & (VMM_FLAG_WC | VMM_FLAG_UCMINUS)) continue;

                    uint64_t src_phys = pte & ~0x8000000000000FFFULL;
                    /* Preserve all PTE flags including bit 63 (NX/XD bit). */
                    uint64_t flags    = pte &  0x8000000000000FFFULL;

                    /* Allocate destination frame */
                    uint64_t dst_phys = pmm_alloc_page();
                    if (!dst_phys) {
                        spin_unlock_irqrestore(&vmm_window_lock, fl);
                        return -1;
                    }

                    /* Copy via two window slots: slot 1 = src, slot 2 = dst */
                    void *src_va = vmm_window_map(src_phys);
                    void *dst_va = vmm_window_map2(dst_phys);
                    __builtin_memcpy(dst_va, src_va, 4096);
                    vmm_window_unmap2();
                    vmm_window_unmap();

                    /* Reconstruct virtual address */
                    uint64_t va = (pml4i << 39) | (pdpti << 30) |
                                  (pdi   << 21) | (pti   << 12);

                    if (vmm_map_user_page_nolock(dst_pml4, va, dst_phys, flags) < 0) {
                        pmm_free_page(dst_phys);
                        spin_unlock_irqrestore(&vmm_window_lock, fl);
                        return -1;
                    }

                    /* Drop and re-take the window lock every 32 pages so
                     * OTHER CPUs contending for vmm_window_lock can make
                     * progress during a large fork copy (the ticket lock
                     * is FIFO, so a waiter gets in at each gap).
                     *
                     * This is NOT an interrupt yield: fl was captured in
                     * syscall context where IF=0 (IA32_SFMASK clears IF on
                     * SYSCALL entry), so the irqrestore leaves interrupts
                     * off and fork stays non-preemptible — which sys_fork
                     * relies on (live-FPU snapshot taken before this copy,
                     * child frame construction).  An earlier comment here
                     * claimed to "yield to interrupts"; it never did. */
                    if (++batch >= FORK_BATCH_SIZE) {
                        batch = 0;
                        spin_unlock_irqrestore(&vmm_window_lock, fl);
                        fl = spin_lock_irqsave(&vmm_window_lock);
                    }
                }
            }
        }
    }
    spin_unlock_irqrestore(&vmm_window_lock, fl);
    return 0;
}

/* vmm_cow_user_pages — share user-half pages between src_pml4 and dst_pml4
 * using copy-on-write semantics (P1 audit activation).
 *
 * For each present user leaf PTE in src_pml4:
 *   - Writable pages: clear W bit and set COW bit in src PTE (parent now
 *     can't write without taking a fault); clone the PTE into dst with
 *     the same flags; pmm_ref_page the phys frame; arch_vmm_invlpg the
 *     parent VA so its TLB entry picks up the new RO mapping.
 *   - Read-only pages: share directly with no flag changes; pmm_ref_page
 *     the frame. No invlpg needed since the mapping didn't change.
 *   - MMIO pages (WC/UC-): skip — framebuffer and device memory are not
 *     refcounted, and the child has no use for them.
 *
 * Returns 0 on success. On OOM during PT allocation, the partial state
 * is rolled back by the caller via vmm_free_user_pml4 on dst_pml4.
 */
int
vmm_cow_user_pages(uint64_t src_pml4, uint64_t dst_pml4)
{
    uint64_t pml4i, pdpti, pdi, pti;
    uint32_t batch = 0;
    #define COW_BATCH_SIZE 256

    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    for (pml4i = 0; pml4i < 256; pml4i++) {
        uint64_t *pml4 = vmm_window_map(src_pml4);
        uint64_t pml4e = pml4[pml4i];
        vmm_window_unmap();
        if (!(pml4e & VMM_FLAG_PRESENT)) continue;

        uint64_t pdpt_phys = ARCH_PTE_ADDR(pml4e);
        for (pdpti = 0; pdpti < 512; pdpti++) {
            uint64_t *pdpt = vmm_window_map(pdpt_phys);
            uint64_t pdpte = pdpt[pdpti];
            vmm_window_unmap();
            if (!(pdpte & VMM_FLAG_PRESENT)) continue;

            uint64_t pd_phys = ARCH_PTE_ADDR(pdpte);
            for (pdi = 0; pdi < 512; pdi++) {
                uint64_t *pd = vmm_window_map(pd_phys);
                uint64_t pde = pd[pdi];
                vmm_window_unmap();
                if (!(pde & VMM_FLAG_PRESENT)) continue;

                uint64_t pt_phys = ARCH_PTE_ADDR(pde);
                for (pti = 0; pti < 512; pti++) {
                    uint64_t *pgtbl = vmm_window_map(pt_phys);
                    uint64_t pte = pgtbl[pti];
                    vmm_window_unmap();
                    if (!(pte & VMM_FLAG_PRESENT)) continue;
                    if (!(pte & VMM_FLAG_USER)) continue;
                    /* Skip MMIO (framebuffer, device memory). */
                    if (pte & (VMM_FLAG_WC | VMM_FLAG_UCMINUS)) continue;

                    uint64_t phys = pte & ~0x8000000000000FFFULL;
                    uint64_t flags = pte & 0x8000000000000FFFULL;

                    /* Reconstruct VA for the invlpg below. */
                    uint64_t va = (pml4i << 39) | (pdpti << 30) |
                                  (pdi   << 21) | (pti   << 12);

                    if (flags & VMM_FLAG_SHARED) {
                        /* Driver-owned shared RAM (sys_fb_map framebuffer
                         * backing — WB system RAM, so not caught by the WC/UC
                         * MMIO skip above). Inherit it as-is into the child:
                         * same frame, same flags (still writable, NO write-
                         * protect, NO COW), and NO pmm_ref_page — the PMM does
                         * not track this frame per-mapping (the GPU driver owns
                         * it; teardown leaves it alone). COW-breaking it would
                         * fork the compositor off the live scanout; ref'ing it
                         * would unbalance a frame teardown never frees. */
                        if (vmm_map_user_page_nolock(dst_pml4, va, phys, flags) < 0) {
                            spin_unlock_irqrestore(&vmm_window_lock, fl);
                            return -1;
                        }
                    } else if (flags & VMM_FLAG_WRITABLE) {
                        /* Writable → RO + COW for both parent and child.
                         * Write-protect the parent first so any concurrent
                         * write from the parent will fault and either
                         * complete the COW via the fault handler or block
                         * on vmm_window_lock until we finish here. */
                        uint64_t cow_flags =
                            (flags & ~(uint64_t)VMM_FLAG_WRITABLE) | VMM_FLAG_COW;

                        /* Update parent PTE: clear W, set COW. No per-page
                         * invlpg here: the parent is suspended in this syscall
                         * (IF=0, not running) for the whole walk, so it cannot
                         * observe a stale writable TLB entry before the single
                         * full TLB flush at the end of this function. Batching
                         * 16384 invlpgs into one CR3 reload is a large saving on
                         * a big address space. (Sibling CPUs are handled by the
                         * thread_count>1 tlb_flush_all_cpus in sys_fork.) */
                        uint64_t *src_pgtbl = vmm_window_map(pt_phys);
                        src_pgtbl[pti] = phys | cow_flags;
                        vmm_window_unmap();

                        /* Install into child with same RO+COW flags. */
                        if (vmm_map_user_page_nolock(dst_pml4, va, phys, cow_flags) < 0) {
                            spin_unlock_irqrestore(&vmm_window_lock, fl);
                            return -1;
                        }
                        /* Now the frame has two sharers. */
                        pmm_ref_page(phys);
                    } else {
                        /* Read-only → share as-is. */
                        if (vmm_map_user_page_nolock(dst_pml4, va, phys, flags) < 0) {
                            spin_unlock_irqrestore(&vmm_window_lock, fl);
                            return -1;
                        }
                        pmm_ref_page(phys);
                    }

                    /* Drop and re-take the window lock periodically so
                     * other CPUs contending for vmm_window_lock can make
                     * progress.  NOT an interrupt yield — IF stays 0 in
                     * syscall context (see the matching comment in
                     * vmm_copy_user_pages). */
                    if (++batch >= COW_BATCH_SIZE) {
                        batch = 0;
                        /* SMP fairness: drop+retake the window lock so other
                         * CPUs can progress. Use RAW spin_unlock/spin_lock —
                         * NOT irqrestore/irqsave — so IRQs stay OFF (the outer
                         * irqsave disabled them). Restoring IRQs here re-enabled
                         * them mid-walk; over a huge address space (~1000 batch
                         * windows) a timer would preempt this task mid-syscall
                         * and it never resumed (Ladybird's COW fork hung). */
                        spin_unlock(&vmm_window_lock);
                        spin_lock(&vmm_window_lock);
                    }
                }
            }
        }
    }
    spin_unlock_irqrestore(&vmm_window_lock, fl);

    /* One full local TLB flush instead of a per-page invlpg during the walk:
     * the parent's now-read-only COW PTEs must not be served from a stale
     * writable TLB entry. A CR3 reload drops every entry at once — far cheaper
     * than 16384 individual invlpgs on a large address space. Done after the
     * window lock is released (it touches only this CPU's CR3). */
    tlb_flush_local();
    return 0;
}

/* vmm_cow_fault_handle — resolve a copy-on-write page fault.
 *
 * Called from the page fault handler when a write faults on a present,
 * user, RO page in the current process. Walks the current PML4 to find
 * the leaf PTE, verifies VMM_FLAG_COW is set, allocates a fresh frame,
 * copies the old contents, and updates the PTE to point at the new
 * frame with W set and COW cleared.
 *
 * Returns 0 if the fault was handled (caller should iretq back to
 * retry the instruction), -1 if the page is not COW (caller should
 * deliver SIGSEGV as usual), or -2 on OOM (caller should SIGBUS).
 */
int
vmm_cow_fault_handle(uint64_t pml4_phys, uint64_t fault_va)
{
    uint64_t pml4i = (fault_va >> 39) & 0x1FF;
    uint64_t pdpti = (fault_va >> 30) & 0x1FF;
    uint64_t pdi   = (fault_va >> 21) & 0x1FF;
    uint64_t pti   = (fault_va >> 12) & 0x1FF;

    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);

    /* Walk to the leaf PTE. */
    uint64_t *pml4 = vmm_window_map(pml4_phys);
    uint64_t pml4e = pml4[pml4i];
    vmm_window_unmap();
    if (!(pml4e & VMM_FLAG_PRESENT)) {
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return -1;
    }

    uint64_t pdpt_phys = ARCH_PTE_ADDR(pml4e);
    uint64_t *pdpt = vmm_window_map(pdpt_phys);
    uint64_t pdpte = pdpt[pdpti];
    vmm_window_unmap();
    if (!(pdpte & VMM_FLAG_PRESENT)) {
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return -1;
    }

    uint64_t pd_phys = ARCH_PTE_ADDR(pdpte);
    uint64_t *pd = vmm_window_map(pd_phys);
    uint64_t pde = pd[pdi];
    vmm_window_unmap();
    if (!(pde & VMM_FLAG_PRESENT)) {
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return -1;
    }

    uint64_t pt_phys = ARCH_PTE_ADDR(pde);
    uint64_t *pgtbl = vmm_window_map(pt_phys);
    uint64_t pte = pgtbl[pti];
    vmm_window_unmap();

    /* Spurious stale-TLB write fault (SMP): in a shared address space
     * (CLONE_VM siblings on >1 CPU), one thread may have already broken
     * this COW page — the PTE is now present, user, WRITABLE — while a
     * sibling on another CPU still holds a stale read-only TLB entry and
     * faults on its write. The page is genuinely writable now, so this is
     * not a violation: just invalidate the stale local entry and resume.
     * (The breaking thread only did a local invlpg; this is where the
     * other CPUs reconcile.) */
    if ((pte & VMM_FLAG_PRESENT) && (pte & VMM_FLAG_USER) &&
        (pte & VMM_FLAG_WRITABLE)) {
        arch_vmm_invlpg(fault_va);
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return 0;
    }

    if (!(pte & VMM_FLAG_PRESENT) ||
        !(pte & VMM_FLAG_USER)     ||
        !(pte & VMM_FLAG_COW)) {
        /* Not a COW fault — real protection violation. */
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return -1;
    }

    uint64_t old_phys = pte & ~0x8000000000000FFFULL;
    uint64_t flags    = pte &  0x8000000000000FFFULL;

    /* Reuse-in-place fast path: if this frame is already singly-owned, the
     * other sharer (the fork peer) has dropped its reference — by execve
     * (vmm_free_user_pages), exit, or its own earlier COW break. There is
     * nothing left to protect, so just clear COW and set writable on the
     * existing frame: no allocation, no 4 KB copy, no free. This is what
     * makes COW fork a net win even for the fork+exec pattern (the child
     * execs immediately, dropping the clone, so every subsequent parent
     * write hits this path and pays only a trap + PTE flip instead of the
     * eager copy's per-page memcpy). Without it, COW always copied and was
     * measured a regression (the reason COW was previously left disabled). */
    if (pmm_page_refcount(old_phys) == 1) {
        uint64_t reuse_flags =
            (flags & ~(uint64_t)VMM_FLAG_COW) | VMM_FLAG_WRITABLE;
        uint64_t *rpgtbl = vmm_window_map(pt_phys);
        rpgtbl[pti] = old_phys | reuse_flags;
        vmm_window_unmap();
        arch_vmm_invlpg(fault_va);
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return 0;
    }

    /* Allocate a fresh frame and copy.
     * pmm_alloc_page sets refcount 1 for the new frame. */
    uint64_t new_phys = pmm_alloc_page();
    if (!new_phys) {
        spin_unlock_irqrestore(&vmm_window_lock, fl);
        return -2;   /* OOM */
    }
    void *src_va = vmm_window_map(old_phys);
    void *dst_va = vmm_window_map2(new_phys);
    __builtin_memcpy(dst_va, src_va, 4096);
    vmm_window_unmap2();
    vmm_window_unmap();

    /* Update the PTE: new frame, W set, COW cleared. */
    uint64_t new_flags =
        (flags & ~(uint64_t)VMM_FLAG_COW) | VMM_FLAG_WRITABLE;
    uint64_t *wpgtbl = vmm_window_map(pt_phys);
    wpgtbl[pti] = new_phys | new_flags;
    vmm_window_unmap();
    arch_vmm_invlpg(fault_va);

    spin_unlock_irqrestore(&vmm_window_lock, fl);

    /* Drop the old frame's refcount. If we were the last sharer this
     * frees it; otherwise (refcount was >= 2) the other sharers keep
     * reading the unchanged contents. */
    pmm_free_page(old_phys);
    return 0;
}



/* vmm_write_user_bytes — copy len bytes from kernel src into user virtual
 * address range [va, va+len) within pml4_phys.  Handles writes crossing
 * page boundaries by splitting at each page boundary.  Uses the mapped-window
 * allocator; pages must already be mapped.
 * Returns 0 on success, -1 if any page in the range is not mapped. */
int
vmm_write_user_bytes(uint64_t pml4_phys, uint64_t va,
                     const void *src, uint64_t len)
{
    const uint8_t *s = (const uint8_t *)src;
    uint64_t done = 0;
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    while (done < len) {
        uint64_t cur_va    = va + done;
        uint64_t pg_va     = cur_va & ~0xFFFULL;
        uint64_t off_in_pg = cur_va & 0xFFFULL;
        uint64_t chunk     = 4096ULL - off_in_pg;
        if (chunk > len - done) chunk = len - done;

        uint64_t phys = vmm_phys_of_user_nolock(pml4_phys, pg_va);
        if (!phys) {
            spin_unlock_irqrestore(&vmm_window_lock, fl);
            return -1;
        }

        uint8_t *dst = (uint8_t *)vmm_window_map(phys) + off_in_pg;
        __builtin_memcpy(dst, s + done, chunk);
        vmm_window_unmap();

        done += chunk;
    }
    spin_unlock_irqrestore(&vmm_window_lock, fl);
    return 0;
}

/* vmm_write_user_u64 — write one uint64_t to user VA in pml4_phys. */
int
vmm_write_user_u64(uint64_t pml4_phys, uint64_t va, uint64_t val)
{
    return vmm_write_user_bytes(pml4_phys, va, &val, sizeof(val));
}

/* vmm_free_user_pages — free only leaf physical frames in user half.
 * Does NOT free PT/PD/PDPT pages and does NOT free the PML4 itself.
 * Intended for sys_execve: the process keeps its PML4 and page-table
 * structure, discards only the old data/text frames, then loads new ones.
 *
 * The inner PT loop holds the window open across all 512 slots.  This is
 * safe because pmm_free_page does not call vmm_window_map; the non-
 * reentrancy guarantee holds for single-CPU operation (Phase 15 scope). */
void
vmm_free_user_pages(uint64_t pml4_phys)
{
    irqflags_t fl = spin_lock_irqsave(&vmm_window_lock);
    uint64_t pml4i, pdpti, pdi, pti;
    uint32_t batch = 0;
    for (pml4i = 0; pml4i < 256; pml4i++) {
        uint64_t *pml4 = vmm_window_map(pml4_phys);
        uint64_t pml4e = pml4[pml4i];
        vmm_window_unmap();
        if (!(pml4e & VMM_FLAG_PRESENT)) continue;

        uint64_t pdpt_phys = ARCH_PTE_ADDR(pml4e);
        for (pdpti = 0; pdpti < 512; pdpti++) {
            uint64_t *pdpt = vmm_window_map(pdpt_phys);
            uint64_t pdpte = pdpt[pdpti];
            vmm_window_unmap();
            if (!(pdpte & VMM_FLAG_PRESENT)) continue;
            if (pdpte & PTE_PS) continue; /* 1GB page — unexpected, skip */

            uint64_t pd_phys = ARCH_PTE_ADDR(pdpte);
            for (pdi = 0; pdi < 512; pdi++) {
                uint64_t *pd = vmm_window_map(pd_phys);
                uint64_t pde = pd[pdi];
                vmm_window_unmap();
                if (!(pde & VMM_FLAG_PRESENT)) continue;
                if (pde & PTE_PS) continue; /* 2MB page — unexpected, skip */

                uint64_t pt_phys = ARCH_PTE_ADDR(pde);
                /* Hold window open across all PT slots: pmm_free_page does
                 * not call vmm_window_map so the mapping remains valid. */
                uint64_t *pt = vmm_window_map(pt_phys);
                for (pti = 0; pti < 512; pti++) {
                    uint64_t pte = pt[pti];
                    if (pte != 0) {
                        pt[pti] = 0;
                        /* VMM_FLAG_SHARED: driver-owned RAM (fb backing) — clear
                         * the PTE for the new image but do NOT free the frame
                         * (the GPU driver owns it; see vmm.h). */
                        if (pte & VMM_FLAG_SHARED)
                            continue;
                        uint64_t phys = ARCH_PTE_ADDR(pte);
                        if (phys)
                            pmm_free_page(phys);
                    }
                }
                vmm_window_unmap();

                /* Yield to interrupts periodically so other tasks
                 * can run during large page teardowns (execve). */
                if (++batch >= 32) {
                    batch = 0;
                    spin_unlock_irqrestore(&vmm_window_lock, fl);
                    fl = spin_lock_irqsave(&vmm_window_lock);
                }
            }
        }
    }
    spin_unlock_irqrestore(&vmm_window_lock, fl);
}
