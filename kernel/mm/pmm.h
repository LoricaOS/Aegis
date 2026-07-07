#ifndef PMM_H
#define PMM_H

#include <stdint.h>
#include "../limits.h"

#define PAGE_SIZE AEGIS_PAGE_SIZE

/* Initialise the physical memory manager.
 * Requires arch_mm_init() to have been called first.
 * Prints [PMM] OK on success; panics on failure. */
void pmm_init(void);

/* Second-phase init: swap the 4GB static bootstrap bitmap for a full
 * RAM-sized one (allocated from KVA, so no fixed cap). Call once, after
 * kva_init() and before pmm_set_alloc_high_pref(1). No-op on <= 4GB machines.
 * Without this, only the first 4GB of RAM is usable. */
void pmm_init_late(void);

/* Allocate one 4KB physical page.
 * Returns the physical address of the page, or 0 on OOM.
 * Address 0 is always reserved, so 0 is unambiguous as an error sentinel.
 *
 * NOTE: single-page (4KB) allocation only for the general allocator. For
 * physically-contiguous multi-page DMA buffers use pmm_alloc_contig_low(). */
uint64_t pmm_alloc_page(void);

/* Allocate one 4KB page guaranteed to have a physical address below 4 GB,
 * for device DMA buffers whose address is programmed into hardware we don't
 * want to assume is 64-bit-DMA-capable (NVMe, virtio). Returns 0 if the low
 * pool is exhausted. */
uint64_t pmm_alloc_page_low(void);

/* Allocate n PHYSICALLY-CONTIGUOUS 4KB pages below 4 GB. Returns the base
 * physical address (page-aligned) of the run, or 0 if no such run exists.
 * For flat-ring DMA devices (e.g. RTL8139's receive buffer) that require a
 * single contiguous physical region the hardware DMAs into linearly — unlike
 * descriptor-ring NICs which use per-descriptor scattered pages. The pages are
 * NOT individually freeable yet; intended for permanent boot-time driver
 * buffers. A first-fit linear bitmap scan; bound the size to a few pages. */
uint64_t pmm_alloc_contig_low(uint64_t n);

/* Enable/disable preferring high (>=4GB) RAM for general pmm_alloc_page().
 * Call with 1 AFTER vmm_init/kva_init so the low pool stays free for DMA;
 * leave it off during early boot so the first page tables land below 1 GB
 * (reached via the identity map before the window allocator exists). */
void pmm_set_alloc_high_pref(int on);

/* Free a page previously returned by pmm_alloc_page().
 * addr must be PAGE_SIZE-aligned.
 *
 * Refcount semantics (COW fork infrastructure): pmm_free_page decrements
 * the page's refcount and only clears the bitmap bit when refcount reaches
 * zero. Every allocation starts at refcount 1, so today every free is the
 * final one and the behavior matches a plain bitmap free. Once sys_fork
 * is updated to share pages via pmm_ref_page, the non-final decrements
 * become meaningful. */
void pmm_free_page(uint64_t addr);

/* Increment refcount of an already-allocated page (COW fork).
 * Panics if the page isn't allocated. The refcount is uint16_t (max 65535
 * sharers); the kernel's hard process/VMA caps keep a frame's sharer count far
 * below that, so the overflow guard is unreachable in practice (secfix M1 — it
 * was uint8_t, which an unprivileged fork-without-exec bomb could overflow into
 * panic_halt). */
void pmm_ref_page(uint64_t addr);

/* Read the refcount of an allocated page: 1 for a singly-owned page, the
 * stored count (>= 2) for a shared page, 0 for an address outside managed RAM.
 * Used by the COW write-fault handler's reuse-in-place fast path. */
uint16_t pmm_page_refcount(uint64_t addr);

/* pmm_unreserve_region — release a boot-time reserved physical range back
 * to the allocator (e.g. multiboot2 module pages after the ramdisk copy).
 * Only pages fully contained in [base, base+len) AND inside usable RAM
 * are freed (start rounds up, end rounds down — at most 2 boundary pages
 * per range stay reserved). Already-free pages and pages with a live
 * refcount are skipped, so the call is idempotent and never double-frees.
 * Returns the number of pages released. */
uint64_t pmm_unreserve_region(uint64_t base, uint64_t len);

/* pmm_set_debug — enable/disable the double-free sentinel (off by default).
 * When on, pmm_free_page logs a symbolized backtrace at any free of a
 * managed-RAM page whose bitmap bit is already clear (a double-free, or a free
 * of a never-allocated page). Gated by the `pmm_debug` kernel cmdline token so
 * the boot oracle (exact-match serial) stays unaffected with it OFF. Intended
 * for the SMP corruption hunt: turns the whole double-free class self-diagnosing
 * (a double-freed frame is a wrong-physical-frame producer). */
void pmm_set_debug(int on);

/* pmm_set_acct / pmm_acct_enabled / pmm_acct_dump — ref/unref accounting
 * diagnostic for the COW teardown-refcount hunt (improve-mm T1). OFF by default
 * (gated by the `pmm_acct` cmdline token) so the boot oracle is unaffected. When
 * on, the PMM keeps a cumulative ledger of allocs / frees-to-zero / ref
 * increments / shared-page decrements / double-frees; pmm_acct_dump(tag) prints
 * a one-line scoreboard plus a refcount-table consistency check. The headline
 * signal is dblfree (a frame freed one time too many). vmm_free_user_pml4 calls
 * pmm_acct_dump("teardown") per address-space teardown when enabled. See the
 * block comment in pmm.c for scope/limits. */
void pmm_set_acct(int on);
int  pmm_acct_enabled(void);
void pmm_acct_dump(const char *tag);

/* pmm_total_pages — return total managed physical pages. */
uint64_t pmm_total_pages(void);

/* pmm_ram_max_page — highest usable-RAM page + 1 (full physical extent). */
uint64_t pmm_ram_max_page(void);

/* pmm_free_pages — return count of currently free physical pages.
 * Scans the bitmap; O(n) where n = PMM_MAX_PAGES/8. */
uint64_t pmm_free_pages(void);

#endif /* PMM_H */
