#ifndef AEGIS_VMM_H
#define AEGIS_VMM_H

#include <stdint.h>

/* Abstract page-mapping flags. Each architecture translates these to
 * hardware PTE bits via arch_pte_from_flags() in arch_vmm.h.
 * On x86-64 the values happen to match the hardware PTE bit positions;
 * ARM64 provides a real translation. Never OR these directly into a PTE
 * without calling arch_pte_from_flags() first. */
#define VMM_FLAG_PRESENT  (1UL << 0)
#define VMM_FLAG_WRITABLE (1UL << 1)
#define VMM_FLAG_USER     (1UL << 2)
/* Cache type bits — only valid after arch_pat_init() has run.
 *
 * With IA32_PAT[1]=WC (set by arch_pat_init):
 *   VMM_FLAG_WC      = PWT bit → PAT entry 1 → Write-Combining
 *   VMM_FLAG_UCMINUS = PCD bit → PAT entry 2 → UC- (weak uncacheable)
 *
 * NOTE: UC- (PA2) is NOT the same as strong-UC (PA3). The PCIe ECAM driver uses
 * PWT=1, PCD=1 (full PTE flags 0x1B = Present|Write|PWT|PCD) → PA3=UC (strong).
 * Use VMM_FLAG_UCMINUS only where MTRR override is acceptable.
 *
 * On x86-64 these map to PTE bits 3 (PWT) and 4 (PCD). Other architectures
 * translate via arch_pte_from_flags().
 * vmm_map_page ORs flags into the PTE without masking, so these pass
 * through as-is to hardware. */
#define VMM_FLAG_WC       (1UL << 3)   /* Write-Combining  (PWT=1, PCD=0) → PA1 */
#define VMM_FLAG_UCMINUS  (1UL << 4)   /* UC-weak          (PWT=0, PCD=1) → PA2 */
/*
 * Copy-on-write marker (P1 audit infrastructure).
 *
 * On x86-64 this maps to PTE bit 9, which is one of the three OS-available
 * bits (9/10/11) that the MMU ignores. The kernel uses it to remember
 * that a page fault on a present + user + read-only page should be
 * handled by allocating a fresh frame and copying, rather than by
 * delivering SIGSEGV.
 *
 * Today nothing sets this bit — it is infrastructure for the eventual
 * sys_fork rewrite that will mark writable user pages as RO+COW and
 * defer the frame copy until the first write fault.
 *
 * arch_pte_from_flags must forward this bit into the emitted PTE.
 */
#define VMM_FLAG_COW      (1UL << 9)
/* VMM_FLAG_SHARED — this user PTE maps a frame that the process does NOT own:
 * shared device/driver RAM (e.g. the virtio-gpu framebuffer backing published
 * by sys_fb_map — WB-cached system RAM owned by the GPU driver, mapped into
 * every GUI process at the same physical frames). Software PTE bit 10 (OS-
 * available on x86-64; arch_pte_from_flags forwards it as an identity).
 *
 * Such pages must be EXEMPT from the two page-table walks that assume every
 * present user leaf is a private, refcounted, owned frame:
 *   - fork (vmm_cow_user_pages): share the mapping as-is (same frame, still
 *     writable, NO write-protect, NO pmm_ref_page, NO COW) — a copy-on-write
 *     break would fork the compositor off the live scanout, and a ref would
 *     unbalance a frame the PMM doesn't track per-mapping.
 *   - teardown (vmm_free_user_pml4 / vmm_free_user_pages): do NOT pmm_free_page
 *     the frame — the GPU driver owns it; freeing it on process exit recycled
 *     the live framebuffer into a kernel stack (wild-write corruption, the
 *     graphical-NVMe #GP). The PTE is still cleared in the execve path. */
#define VMM_FLAG_SHARED   (1UL << 10)
#define VMM_FLAG_NX       (1UL << 63)

/* vmm_init — build the initial higher-half page tables and activate them.
 * Must be called after pmm_init(). Prints [VMM] OK on success. */
void vmm_init(void);

/* vmm_map_page — map a single 4KB page.
 * virt and phys must be 4KB-aligned. flags is a combination of VMM_FLAG_*. */
void vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags);

/* vmm_unmap_page — unmap a single 4KB page and invalidate its TLB entry.
 * virt must be 4KB-aligned and must currently be mapped.
 * Valid for 4KB mappings only. Must not be called on addresses backed by
 * 2MB huge pages; doing so will panic the kernel. */
void vmm_unmap_page(uint64_t virt);

/* vmm_unmap_page_noshoot — like vmm_unmap_page but skips the cross-CPU TLB
 * shootdown (local invlpg only).  For batch unmaps: the caller MUST issue one
 * tlb_shootdown_kernel() over the whole range afterwards, or other CPUs keep
 * stale translations (the SMP recycled-KVA corruption bug). */
void vmm_unmap_page_noshoot(uint64_t virt);

/* Allocate a new PML4 and copy kernel high entries [256..511] from the
 * master PML4. Returns physical address of the new PML4.
 * Valid while identity map [0..4MB) is active (Phase 5 constraint). */
uint64_t vmm_create_user_pml4(void);

/* Map a single 4KB page in pml4_phys (NOT the active kernel PML4).
 * All intermediate page-table entries (PML4e, PDPTe, PDe) created for
 * this mapping have VMM_FLAG_USER set — required because the x86-64 MMU
 * checks the USER bit at every level of the page-table walk.
 * A leaf PTE with USER set but any ancestor without USER causes a ring-3
 * #PF even if the leaf mapping is correct.
 * flags: VMM_FLAG_PRESENT | VMM_FLAG_USER | VMM_FLAG_WRITABLE as needed. */
void vmm_map_user_page(uint64_t pml4_phys, uint64_t virt,
                       uint64_t phys, uint64_t flags);

/* vmm_try_map_user_page — map [virt]→[phys], but TOLERATE an already-present PTE
 * instead of panicking. Returns 0 if it installed the mapping, 1 if the PTE was
 * already present (a concurrent thread mapped it first — caller frees its frame),
 * -1 on OOM allocating a page table. The PTE check+set is under vmm_window_lock,
 * so this is the SMP-safe demand-fault map: two threads faulting the same lazy
 * page serialize on the window lock; one wins (0), the other loses (1). */
int vmm_try_map_user_page(uint64_t pml4_phys, uint64_t virt,
                          uint64_t phys, uint64_t flags);

/* Load pml4_phys into CR3. Flushes TLB. */
void vmm_switch_to(uint64_t pml4_phys);

/* Return the physical address of the master (kernel) PML4.
 * Used by the scheduler to restore the master PML4 after a user task runs. */
uint64_t vmm_get_master_pml4(void);

/* vmm_phys_of — return the physical address of the 4KB page mapped at virt.
 * Uses the walk-overwrite window pattern. Panics if any level is not present. */
uint64_t vmm_phys_of(uint64_t virt);

/* vmm_teardown_identity — clear pml4[0] (the [0..512GB) identity range)
 * and reload CR3 for a full TLB flush. Must be called after all kernel
 * objects have been allocated via kva (so no identity-map cast remains).
 * Prints [VMM] OK: identity map removed. */
void vmm_teardown_identity(void);

/* vmm_free_user_pml4 — walk PML4 entries 0–255 (user half) and free:
 *   - all leaf physical frames (PT entries)
 *   - all intermediate page-table pages (PT, PD, PDPT)
 *   - the PML4 page itself
 *
 * MUST NOT touch PML4 entries 256–511 (kernel half): those pages are shared
 * with the master PML4; freeing them corrupts every other process and the
 * kernel itself.
 *
 * Uses the mapped-window allocator for all page-table accesses.
 * Caller must have switched to the master PML4 before calling (sched_exit
 * does this at entry). Single-CPU only: no TLB shootdown. */
void vmm_free_user_pml4(uint64_t pml4_phys);

/* vmm_phys_of_user — walk pml4_phys to find the physical address mapped at virt.
 * Returns physical address, or 0 if not mapped (PRESENT bit must be set).
 * Uses the window allocator. Safe to call with any PML4 (not just active CR3). */
uint64_t vmm_phys_of_user(uint64_t pml4_phys, uint64_t virt);

/* vmm_user_range_mapped — 1 if every page of [addr, addr+len) has a present
 * leaf PTE in pml4_phys.  Backs user_ptr_valid's mapped-check (uaccess has
 * no fault fixup; unmapped user pointers would panic the kernel). */
int vmm_user_range_mapped(uint64_t pml4_phys, uint64_t addr, uint64_t len);

/* vmm_phys_of_user_raw — like vmm_phys_of_user but returns the physical address
 * for any non-zero leaf PTE regardless of PRESENT bit. Use for munmap to find
 * and free physical frames backing PROT_NONE pages (PRESENT cleared by mprotect). */
uint64_t vmm_phys_of_user_raw(uint64_t pml4_phys, uint64_t virt);

/* vmm_pte_of_user_raw — returns the full leaf PTE (flags incl.) for virt, or 0.
 * Lets callers test software bits (e.g. VMM_FLAG_SHARED) before freeing a frame. */
uint64_t vmm_pte_of_user_raw(uint64_t pml4_phys, uint64_t virt);

/* vmm_unmap_user_page — clear the PTE for virt in pml4_phys and invlpg.
 * Does not free the physical page. Caller frees via pmm_free_page.
 * Silent no-op if the page is not mapped. */
void vmm_unmap_user_page(uint64_t pml4_phys, uint64_t virt);

/* vmm_set_user_prot — change PTE flags for a single user page in pml4_phys.
 * Walks the 4-level page table to the leaf PTE, preserves the physical address,
 * and overwrites the flag bits. Issues invlpg for virt.
 * flags=0 clears PRESENT (PROT_NONE). Returns 0 on success, -1 if the page
 * is not mapped (caller should skip silently, matching Linux mprotect). */
int vmm_set_user_prot(uint64_t pml4_phys, uint64_t virt, uint64_t flags);

/* vmm_window_map — map a physical page into the kernel window slot.
 * Returns a pointer to the mapped VA. Not reentrant — only one mapping
 * active at a time (protected by vmm_window_lock internally).
 * Caller must call vmm_window_unmap() when done. */
void *vmm_window_map(uint64_t phys);

/* vmm_window_unmap — clear the window PTE and flush TLB. */
void vmm_window_unmap(void);

/* vmm_zero_page — zero the physical page at phys using the mapped-window slot.
 * Required for MAP_ANONYMOUS: musl's heap allocator depends on zeroed pages.
 * Uses the internal vmm_window_map/vmm_window_unmap pair. */
void vmm_zero_page(uint64_t phys);

/* vmm_write_phys_bytes — copy len bytes from src into physical page phys at
 * byte offset off (off+len <= 4096). Fills a frame before it is user-mapped. */
void vmm_write_phys_bytes(uint64_t phys, uint32_t off,
                          const void *src, uint32_t len);

/* vmm_copy_from_phys — copy len bytes from offset off within physical page phys
 * into dst, under vmm_window_lock (safe for callers outside vmm.c that cannot
 * take the static window lock). off+len must be <= 4096. */
void vmm_copy_from_phys(void *dst, uint64_t phys, uint32_t off, uint32_t len);

/* vmm_copy_user_pages — full copy of all user-half (PML4 entries 0-255) pages
 * from src_pml4 to dst_pml4.
 * For each present user leaf PTE in src_pml4: allocates a new frame via pmm,
 * copies contents via the two-window-slot mechanism, maps into dst_pml4.
 * Returns 0 on success, -1 on OOM.
 * Kept for reference / fallback; sys_fork uses vmm_cow_user_pages below. */
int vmm_copy_user_pages(uint64_t src_pml4, uint64_t dst_pml4);

/* vmm_cow_user_pages — share user-half pages using copy-on-write (P1).
 *
 * Clears the W bit and sets VMM_FLAG_COW on every writable user page in
 * both src_pml4 and dst_pml4, leaving them pointing at the same physical
 * frames. Read-only pages are shared directly. Per-page refcounts are
 * bumped via pmm_ref_page. The parent's TLB is invalidated for each
 * modified page so subsequent writes take a fault and are handled by
 * vmm_cow_fault_handle.
 * Returns 0 on success, -1 on OOM. On failure the caller discards
 * dst_pml4 via vmm_free_user_pml4 which will unref the partially
 * populated pages.
 */
int vmm_cow_user_pages(uint64_t src_pml4, uint64_t dst_pml4);

/* vmm_cow_fault_handle — resolve a COW page fault.
 * pml4_phys: the faulting process's top-level page table.
 * fault_va:  the faulting virtual address (CR2).
 *
 * Returns 0 if the fault was handled (retry the instruction), -1 if the
 * target page is not COW (deliver SIGSEGV), -2 on OOM (deliver SIGBUS).
 */
int vmm_cow_fault_handle(uint64_t pml4_phys, uint64_t fault_va);

/* vmm_free_user_pages — free all leaf physical frames mapped in user half
 * (PML4 entries 0-255) of pml4_phys. Does NOT free PT/PD/PDPT pages and
 * does NOT free the PML4 itself. Zeros the leaf PTEs after freeing.
 *
 * Contrast with vmm_free_user_pml4 which also frees the page-table pages.
 * Use vmm_free_user_pages for sys_execve (process keeps its PML4 and
 * reloads new mappings). Use vmm_free_user_pml4 for waitpid zombie reap.
 *
 * Caller must reload CR3 after calling to flush stale TLB entries. */
void vmm_free_user_pages(uint64_t pml4_phys);

/* vmm_write_user_bytes — copy len bytes from kernel src into user VA range
 * [va, va+len) in pml4_phys.  Handles writes that cross page boundaries.
 * Uses the mapped-window allocator; caller must ensure pages are mapped.
 * Returns 0 on success, -1 if a page is not mapped. */
int vmm_write_user_bytes(uint64_t pml4_phys, uint64_t va,
                         const void *src, uint64_t len);

/* vmm_write_user_u64 — write one uint64_t value to user VA in pml4_phys.
 * Returns 0 on success, -1 if the page is not mapped.
 * Convenience wrapper around vmm_write_user_bytes. */
int vmm_write_user_u64(uint64_t pml4_phys, uint64_t va, uint64_t val);

#endif /* AEGIS_VMM_H */
