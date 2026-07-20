#ifndef AEGIS_KVA_H
#define AEGIS_KVA_H

#include <stdint.h>

/* kva_init — initialise the kernel virtual allocator.
 * Must be called after vmm_init() (requires the mapped-window allocator).
 * Prints [KVA] OK on success. */
void kva_init(void);

/* kva_alloc_pages — allocate n 4KB pages, map them to consecutive higher-half
 * virtual addresses, and return the base VA as a pointer.
 * Panics on PMM exhaustion. Never pass VMM_FLAG_USER — kva pages are kernel-only;
 * USER must be absent so the MMU denies ring-3 access to kernel objects. */
void *kva_alloc_pages(uint64_t n);

/* kva_alloc_pages_low — like kva_alloc_pages, but the backing physical pages
 * are guaranteed below 4GB (DMA-safe for devices whose 64-bit addressing we
 * don't want to trust). Returns NULL on low-pool exhaustion (does NOT panic);
 * kva_page_phys() on the result returns the <4GB physical address. For device
 * DMA buffers only (NVMe, virtio); ordinary kernel allocations use the
 * unconstrained kva_alloc_pages. */
void *kva_alloc_pages_low(uint64_t n);

/* kva_alloc_pages_low_nc — same <4GB DMA pool as kva_alloc_pages_low, but the
 * pages are mapped NON-CACHEABLE (Normal-NC on arm64). For non-coherent DMA
 * devices (e.g. the RPi5 Broadcom PCIe RC, no `dma-coherent` in its DTB) whose
 * controller does not snoop the CPU cache. Callers must access these frames
 * ONLY through the returned VA, never the cacheable DMAP alias. */
void *kva_alloc_pages_low_nc(uint64_t n);

/* kva_map_phys_pages — map num_pages of existing physical memory starting at
 * phys_base into contiguous kernel VA. Does NOT allocate physical pages from
 * PMM — the pages must already exist (e.g. GRUB-loaded module).
 * phys_base must be 4KB-aligned. Returns the virtual base address. */
void *kva_map_phys_pages(uint64_t phys_base, uint32_t num_pages);

/* kva_map_mmio — map a device BAR (num_pages of MMIO at phys_base) into fresh
 * kernel VA as uncached (WC|UC-) registers. Like kva_map_phys_pages but with
 * MMIO cache flags; replaces the per-driver static map_mmio() copies. Does NOT
 * allocate frames. phys_base must be 4KB-aligned. Returns the virtual base. */
void *kva_map_mmio(uint64_t phys_base, uint32_t num_pages);

/* kva_page_phys — return the physical address of the page mapped at va.
 * va must be a VA previously returned by kva_alloc_pages (or offset within
 * such a range). Panics if any page-table level is absent. */
uint64_t kva_page_phys(void *va);

/* kva_free_pages — return n 4KB pages at va to the PMM.
 *
 * For each page i in [0, n): recover phys via vmm_phys_of, unmap the VA
 * via vmm_unmap_page, then return the frame via pmm_free_page. The virtual
 * address range is permanently abandoned — the bump cursor is not rewound;
 * VA space is not the scarce resource.
 *
 * va must be the base of a contiguous kva allocation. Panics if any page
 * is not mapped (calling with an unallocated VA is a kernel bug). */
void kva_free_pages(void *va, uint64_t n);

/* kva_unmap_keep_frames — unmap n 4KB pages of kernel VA at `va` WITHOUT
 * freeing the backing physical frames, and return the VA range to the kva
 * freelist for reuse.
 *
 * For when a frame's ownership has been TRANSFERRED to another mapping (e.g.
 * elf_load builds a segment in kva-mapped frames, then maps those same frames
 * into the user PML4 — the user mapping now owns them at implicit refcount 1).
 * The kva-side mapping is then dead weight: kva_free_pages would pmm_free_page
 * the frames the user owns (double-free at user exit), while leaving the kva
 * mapping in place leaks the VA + the page-table entries permanently. This
 * clears the kva PTEs (vmm_unmap_page — which does NOT free frames) and reclaims
 * the VA, leaving the frames allocated for their new owner.
 *
 * va must be the base of a contiguous kva allocation; every page must be mapped
 * (vmm_unmap_page panics otherwise — calling with an unmapped VA is a bug). */
void kva_unmap_keep_frames(void *va, uint64_t n);

#endif /* AEGIS_KVA_H */
