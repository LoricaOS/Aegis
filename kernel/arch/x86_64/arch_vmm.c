#include "arch.h"

/* arch_vmm_load_pml4 — load a new PML4 physical address into CR3.
 * Flushes the entire TLB (non-global entries). */
void
arch_vmm_load_pml4(uint64_t phys)
{
    __asm__ volatile ("mov %0, %%cr3" : : "r"(phys) : "memory");
}

/* arch_vmm_invlpg — invalidate the TLB entry for a single virtual address. */
void
arch_vmm_invlpg(uint64_t virt)
{
    __asm__ volatile ("invlpg (%0)" : : "r"(virt) : "memory");
}
