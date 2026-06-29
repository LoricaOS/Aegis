#ifndef ARCH_VMM_H
#define ARCH_VMM_H

#include <stdint.h>

/* arch_pte_from_flags — translate abstract VMM_FLAG_* constants into
 * hardware PTE bits for x86-64.
 *
 * On x86-64, the abstract flag values defined in vmm.h happen to match
 * the hardware PTE bit positions (PRESENT=0, WRITABLE=1, USER=2, etc.),
 * so this function is an identity transformation.
 *
 * ARM64 arch_vmm.h provides a real translation (e.g., VMM_FLAG_WRITABLE
 * maps to clearing AP[2], VMM_FLAG_USER maps to setting AP[1], etc.). */
static inline uint64_t
arch_pte_from_flags(uint64_t flags)
{
    return flags;
}

/* arch_pte_addr — extract the physical address from a hardware PTE.
 * On x86-64, bits [51:12] hold the physical page frame number.
 * ARM64 uses a different mask (bits [47:12] typically). */
#define ARCH_PTE_ADDR(e) ((e) & 0x000FFFFFFFFFF000UL)

#endif /* ARCH_VMM_H */
