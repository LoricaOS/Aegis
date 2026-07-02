#ifndef ARCH_VMM_H
#define ARCH_VMM_H

#include <stdint.h>

/*
 * arch_vmm.h — ARM64 PTE translation.
 *
 * The abstract VMM_FLAG_* values (vmm.h) are x86 PTE bit positions; ARM64
 * needs a real translation. IMPORTANT CONTRACT: every vmm.h API function
 * in kernel/arch/arm64/vmm.c speaks ABSTRACT flags at the boundary —
 * arch_pte_from_flags() translates abstract→hardware on the way in, and
 * arch_pte_to_flags() translates hardware→abstract on the way out (for
 * callers like sys_munmap that test VMM_FLAG_SHARED on a returned PTE).
 * Hardware-format PTEs never escape vmm.c.
 *
 * ARM64 stage-1 4K descriptor (level-3 page):
 *   bit 0      VALID
 *   bit 1      1 = page (level 3) / table (levels 0-2)
 *   bits 4:2   AttrIndx  (0 = Normal WB, 1 = Device-nGnRE, 2 = Normal-NC)
 *   bit 6      AP[1]     1 = EL0 accessible
 *   bit 7      AP[2]     1 = read-only
 *   bits 9:8   SH        0b11 = inner shareable
 *   bit 10     AF        access flag (must be 1; no HW AF management)
 *   bit 53     PXN       privileged execute never
 *   bit 54     UXN       user execute never
 *   bits 58:55 software  (bit 55 = COW, bit 56 = SHARED)
 */

#define A64_PTE_VALID   (1UL << 0)
#define A64_PTE_PAGE    (1UL << 1)
#define A64_PTE_ATTR(i) ((uint64_t)(i) << 2)
#define A64_PTE_USER    (1UL << 6)     /* AP[1] */
#define A64_PTE_RO      (1UL << 7)     /* AP[2] */
#define A64_PTE_SH_IS   (3UL << 8)
#define A64_PTE_AF      (1UL << 10)
#define A64_PTE_PXN     (1UL << 53)
#define A64_PTE_UXN     (1UL << 54)
#define A64_PTE_SW_COW    (1UL << 55)
#define A64_PTE_SW_SHARED (1UL << 56)

/* MAIR_EL1 attribute indices programmed by entry.S (see MAIR_VALUE there). */
#define A64_ATTR_NORMAL_WB 0
#define A64_ATTR_DEVICE    1
#define A64_ATTR_NORMAL_NC 2

static inline uint64_t
arch_pte_from_flags(uint64_t flags)
{
    uint64_t pte = 0;

    if (flags & (1UL << 0)) {                 /* VMM_FLAG_PRESENT */
        pte |= A64_PTE_VALID | A64_PTE_PAGE | A64_PTE_AF | A64_PTE_SH_IS;
        if (!(flags & (1UL << 1)))            /* !VMM_FLAG_WRITABLE → RO */
            pte |= A64_PTE_RO;
        if (flags & (1UL << 2)) {             /* VMM_FLAG_USER */
            pte |= A64_PTE_USER | A64_PTE_PXN;
            /* user NX honored below; user-executable unless NX */
        } else {
            pte |= A64_PTE_UXN;               /* kernel page: never EL0-exec */
        }
        if (flags & (1UL << 63))              /* VMM_FLAG_NX */
            pte |= A64_PTE_UXN | A64_PTE_PXN;
        /* Device wins when both bits are set: kva_map_mmio passes WC|UCMINUS
         * for device registers (config/BAR MMIO), which must be Device
         * memory (no speculation/reordering), not Normal-NC. A pure WC
         * mapping (framebuffer) has only VMM_FLAG_WC and gets Normal-NC. */
        if (flags & (1UL << 4))               /* VMM_FLAG_UCMINUS → Device */
            pte = (pte & ~A64_PTE_ATTR(7)) | A64_PTE_ATTR(A64_ATTR_DEVICE);
        else if (flags & (1UL << 3))          /* VMM_FLAG_WC → Normal-NC */
            pte = (pte & ~A64_PTE_ATTR(7)) | A64_PTE_ATTR(A64_ATTR_NORMAL_NC);
        /* else AttrIndx 0 = Normal WB (bits already 0) */
    }
    if (flags & (1UL << 9))                   /* VMM_FLAG_COW */
        pte |= A64_PTE_SW_COW;
    if (flags & (1UL << 10))                  /* VMM_FLAG_SHARED */
        pte |= A64_PTE_SW_SHARED;
    return pte;
}

/* Reverse translation: hardware PTE → abstract VMM_FLAG_* form (with the
 * physical address preserved), for vmm.c query functions that hand PTEs to
 * arch-neutral callers. */
static inline uint64_t
arch_pte_to_flags(uint64_t pte)
{
    uint64_t f = pte & 0x0000FFFFFFFFF000UL;  /* keep the PA bits */

    if (pte & A64_PTE_VALID)
        f |= (1UL << 0);
    if ((pte & (A64_PTE_VALID | A64_PTE_RO)) == A64_PTE_VALID)
        f |= (1UL << 1);                       /* writable = valid && !RO */
    if (pte & A64_PTE_USER)
        f |= (1UL << 2);
    if ((pte & A64_PTE_ATTR(7)) == A64_PTE_ATTR(A64_ATTR_NORMAL_NC))
        f |= (1UL << 3);
    if ((pte & A64_PTE_ATTR(7)) == A64_PTE_ATTR(A64_ATTR_DEVICE))
        f |= (1UL << 4);
    if (pte & A64_PTE_SW_COW)
        f |= (1UL << 9);
    if (pte & A64_PTE_SW_SHARED)
        f |= (1UL << 10);
    if (pte & A64_PTE_UXN)
        f |= (1UL << 63);
    return f;
}

/* Physical address bits of a descriptor (48-bit PA space). */
#define ARCH_PTE_ADDR(e) ((e) & 0x0000FFFFFFFFF000UL)

#endif /* ARCH_VMM_H */
