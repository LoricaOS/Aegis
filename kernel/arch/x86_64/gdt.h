#ifndef ARCH_GDT_H
#define ARCH_GDT_H

#include <stdint.h>

/*
 * GDT segment selectors.
 *
 * CRITICAL: user data (0x18) MUST precede user code (0x20).
 * SYSRET derives selectors arithmetically from STAR[63:48]=0x10:
 *   SS = (0x10 + 8)  | 3 = 0x1B → GDT[3] = user data  ✓
 *   CS = (0x10 + 16) | 3 = 0x23 → GDT[4] = user code  ✓
 * Swapping user data/code causes SYSRET to load a data descriptor
 * into CS, triggering an immediate #GP on return to ring 3.
 */
#define GDT_SEL_NULL         0x00
#define GDT_SEL_KERNEL_CODE  0x08
#define GDT_SEL_KERNEL_DATA  0x10
#define GDT_SEL_USER_DATA    0x18   /* index 3 — MUST be before user code */
#define GDT_SEL_USER_CODE    0x20   /* index 4 */
#define GDT_SEL_TSS          0x28   /* 16-byte system descriptor at indices 5+6 */

/*
 * User selectors with RPL=3 (for iretq frames and SYSCALL/SYSRET).
 * CS=0x23, SS=0x1B.
 */
#define GDT_USER_CODE_RPL3   (GDT_SEL_USER_CODE | 3)
#define GDT_USER_DATA_RPL3   (GDT_SEL_USER_DATA | 3)

/* Build runtime GDT, lgdt, reload segments, ltr.  Prints [GDT] OK. */
void arch_gdt_init(void);

/* Initialize per-CPU GDT for an AP: copies BSP segments, installs
 * this CPU's TSS descriptor at tss_base, lgdt, ltr. */
void arch_gdt_init_ap(uint8_t cpu_id, uint64_t tss_base);

#endif /* ARCH_GDT_H */
