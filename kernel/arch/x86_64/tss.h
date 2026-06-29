#ifndef ARCH_TSS_H
#define ARCH_TSS_H

#include <stdint.h>

/*
 * 104-byte x86-64 Task State Segment.
 * Only RSP0 is used — loaded by CPU on ring 3→0 transitions.
 * iomap_base = 104 disables I/O permission bitmap.
 */
typedef struct {
	uint32_t reserved0;    /* +0   */
	uint64_t rsp0;         /* +4   — kernel stack for ring 3 interrupts */
	uint64_t rsp1;         /* +12  */
	uint64_t rsp2;         /* +20  */
	uint64_t reserved1;    /* +28  */
	uint64_t ist[7];       /* +36  — IST1-IST7, all zero */
	uint64_t reserved2;    /* +92  */
	uint16_t reserved3;    /* +100 */
	uint16_t iomap_base;   /* +102 — 104 = disable I/O bitmap */
} __attribute__((packed)) aegis_tss_t;

/* Returns pointer to BSP's TSS (used by gdt.c to install TSS descriptor). */
aegis_tss_t *arch_tss_get(void);

/* Returns the base address of the specified CPU's TSS. */
uint64_t arch_tss_get_base_ap(uint8_t cpu_id);

/* Initialize BSP's TSS fields; set iomap_base = 104. Prints [TSS] OK. */
void arch_tss_init(void);

/* Initialize AP's TSS: iomap_base and IST1 (#DF stack). */
void arch_tss_init_ap(uint8_t cpu_id);

/* Update current CPU's TSS.RSP0 and percpu.kernel_stack to rsp0.
 * Called by scheduler before every ctx_switch so the CPU uses the
 * correct kernel stack top when the next ring-3 interrupt fires. */
void arch_set_kernel_stack(uint64_t rsp0);

#endif /* ARCH_TSS_H */
