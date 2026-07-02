#ifndef ARM64_IDT_H
#define ARM64_IDT_H

#include <stdint.h>

/* cpu_state_t — full register frame saved by SAVE_ALL in vectors.S.
 * Layout MUST match the stp/ldp sequence there: x0-x30 at slots [0..30],
 * then sp_el0, elr_el1, spsr_el1. 34 slots = 272 bytes (16-byte aligned).
 * This is the SAME memory layout as syscall_frame_t (kernel/syscall/
 * syscall.h) — one saved frame, two typed views (fault vs syscall path).
 * Shared code (signal.c) reads/writes x[], sp_el0, elr, spsr by name. */
typedef struct cpu_state {
    uint64_t x[31];     /* x0-x30 */
    uint64_t sp_el0;
    uint64_t elr;
    uint64_t spsr;
} cpu_state_t;

/* Install VBAR_EL1 (the 16-entry EL1 vector table in vectors.S). */
void idt_init(void);

/* C-level dispatchers called from vectors.S. */
void arm64_sync_el0(cpu_state_t *s);   /* SVC / aborts / traps from EL0 */
void arm64_irq(cpu_state_t *s);        /* IRQ from EL0 or EL1 */
void arm64_fault_el1(cpu_state_t *s);  /* sync exception from EL1 = kernel bug */

#endif /* ARM64_IDT_H */
