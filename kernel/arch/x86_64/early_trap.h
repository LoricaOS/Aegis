#ifndef AEGIS_EARLY_TRAP_H
#define AEGIS_EARLY_TRAP_H

/* early_trap.h — exception capture for the pre-IDT window (see early_trap.c).
 *
 * Internal to kernel/arch/x86_64/. */

#include <stdint.h>

/* Install a minimal IDT covering the 32 architectural exception vectors.
 * Call once, after serial_init() — the handler reports over COM1. */
void early_trap_init(void);

/* Name the bring-up stage that is running, so a fault report can say where it
 * happened instead of only where the instruction pointer was. */
void early_trap_stage(const char *stage);

/* Bytes of the boot stack actually used so far, measured against the pattern
 * boot.asm paints at entry (see kernel/arch/x86_64/boot.asm). */
uint64_t boot_stack_used(void);

#endif /* AEGIS_EARLY_TRAP_H */
