#ifndef AEGIS_IDT_H
#define AEGIS_IDT_H

#include <stdint.h>

/* x86-64 IDT gate descriptor (16 bytes, packed) */
typedef struct {
    uint16_t offset_lo;   /* handler address bits 0-15  */
    uint16_t selector;    /* kernel code segment: 0x08  */
    uint8_t  ist;         /* interrupt stack table: 0   */
    uint8_t  type_attr;   /* 0x8E = present, DPL=0, 64-bit interrupt gate */
    uint16_t offset_mid;  /* handler address bits 16-31 */
    uint32_t offset_hi;   /* handler address bits 32-63 */
    uint32_t zero;        /* reserved                   */
} __attribute__((packed)) aegis_idt_gate_t;

/* Register state pushed by isr_common_stub (matches push order in isr.asm).
 * isr_dispatch receives a pointer to this struct. */
typedef struct cpu_state {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t vector, error_code;
    /* CPU-pushed interrupt frame: */
    uint64_t rip, cs, rflags, rsp, ss;
} cpu_state_t;

/* Install 48 IDT gates and load with lidt.
 * Must be called before enabling any interrupts. */
void idt_init(void);

/* Reload the IDT on the current CPU without reinitializing gate entries.
 * Used by AP startup — the BSP's s_idt[] is shared across all cores. */
void arch_load_idt(void);

/* C-level interrupt dispatcher — called by isr_common_stub in isr.asm.
 * Marked with __attribute__((used)) to prevent dead-code elimination. */
void isr_dispatch(cpu_state_t *s);

#endif /* AEGIS_IDT_H */
