#ifndef AEGIS_APPLE_KERNEL_TIMER_H
#define AEGIS_APPLE_KERNEL_TIMER_H
#include "kernel_handoff.h"
#include "../idt.h"
struct apple_timer_report {
    uint64_t stage, frequency, start, end, delivered, returned, failure;
    uint64_t ctl_before, ctl_entry, ctl_final, saved_spsr, saved_elr, frame;
    uint64_t daif_after, hcr, gate_before, gate_after, cnthctl;
};
extern volatile struct apple_timer_report apple_timer_report;
void apple_timer_prepare(const struct apple_kernel_handoff *);
void apple_timer_run(void) __attribute__((noreturn));
void apple_timer_fiq(cpu_state_t *);
void apple_timer_unexpected_irq(cpu_state_t *);
#endif
