#ifndef APPLE_KERNEL_PREEMPT_H
#define APPLE_KERNEL_PREEMPT_H
#include <stdint.h>
#include "../idt.h"
#define APPLE_PREEMPT_RETURNS 8
#define APPLE_PREEMPT_MAX_TICKS 128
struct apple_preempt_report {
    uint64_t stage, reason, ticks, interrupted[2], resumed[2], verified[2];
    uint64_t entered[2], task[2], stack[2], frequency, cpacr, daif;
    uint64_t start, end, ctl_final, frame[2], elr[2], spsr[2], clock_ns;
};
extern volatile struct apple_preempt_report apple_preempt_report;
void apple_preempt_run(void) __attribute__((noreturn));
void apple_preempt_interrupt(cpu_state_t *s, int fiq);
#endif
