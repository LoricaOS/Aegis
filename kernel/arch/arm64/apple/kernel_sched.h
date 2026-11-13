#ifndef APPLE_KERNEL_SCHED_H
#define APPLE_KERNEL_SCHED_H
#include <stdint.h>
#define APPLE_SCHED_ROUNDS 32
struct apple_sched_report {
    uint64_t stage, reason, completed[2], entered[2], task[2], stack[2];
    uint64_t cpacr, daif, free_before, free_after, mask_checks, verified[2];
};
extern volatile struct apple_sched_report apple_sched_report;
void apple_sched_run(void) __attribute__((noreturn));
#endif
