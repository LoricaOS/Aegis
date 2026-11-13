#ifndef APPLE_KERNEL_USER_H
#define APPLE_KERNEL_USER_H
#include "../idt.h"
struct apple_user_report {
    uint64_t stage, step, reason, pid, uid, svcs, kernel_deny, text_deny, nx_deny;
    uint64_t capdeny, badptr, process, root, kstack, usp, frame, esr, far, elr;
    uint64_t cpacr, entered, free;
};
extern volatile struct apple_user_report apple_user_report;
void apple_user_run(void) __attribute__((noreturn));
int apple_user_exception(cpu_state_t *s, uint64_t esr);
void apple_user_syscall_result(cpu_state_t *s);
#endif
