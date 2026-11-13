#!/usr/bin/env python3
"""Host-execute actual preemption frame/source validation with register mocks."""
from pathlib import Path
import subprocess
import tempfile

from apple_memory_handoff_test import ROOT, function

PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "kernel/arch/arm64/apple/kernel_preempt.h"
typedef struct {
    uint8_t *stack_base;
    uint64_t kernel_stack_top;
    int on_cpu, is_user;
} aegis_task_t;
_Alignas(16) static uint8_t stack[16384];
static aegis_task_t tasks[2];
static aegis_task_t *current = &tasks[0];
static unsigned ctl = 5, writes, accounted, scheduled, lose_identity;
static uint64_t armed;
volatile struct apple_preempt_report apple_preempt_report;
#define apple_preempt_wait_begin ((char *)(uintptr_t)0x8000)
#define apple_preempt_wait_end ((char *)(uintptr_t)0x9000)
static void arch_disable_irq(void) {}
static aegis_task_t *sched_current(void) { return current; }
static uint64_t counter(void) { return 1000000; }
static void arm64_timer_account_tick(void) { accounted++; }
static void apple_preempt_schedule(void) {
    scheduled++;
    if (lose_identity) current = &tasks[1];
}
static _Noreturn void stop(uint64_t reason) {
    assert(reason >= 2 && reason <= 6);
    if (reason < 6) assert(!scheduled && !accounted && !writes);
    else assert(scheduled == 1 && accounted == 1 && writes == 1);
    exit(70 + (int)reason);
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    assert(argc == 2);
    const char *name = argv[1];
    tasks[0].stack_base = stack;
    tasks[0].kernel_stack_top = (uintptr_t)(stack + sizeof(stack));
    apple_preempt_report.task[0] = (uintptr_t)&tasks[0];
    apple_preempt_report.task[1] = (uintptr_t)&tasks[1];
    apple_preempt_report.frequency = 62500000;
    apple_preempt_report.stage = 2;
    cpu_state_t *s = (cpu_state_t *)(stack + 4096);
    s->spsr = 0xa0000085; s->elr = 0x8120;
    for (unsigned i = 0; i < 31; i++) s->x[i] = 0x12340000 + i;
    cpu_state_t before = *s;
    int fiq = 1;
    if (!strcmp(name, "unknown-task")) current = NULL;
    else if (!strcmp(name, "low-frame")) s = (cpu_state_t *)((uintptr_t)stack - 16);
    else if (!strcmp(name, "high-frame")) s = (cpu_state_t *)(stack + sizeof(stack));
    else if (!strcmp(name, "irq")) fiq = 0;
    else if (!strcmp(name, "not-pending")) ctl = 1;
    else if (!strcmp(name, "masked-source")) ctl = 7;
    else if (!strcmp(name, "wrong-cpu")) tasks[0].on_cpu = 1;
    else if (!strcmp(name, "user-task")) tasks[0].is_user = 1;
    else if (!strcmp(name, "el0-frame")) s->spsr = 0;
    else if (!strcmp(name, "masked-frame")) s->spsr |= 0x40;
    else if (!strcmp(name, "irq-enabled")) s->spsr &= ~0x80ULL;
    else if (!strcmp(name, "foreign-pc")) s->elr = 0x7000;
    else if (!strcmp(name, "tick-budget")) apple_preempt_report.ticks = 128;
    else if (!strcmp(name, "lost-identity")) lose_identity = 1;
    else assert(!strcmp(name, "valid"));
    apple_preempt_interrupt(s, fiq);
    assert(!strcmp(name, "valid"));
    assert(!memcmp(s, &before, sizeof(*s))); /* saved return state stays intact */
    assert(scheduled == 1 && accounted == 1 && writes == 1 && armed == 1625000);
    assert(apple_preempt_report.ticks == 1);
    assert(apple_preempt_report.interrupted[0] == 1 && apple_preempt_report.resumed[0] == 1);
    assert(!apple_preempt_report.interrupted[1] && !apple_preempt_report.resumed[1]);
    return 0;
}
'''
source = (ROOT / "kernel/arch/arm64/apple/kernel_preempt.c").read_text()
handler = function(source, "apple_preempt_interrupt")
replacements = {
    '__asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(ctl));': "ctl = test_ctl;",
    '__asm__ volatile("msr cntp_cval_el0, %0\\nisb" : : "r"(next) : "memory");':
        "armed = next; writes++;",
}
# Avoid shadowing the handler's local ctl in the register mock.
PREFIX = PREFIX.replace("unsigned ctl = 5", "unsigned test_ctl = 5")
MAIN = MAIN.replace("ctl = 1", "test_ctl = 1").replace("ctl = 7", "test_ctl = 7")
for old, new in replacements.items():
    assert handler.count(old) == 1, old
    handler = handler.replace(old, new)
cases = {"valid": 0, "unknown-task": 72, "low-frame": 73, "high-frame": 73,
         "irq": 74, "not-pending": 74, "masked-source": 74, "wrong-cpu": 74,
         "user-task": 74, "el0-frame": 74, "masked-frame": 74, "irq-enabled": 74,
         "foreign-pc": 74, "tick-budget": 75, "lost-identity": 76}
with tempfile.TemporaryDirectory(prefix="aegis-preempt-state-") as directory:
    path = Path(directory) / "check.c"
    path.write_text(PREFIX + handler + MAIN)
    binary = path.with_suffix("")
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-I", str(ROOT), str(path), "-o", str(binary)], check=True)
    for name, expected in cases.items():
        result = subprocess.run([str(binary), name], timeout=5)
        assert result.returncode == expected, (name, result.returncode, expected)
print("PASS: 15 actual preemption validation/source/frame/resume-state cases")
