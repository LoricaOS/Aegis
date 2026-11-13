#!/usr/bin/env python3
"""Host-execute actual diagnostic EL0 validation/fixups and result checks."""
from pathlib import Path
import subprocess
import tempfile

from apple_memory_handoff_test import ROOT, function

PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "kernel/arch/arm64/apple/kernel_user.h"
#include "build/appleuser/apple_user_layout.h"
#define USER_TOP 0x7fffffff000ULL
#define KERNEL_TEST 0xffffffff80200000ULL
#define CAP_TABLE_SIZE 64
typedef struct { unsigned kind, rights; } cap_slot_t;
typedef struct {
    struct { uint8_t *stack_base; uint64_t kernel_stack_top; int is_user, on_cpu; } task;
    uint64_t pml4_phys;
    cap_slot_t caps[CAP_TABLE_SIZE];
} process_t;
_Alignas(16) static uint8_t stack[16384];
static process_t proc, *subject = &proc;
static void *current = &proc.task;
static uint64_t test_root = 0x12345000, test_far;
volatile struct apple_user_report apple_user_report;
static void *sched_current(void) { return current; }
static _Noreturn void stop(uint64_t reason) {
    assert(reason <= 8);
    exit(70 + (int)reason);
}
'''
MAIN = r'''
static void svc(cpu_state_t *s, uint64_t pc, uint64_t num, uint64_t arg, uint64_t result) {
    s->elr = pc + 4; s->x[8] = num; s->x[0] = arg;
    assert(!apple_user_exception(s, 0x15ULL << 26));
    s->x[0] = result;
    apple_user_syscall_result(s);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    const char *name = argv[1];
    subject->task.stack_base = stack;
    subject->task.kernel_stack_top = (uintptr_t)stack + sizeof(stack);
    subject->task.is_user = 1;
    subject->pml4_phys = test_root;
    apple_user_report.stage = 2;
    cpu_state_t *s = (cpu_state_t *)(stack + 4096);
    s->spsr = 0xa00003c0; s->sp_el0 = USER_TOP - 512;
    s->elr = APPLE_USER_USER_SVC_PID + 4; s->x[8] = 172;
    if (!strcmp(name, "wrong-mode")) s->spsr |= 5;
    else if (!strcmp(name, "unmasked-frame")) s->spsr &= ~0x40ULL;
    else if (!strcmp(name, "foreign-task")) current = NULL;
    else if (!strcmp(name, "wrong-root")) test_root += 4096;
    else if (!strcmp(name, "foreign-frame")) s = (cpu_state_t *)(stack + sizeof(stack));
    else if (!strcmp(name, "unexpected-cap")) subject->caps[0].kind = 1;
    else if (!strcmp(name, "wrong-svc")) s->x[8] = 999;
    else if (!strcmp(name, "wrong-svc-pc")) s->elr += 4;
    else if (!strcmp(name, "wrong-arg")) {
        apple_user_report.step = 2; s->elr = APPLE_USER_USER_SVC_UNAME + 4;
        s->x[8] = 160; s->x[0] = 0;
    } else if (!strcmp(name, "bad-result")) {
        s->x[0] = 2; apple_user_syscall_result(s); assert(0);
    } else if (!strcmp(name, "missing-proofs")) {
        apple_user_report.step = 8; s->elr = APPLE_USER_USER_DONE; s->x[0] = 0x5a;
        apple_user_exception(s, (0x3cULL << 26) | 0x5a); assert(0);
    } else if (!strcmp(name, "foreign-fault")) {
        apple_user_report.step = 5; s->elr = APPLE_USER_USER_KERNEL_READ + 4;
        test_far = KERNEL_TEST;
        apple_user_exception(s, (0x24ULL << 26) | 15); assert(0);
    } else assert(!strcmp(name, "valid"));
    if (strcmp(name, "valid")) {
        apple_user_exception(s, 0x15ULL << 26); assert(0);
    }
    svc(s, APPLE_USER_USER_SVC_PID, 172, 0, 1);
    svc(s, APPLE_USER_USER_SVC_UID, 174, 0, 0);
    svc(s, APPLE_USER_USER_SVC_UNAME, 160, USER_TOP - 512, 0);
    svc(s, APPLE_USER_USER_SVC_BADPTR, 160, KERNEL_TEST, (uint64_t)-14);
    s->x[1] = 1; s->x[2] = 0;
    svc(s, APPLE_USER_USER_SVC_SOCKET, 198, 2, (uint64_t)-1);
    assert(apple_user_report.step == 5 && apple_user_report.svcs == 5);
    s->elr = APPLE_USER_USER_KERNEL_READ; test_far = KERNEL_TEST;
    assert(apple_user_exception(s, (0x24ULL << 26) | 15));
    assert(s->elr == APPLE_USER_USER_KERNEL_READ + 4);
    s->elr = APPLE_USER_USER_TEXT_WRITE; test_far = APPLE_USER_START;
    assert(apple_user_exception(s, (0x24ULL << 26) | 15 | 64));
    assert(s->elr == APPLE_USER_USER_TEXT_WRITE + 4);
    s->elr = test_far = USER_TOP - 16; s->x[30] = APPLE_USER_USER_NX_RESUME;
    assert(apple_user_exception(s, (0x20ULL << 26) | 15));
    assert(s->elr == APPLE_USER_USER_NX_RESUME);
    assert(apple_user_report.step == 8);
    s->elr = APPLE_USER_USER_DONE; s->x[0] = 0x5a;
    apple_user_exception(s, (0x3cULL << 26) | 0x5a);
    assert(0);
}
'''
source = (ROOT / "kernel/arch/arm64/apple/kernel_user.c").read_text()
context = function(source, "context")
for old, new in (
    ('__asm__ volatile("mrs %0, ttbr0_el1" : "=r"(root));', "root = test_root;"),
    ('__asm__ volatile("mrs %0, far_el1" : "=r"(far));', "far = test_far;"),
):
    assert context.count(old) == 1
    context = context.replace(old, new)
body = context + function(source, "apple_user_exception") + function(source, "apple_user_syscall_result")
cases = {"valid": 70, "wrong-mode": 72, "unmasked-frame": 72, "foreign-task": 72,
         "wrong-root": 72, "foreign-frame": 72, "unexpected-cap": 73,
         "wrong-svc": 74, "wrong-svc-pc": 74, "wrong-arg": 75,
         "bad-result": 78, "missing-proofs": 76, "foreign-fault": 77}
with tempfile.TemporaryDirectory(prefix="aegis-user-state-") as directory:
    path = Path(directory) / "check.c"
    path.write_text(PREFIX + body + MAIN)
    binary = path.with_suffix("")
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-I", str(ROOT), str(path), "-o", str(binary)], check=True)
    for name, expected in cases.items():
        result = subprocess.run([str(binary), name], timeout=5)
        assert result.returncode == expected, (name, result.returncode, expected)
print("PASS: 13 actual EL0 context, SVC/result and exact fault-recovery cases")
