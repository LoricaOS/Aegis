#!/usr/bin/env python3
"""Host-check actual timer setup validation and source/frame rejection logic.

Only architectural register access/disarm/halt is mocked. Actual interrupt
delivery and ERET are separately exercised in apple_timer_kernel_test.py.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

from apple_memory_handoff_test import ROOT, function

PREFIX = r'''
#define APPLE_MEMORY_CHECKPOINT 1
#define APPLE_TIMER_CHECKPOINT 1
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "kernel/arch/arm64/apple/kernel_timer.h"
volatile struct apple_timer_report apple_timer_report;
_Alignas(16) static uint8_t stack[32768];
#define apple_kernel_stack_top ((char *)stack + sizeof(stack))
#define apple_timer_wait_begin ((char *)(uintptr_t)0x8000)
#define apple_timer_wait_end ((char *)(uintptr_t)0x9000)
static uint64_t test_ctl = 5, test_midr = 0x61000000;
static unsigned disarmed;
static void disarm(void) { disarmed++; }
static _Noreturn void stop(const char *phase, uint64_t reason) {
    assert(!strcmp(phase, "timer-setup-refused"));
    assert(reason == 1 || reason == 2);
    exit(77);
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    assert(argc == 2);
    const char *n = argv[1];
    struct apple_kernel_handoff h = {
        .timer_hcr = 1ULL << 31, .timer_gate_before = 0,
        .timer_gate_after = 2, .timer_cnthctl = 3,
    };
    if (!strncmp(n, "setup-", 6)) {
        if (!strcmp(n, "setup-vhe")) {
            h.timer_hcr |= 1ULL << 34; h.timer_cnthctl = 3ULL << 10;
        } else if (!strcmp(n, "setup-wrong-layout")) h.timer_hcr |= 1ULL << 34;
        else if (!strcmp(n, "setup-gate-off")) h.timer_gate_after = 0;
        else if (!strcmp(n, "setup-fmo")) h.timer_hcr |= 8;
        else if (!strcmp(n, "setup-not-aarch64")) h.timer_hcr = 0;
        else if (!strcmp(n, "setup-null")) { apple_timer_prepare(NULL); assert(0); }
        else if (!strcmp(n, "setup-repeat")) apple_timer_report.stage = 1;
        else if (!strcmp(n, "setup-qemu-el1")) { test_midr = 0x41000000; memset(&h, 0, sizeof(h)); }
        else assert(!strcmp(n, "setup-nonvhe"));
        apple_timer_prepare(&h);
        assert(!strcmp(n, "setup-vhe") || !strcmp(n, "setup-nonvhe") || !strcmp(n, "setup-qemu-el1"));
        assert(apple_timer_report.stage == 1);
        assert(apple_timer_report.cnthctl == h.timer_cnthctl);
        puts("PASS setup"); return 0;
    }
    cpu_state_t *s = (cpu_state_t *)(stack + sizeof(stack) - 1024);
    memset(s, 0, sizeof(*s));
    for (unsigned i = 0; i < 31; i++) s->x[i] = 0xabcdef0000ULL + i;
    s->sp_el0 = 0x12340000; s->spsr = 0xa0000085; s->elr = 0x8120;
    cpu_state_t before = *s;
    apple_timer_report.stage = 2;
    int fiq = 1;
    if (!strcmp(n, "irq")) fiq = 0;
    else if (!strcmp(n, "inactive")) apple_timer_report.stage = 1;
    else if (!strcmp(n, "duplicate")) apple_timer_report.delivered = 1;
    else if (!strcmp(n, "not-pending")) test_ctl = 1;
    else if (!strcmp(n, "masked-source")) test_ctl = 7;
    else if (!strcmp(n, "wrong-mode")) s->spsr &= ~15ULL;
    else if (!strcmp(n, "masked-frame")) s->spsr |= 0x40;
    else if (!strcmp(n, "foreign-pc")) s->elr = 0x7000;
    else if (!strcmp(n, "foreign-frame")) {
        interrupt((cpu_state_t *)(stack + sizeof(stack)), 1); assert(0);
    } else assert(!strcmp(n, "valid"));
    uint64_t old_spsr = s->spsr;
    interrupt(s, fiq);
    assert(disarmed == 1 && s->spsr == (old_spsr | 0xc0));
    assert(!memcmp(s->x, before.x, sizeof(s->x)) && s->sp_el0 == before.sp_el0);
    assert(apple_timer_report.saved_spsr == old_spsr);
    if (!strcmp(n, "valid"))
        assert(apple_timer_report.delivered == 1 && !apple_timer_report.failure);
    else {
        assert(apple_timer_report.failure == (fiq ? 4 : 5));
        assert(apple_timer_report.delivered == (!strcmp(n, "duplicate") ? 1 : 0));
    }
    puts("PASS frame");
    return 0;
}
'''


class TimerStateTests(unittest.TestCase):
    def test_setup_and_frame_state(self):
        source = (ROOT / "kernel/arch/arm64/apple/kernel_timer.c").read_text()
        prepare = function(source, "apple_timer_prepare")
        read_midr = '__asm__ volatile("mrs %0, midr_el1" : "=r"(midr));'
        assert prepare.count(read_midr) == 1
        prepare = prepare.replace(read_midr, "midr = test_midr;")
        handler = function(source, "interrupt")
        replacements = {
            '__asm__ volatile("msr daifset, #3" ::: "memory");': "(void)0;",
            '__asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(ctl));': "ctl = test_ctl;",
            '__asm__ volatile("dsb sy" ::: "memory");': "(void)0;",
            'for (;;) __asm__ volatile("wfe");': "exit(77);",
        }
        for old, new in replacements.items():
            assert handler.count(old) == 1, old
            handler = handler.replace(old, new)
        with tempfile.TemporaryDirectory(prefix="aegis-timer-state-") as directory:
            path = Path(directory) / "check.c"
            path.write_text(PREFIX + prepare + handler + MAIN)
            binary = path.with_suffix("")
            subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-I", str(ROOT), str(path), "-o", str(binary)], check=True)
            cases = ("setup-vhe", "setup-nonvhe", "setup-qemu-el1", "setup-wrong-layout",
                     "setup-gate-off", "setup-fmo", "setup-not-aarch64", "setup-null", "setup-repeat",
                     "valid", "irq", "inactive", "duplicate", "not-pending", "masked-source",
                     "wrong-mode", "masked-frame", "foreign-pc", "foreign-frame")
            for name in cases:
                with self.subTest(name=name):
                    result = subprocess.run([str(binary), name], capture_output=True, text=True, timeout=5)
                    refusal = name.startswith("setup-") and name not in (
                        "setup-vhe", "setup-nonvhe", "setup-qemu-el1") or name == "foreign-frame"
                    self.assertEqual(result.returncode, 77 if refusal else 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
