/* Bounded cooperative scheduling gate. No periodic preemption or userland.
 * Uses real sched_spawn/start/yield, guarded KVA stacks and ctx_switch.S. */
#include "kernel_sched.h"
#include "kernel_timer.h"
#include "kernel_memory.h"
#include "probe_console.h"
#include "qr_report.h"
#include "sched.h"
#include "arch.h"
#include "pmm.h"
#include "kva.h"
#include "printk.h"

extern volatile uint64_t apple_kernel_atomic_report[4];
extern unsigned apple_sched_yield_test(uint64_t);
volatile struct apple_sched_report apple_sched_report;

static uint64_t daif(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, daif" : "=r"(value));
    return value;
}

static void report(const char *phase)
{
    apple_qr_sched[0] = apple_sched_report.completed[0];
    apple_qr_sched[1] = apple_sched_report.completed[1];
    apple_qr_sched[2] = APPLE_SCHED_ROUNDS;
    apple_qr_sched[3] = apple_sched_report.reason;
    apple_qr_sched[4] = apple_sched_report.cpacr;
    apple_qr_sched[5] = daif();
    apple_qr_sched[6] = apple_sched_report.entered[0] + apple_sched_report.entered[1];
    apple_qr_sched[7] = pmm_free_pages();
    apple_qr_progress(phase, apple_kernel_atomic_report);
}

static __attribute__((noreturn)) void stop(uint64_t reason)
{
    arch_disable_irq();
    apple_sched_report.reason = reason;
    apple_sched_report.daif = daif();
    apple_sched_report.free_after = pmm_free_pages();
    probe_puts(reason ? "SCHEDULER CHECKPOINT FAILED\n" : "SCHEDULER CHECKPOINT PASSED\n");
    probe_puts("COOPERATIVE THREADS ONLY - TIMERS DISABLED\n");
    report(reason ? "sched-failed" : "sched-complete");
    apple_sched_report.stage = reason ? 255 : 3;
    for (;;) __asm__ volatile("wfe");
}

static void masks(void)
{
    /* No source is armed during this brief enable window. Validate nesting
     * and exact restore, not just an unconditional mask on unlock. */
    arch_enable_irq();
    uint64_t enabled = daif();
    unsigned long outer = arch_irq_save();
    if ((enabled & 0xc0) != 0x80 || outer != enabled || (daif() & 0xc0) != 0xc0)
        stop(2);
    unsigned long inner = arch_irq_save();
    arch_irq_restore(inner);
    if (daif() != inner || (inner & 0xc0) != 0xc0) stop(3);
    arch_irq_restore(outer);
    if (daif() != enabled) stop(4);
    arch_disable_irq();
    if ((daif() & 0x3c0) != 0x3c0) stop(5);
    apple_sched_report.mask_checks = 1;
}

static void worker(unsigned id)
{
    aegis_task_t *self = sched_current();
    uint64_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    if (!self || self->is_user || self->on_cpu != 0 || self->fs_base ||
        self->sleep_deadline || self->clear_child_tid ||
        sp < (uintptr_t)self->stack_base || sp >= self->kernel_stack_top)
        stop(6);
    uint64_t guard = (uintptr_t)self->stack_base - 4096, par;
    __asm__ volatile("at s1e1r, %1\nisb\nmrs %0, par_el1" : "=r"(par) : "r"(guard));
    if (!(par & 1)) stop(7);
    for (uint64_t va = (uintptr_t)self->stack_base; va < self->kernel_stack_top; va += 4096) {
        uint64_t pa = kva_page_phys((void *)(uintptr_t)va);
        if (pa < apple_qr_memory[0] || pa >= apple_qr_memory[0] + apple_qr_memory[1])
            stop(8);
    }
    apple_sched_report.task[id] = (uintptr_t)self;
    apple_sched_report.stack[id] = sp;
    apple_sched_report.entered[id] = 1;
    /* Exercise every V register, FPSR/FPCR, and live TLS across real yields.
     * C is general-registers-only, so it cannot silently preserve the test
     * state on our behalf or clobber it while comparing snapshots. */
    uint8_t expected[528] __attribute__((aligned(16))) = {0};
    uint8_t actual[528] __attribute__((aligned(16)));
    for (unsigned i = 0; i < 512; i++) expected[i] = (uint8_t)(i * 17 + id * 73 + 1);
    uint32_t fpsr = 1U << id, fpcr = id ? 1U << 22 : 0;
    __builtin_memcpy(expected + 512, &fpsr, 4);
    __builtin_memcpy(expected + 516, &fpcr, 4);
    uint64_t tls = 0x51510000 + id;
    __asm__ volatile("msr tpidr_el0, %0" : : "r"(tls) : "memory");
    arm64_fpu_restore(expected);
    for (unsigned round = 0; round < APPLE_SCHED_ROUNDS; round++) {
        if (apple_sched_yield_test(0x3190 + id)) stop(9);
        arm64_fpu_save(actual);
        uint64_t live_tls;
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(live_tls));
        if (live_tls != tls || sched_current() != self || self->on_cpu != 0 ||
            (daif() & 0x3c0) != 0x3c0) stop(10);
        for (unsigned i = 0; i < 520; i++)
            if (actual[i] != expected[i]) stop(11);
        apple_sched_report.completed[id]++;
    }
    apple_sched_report.verified[id] = 1;
    /* Neither worker exits/reaps a live test stack. The final worker reports;
     * the other remains parked in the shared scheduler's yield path. */
    for (unsigned budget = 0; budget < 256; budget++) {
        if (apple_sched_report.verified[0] && apple_sched_report.verified[1]) {
            if (apple_sched_report.task[0] == apple_sched_report.task[1] ||
                apple_sched_report.stack[0] == apple_sched_report.stack[1]) stop(12);
            stop(0);
        }
        sched_yield_to_next();
    }
    stop(13);
}

static void worker_a(void) { worker(0); }
static void worker_b(void) { worker(1); }

void apple_sched_run(void)
{
    arch_disable_irq();
    if (apple_memory_report.stage != 5 || apple_timer_report.stage != 3 ||
        apple_timer_report.delivered != 1 || apple_timer_report.returned != 1 ||
        apple_timer_report.failure || apple_sched_report.stage) stop(1);
    probe_console_reset();
    probe_puts("AEGIS - SHARED SCHEDULER CONTEXT TEST\n");
    apple_sched_report.stage = 1;
    report("sched-before-fp");
    uint64_t cpacr;
    __asm__ volatile("mrs %0, cpacr_el1" : "=r"(cpacr));
    cpacr |= 3ULL << 20;
    __asm__ volatile("msr cpacr_el1, %0\nisb" : : "r"(cpacr) : "memory");
    __asm__ volatile("mrs %0, cpacr_el1" : "=r"(apple_sched_report.cpacr));
    if ((apple_sched_report.cpacr & (3ULL << 20)) != (3ULL << 20)) stop(14);
    masks();
    apple_sched_report.free_before = pmm_free_pages();
    sched_init();
    sched_spawn(worker_a);
    sched_spawn(worker_b);
    aegis_task_t *first = sched_current();
    if (!first || first->next == first || first->next->next != first) stop(15);
    apple_sched_report.stage = 2;
    report("sched-before-start");
    sched_start();
    __builtin_unreachable();
}
