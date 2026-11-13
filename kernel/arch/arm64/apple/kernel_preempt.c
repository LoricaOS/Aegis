/* Timer-only preemption gate: no voluntary yield, pollers, devices or EL0.
 * C never uses FP/SIMD; ctx_switch owns per-task FP/TLS preservation. */
#include "kernel_preempt.h"
#include "kernel_timer.h"
#include "kernel_memory.h"
#include "qr_report.h"
#include "probe_console.h"
#include "sched.h"
#include "arch.h"
#include "pmm.h"

extern volatile uint64_t apple_kernel_atomic_report[4];
extern unsigned apple_preempt_wait(uint64_t, const volatile uint64_t *,
                                  const volatile uint64_t *, uint64_t, uint64_t);
extern char apple_preempt_wait_begin[], apple_preempt_wait_end[];
volatile struct apple_preempt_report apple_preempt_report;

static uint64_t counter(void)
{
    uint64_t n;
    __asm__ volatile("isb\nmrs %0, cntpct_el0" : "=r"(n));
    return n;
}

static void disarm(void)
{
    __asm__ volatile("msr cntp_ctl_el0, %0\nisb" : : "r"(2ULL) : "memory");
}

static void report(const char *phase)
{
    apple_qr_sched[0] = apple_preempt_report.verified[0];
    apple_qr_sched[1] = apple_preempt_report.verified[1];
    apple_qr_sched[2] = APPLE_PREEMPT_RETURNS;
    apple_qr_sched[3] = apple_preempt_report.reason;
    apple_qr_sched[4] = apple_preempt_report.cpacr;
    apple_qr_sched[5] = apple_preempt_report.daif;
    apple_qr_sched[6] = apple_preempt_report.entered[0] + apple_preempt_report.entered[1];
    apple_qr_sched[7] = pmm_free_pages();
    apple_qr_preempt[0] = apple_preempt_report.ticks;
    apple_qr_preempt[1] = apple_preempt_report.interrupted[0];
    apple_qr_preempt[2] = apple_preempt_report.interrupted[1];
    apple_qr_preempt[3] = apple_preempt_report.resumed[0];
    apple_qr_preempt[4] = apple_preempt_report.resumed[1];
    apple_qr_preempt[5] = apple_preempt_report.frequency;
    apple_qr_progress(phase, apple_kernel_atomic_report);
}

static __attribute__((noreturn)) void stop(uint64_t reason)
{
    arch_disable_irq();
    disarm();
    apple_preempt_report.reason = reason;
    apple_preempt_report.end = counter();
    __asm__ volatile("mrs %0, daif" : "=r"(apple_preempt_report.daif));
    __asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(apple_preempt_report.ctl_final));
    apple_preempt_report.clock_ns = arch_clock_mono_ns();
    probe_puts(reason ? "AEGIS - PREEMPTION CHECKPOINT FAILED\n" :
                        "AEGIS - PREEMPTION CHECKPOINT PASSED\n");
    probe_puts("TIMER DISABLED - NO USERLAND OR DEVICE PROBES\n");
    report(reason ? "preempt-failed" : "preempt-complete");
    apple_preempt_report.stage = reason ? 255 : 3;
    for (;;) __asm__ volatile("wfe");
}

/* Kept out of line to expose the scheduling boundary to the QEMU-only GIC
 * adapter. Native code has no interrupt-controller acknowledgement here. */
__attribute__((noinline))
void apple_preempt_schedule(void)
{
    sched_tick();
    __asm__ volatile("" ::: "memory");
}

void apple_preempt_interrupt(cpu_state_t *s, int fiq)
{
    arch_disable_irq();
    aegis_task_t *self = sched_current();
    unsigned id;
    if ((uintptr_t)self == apple_preempt_report.task[0]) id = 0;
    else if ((uintptr_t)self == apple_preempt_report.task[1]) id = 1;
    else stop(2);
    uintptr_t frame = (uintptr_t)s;
    if (!self || frame < (uintptr_t)self->stack_base ||
        frame > self->kernel_stack_top - sizeof(*s)) stop(3);
    uint64_t ctl;
    __asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(ctl));
    if (!fiq || (ctl & 7) != 5 || self->on_cpu != 0 || self->is_user ||
        (s->spsr & 15) != 5 || (s->spsr & 0xc0) != 0x80 ||
        s->elr < (uintptr_t)apple_preempt_wait_begin ||
        s->elr >= (uintptr_t)apple_preempt_wait_end) stop(4);
    apple_preempt_report.frame[id] = frame;
    apple_preempt_report.elr[id] = s->elr;
    apple_preempt_report.spsr[id] = s->spsr;
    apple_preempt_report.interrupted[id]++;
    if (++apple_preempt_report.ticks > APPLE_PREEMPT_MAX_TICKS) stop(5);
    uint64_t next = counter() + apple_preempt_report.frequency / 100;
    __asm__ volatile("msr cntp_cval_el0, %0\nisb" : : "r"(next) : "memory");
    arm64_timer_account_tick();
    apple_preempt_schedule();
    /* This stack can have been suspended inside sched_tick/ctx_switch while
     * the other thread ran. Only its own task may resume this handler. */
    if (sched_current() != self || self->on_cpu != 0) stop(6);
    apple_preempt_report.resumed[id]++;
}

static void worker(unsigned id)
{
    aegis_task_t *self = sched_current();
    uint64_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    if ((uintptr_t)self != apple_preempt_report.task[id] ||
        sp < (uintptr_t)self->stack_base || sp >= self->kernel_stack_top) stop(7);
    apple_preempt_report.stack[id] = sp;
    apple_preempt_report.entered[id] = 1;
    uint8_t expected[528] __attribute__((aligned(16))) = {0};
    uint8_t actual[528] __attribute__((aligned(16)));
    for (unsigned i = 0; i < 512; i++) expected[i] = (uint8_t)(i * 23 + id * 61 + 1);
    uint32_t fpsr = 1U << id, fpcr = id ? 1U << 22 : 0;
    __builtin_memcpy(expected + 512, &fpsr, 4);
    __builtin_memcpy(expected + 516, &fpcr, 4);
    uint64_t tls = 0x61610000 + id;
    __asm__ volatile("msr tpidr_el0, %0" : : "r"(tls) : "memory");
    arm64_fpu_restore(expected);
    if (id == 0) {
        apple_preempt_report.start = counter();
        if (apple_preempt_report.start > UINT64_MAX - 2 * apple_preempt_report.frequency)
            stop(16);
        uint64_t next = apple_preempt_report.start + apple_preempt_report.frequency / 100;
        __asm__ volatile("msr cntp_cval_el0, %0\nmsr cntp_ctl_el0, %1\nisb"
                         : : "r"(next), "r"(1ULL) : "memory");
    }
    unsigned result = apple_preempt_wait(apple_preempt_report.start + 2 * apple_preempt_report.frequency,
            &apple_preempt_report.resumed[id], &apple_preempt_report.resumed[1 - id],
            APPLE_PREEMPT_RETURNS, 0x4190 + id);
    if (result) stop(result == 1 ? 8 : 9);
    arm64_fpu_save(actual);
    uint64_t live_tls, daif;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(live_tls));
    __asm__ volatile("mrs %0, daif" : "=r"(daif));
    if (live_tls != tls || sched_current() != self ||
        (daif & 0x3c0) != 0x3c0) stop(10);
    for (unsigned i = 0; i < 520; i++)
        if (actual[i] != expected[i]) stop(11);
    apple_preempt_report.verified[id] = 1;
    result = apple_preempt_wait(apple_preempt_report.start + 2 * apple_preempt_report.frequency,
            &apple_preempt_report.verified[id], &apple_preempt_report.verified[1 - id],
            1, 0x5190 + id);
    if (result) stop(12);
    if (apple_preempt_report.resumed[0] < APPLE_PREEMPT_RETURNS ||
        apple_preempt_report.resumed[1] < APPLE_PREEMPT_RETURNS ||
        apple_preempt_report.task[0] == apple_preempt_report.task[1] ||
        apple_preempt_report.stack[0] == apple_preempt_report.stack[1]) stop(13);
    stop(0);
}

static void worker_a(void) { worker(0); }
static void worker_b(void) { worker(1); }

void apple_preempt_run(void)
{
    arch_disable_irq();
    disarm();
    if (apple_timer_report.stage != 3 || apple_timer_report.returned != 1 ||
        apple_timer_report.failure || apple_memory_report.stage != 5 ||
        apple_preempt_report.stage) stop(1);
    probe_console_reset();
    probe_puts("AEGIS - TIMER-DRIVEN SCHEDULER TEST\n");
    apple_preempt_report.stage = 1;
    apple_preempt_report.frequency = apple_timer_report.frequency;
    uint64_t cpacr;
    __asm__ volatile("mrs %0, cpacr_el1" : "=r"(cpacr));
    cpacr |= 3ULL << 20;
    __asm__ volatile("msr cpacr_el1, %0\nisb" : : "r"(cpacr) : "memory");
    __asm__ volatile("mrs %0, cpacr_el1" : "=r"(apple_preempt_report.cpacr));
    arm64_timer_clock_init();
    if ((apple_preempt_report.cpacr & (3ULL << 20)) != (3ULL << 20) ||
        arch_tsc_hz() != apple_preempt_report.frequency) stop(15);
    report("preempt-before-start");
    sched_init();
    sched_spawn(worker_a);
    sched_spawn(worker_b);
    aegis_task_t *first = sched_current();
    if (!first || first->next == first || first->next->next != first) stop(14);
    apple_preempt_report.task[0] = (uintptr_t)first;
    apple_preempt_report.task[1] = (uintptr_t)first->next;
    apple_preempt_report.stage = 2;
    sched_start();
    __builtin_unreachable();
}
