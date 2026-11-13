/* First native timer gate: one EL1 physical-timer FIQ, complete register
 * frame return, then mask/disable and halt. No scheduler/pollers/GIC/AIC. */
#include "kernel_timer.h"
#include "kernel_memory.h"
#include "probe_console.h"
#include "qr_report.h"
#include "../arch.h"
#include "printk.h"
#include <stddef.h>
#ifdef APPLE_USER_CHECKPOINT
#include "kernel_user.h"
#endif
#ifdef APPLE_PREEMPT_CHECKPOINT
#include "kernel_preempt.h"
#endif

extern volatile uint64_t apple_kernel_atomic_report[4];
extern char apple_timer_wait_begin[], apple_timer_wait_end[], apple_kernel_stack_top[];
extern unsigned apple_timer_wait(uint64_t, const volatile uint64_t *, const volatile uint64_t *);
volatile struct apple_timer_report apple_timer_report;

static void publish(const char *phase)
{
    apple_qr_timer[0] = apple_timer_report.frequency;
    apple_qr_timer[1] = apple_timer_report.delivered;
    apple_qr_timer[2] = apple_timer_report.returned;
    apple_qr_timer[3] = apple_timer_report.failure;
    apple_qr_timer[4] = apple_timer_report.hcr;
    apple_qr_timer[5] = apple_timer_report.gate_before;
    apple_qr_timer[6] = apple_timer_report.gate_after;
    apple_qr_timer[7] = apple_timer_report.cnthctl;
    apple_qr_progress(phase, apple_kernel_atomic_report);
}

static void disarm(void)
{
    uint64_t ctl = 2; /* disabled and masked; ISTATUS is read-only */
    __asm__ volatile("msr cntp_ctl_el0, %0\nisb" : : "r"(ctl) : "memory");
}

static __attribute__((noreturn)) void stop(const char *phase, uint64_t reason)
{
    __asm__ volatile("msr daifset, #3\nisb" ::: "memory");
    apple_timer_report.failure = reason;
    probe_puts("TIMER CHECKPOINT HALTED - ");
    probe_puts(phase);
    probe_puts("\nNO SCHEDULER OR DEVICE PROBES\n");
    publish(phase);
    apple_timer_report.stage = reason ? 255 : 3;
    for (;;) __asm__ volatile("wfe");
}

void apple_timer_prepare(const struct apple_kernel_handoff *h)
{
    if (!h || apple_timer_report.stage) stop("timer-setup-refused", 1);
    apple_timer_report.hcr = h->timer_hcr;
    apple_timer_report.gate_before = h->timer_gate_before;
    apple_timer_report.gate_after = h->timer_gate_after;
    apple_timer_report.cnthctl = h->timer_cnthctl;
    uint64_t midr;
    __asm__ volatile("mrs %0, midr_el1" : "=r"(midr));
    uint64_t access = h->timer_hcr & (1ULL << 34) ? 3ULL << 10 : 3;
    if (((midr >> 24) & 255) == 0x61 &&
        (!(h->timer_hcr & (1ULL << 31)) || (h->timer_hcr & (1ULL << 3)) ||
         !(h->timer_gate_after & 2) || (h->timer_cnthctl & access) != access))
        stop("timer-setup-refused", 2);
    apple_timer_report.stage = 1;
}

static void interrupt(cpu_state_t *s, int fiq)
{
    /* No shared locks, logging, allocation or device-register accesses here.
     * Only the timer this diagnostic owns is quiesced. Unknown FIQ sources
     * are not guessed/acknowledged; they force a foreground failure report. */
    __asm__ volatile("msr daifset, #3" ::: "memory");
    uint64_t frame = (uintptr_t)s, top = (uintptr_t)apple_kernel_stack_top;
    if (frame < top - 32768 || frame > top - sizeof(*s)) {
        disarm();
        apple_timer_report.failure = 3;
        /* Never ERET through a frame outside this diagnostic's stack. */
        apple_timer_report.stage = 255;
        for (;;) __asm__ volatile("wfe");
    }
    uint64_t ctl;
    __asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(ctl));
    disarm();
    apple_timer_report.ctl_entry = ctl;
    apple_timer_report.saved_spsr = s->spsr;
    apple_timer_report.saved_elr = s->elr;
    apple_timer_report.frame = frame;
    s->spsr |= 0xc0; /* return with FIQ + IRQ masked, preventing any storm */
    if (!fiq || apple_timer_report.stage != 2 || apple_timer_report.delivered ||
        (ctl & 7) != 5 || (apple_timer_report.saved_spsr & 15) != 5 ||
        (apple_timer_report.saved_spsr & 0xc0) != 0x80 ||
        s->elr < (uintptr_t)apple_timer_wait_begin || s->elr >= (uintptr_t)apple_timer_wait_end) {
        apple_timer_report.failure = fiq ? 4 : 5;
        return;
    }
    apple_timer_report.delivered = 1;
    __asm__ volatile("dsb sy" ::: "memory");
}

void apple_timer_fiq(cpu_state_t *s)
{
#ifdef APPLE_PREEMPT_CHECKPOINT
    if (apple_preempt_report.stage == 2) {
        apple_preempt_interrupt(s, 1);
        return;
    }
#endif
    interrupt(s, 1);
}
void apple_timer_unexpected_irq(cpu_state_t *s)
{
#ifdef APPLE_PREEMPT_CHECKPOINT
    if (apple_preempt_report.stage == 2) {
        apple_preempt_interrupt(s, 0);
        return;
    }
#endif
    interrupt(s, 0);
}

__attribute__((noreturn))
void apple_timer_run(void)
{
    __asm__ volatile("msr daifset, #3\nisb" ::: "memory");
    if (apple_memory_report.stage != 5 || apple_timer_report.stage != 1)
        stop("timer-setup-refused", 6);
    probe_console_reset();
    probe_puts("AEGIS - PHYSICAL TIMER FIQ RETURN TEST\n");
    publish("timer-before-counter");
    uint64_t freq, start, ctl, virtual_ctl = 2;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    if (freq < 1000 || freq > 1000000000ULL) stop("timer-bad-frequency", 7);
    apple_timer_report.frequency = freq;
    __asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(ctl));
    apple_timer_report.ctl_before = ctl;
    disarm();
    __asm__ volatile("msr cntv_ctl_el0, %0\nisb" : : "r"(virtual_ctl) : "memory");
    publish("timer-before-arm");
    __asm__ volatile("isb\nmrs %0, cntpct_el0" : "=r"(start));
    if (start > UINT64_MAX - 2 * freq) stop("timer-counter-wrap", 8);
    apple_timer_report.start = start;
    apple_timer_report.stage = 2;
    uint64_t deadline = start + 2 * freq, compare = start + freq / 100, enable = 1;
    __asm__ volatile("msr cntp_cval_el0, %0\nmsr cntp_ctl_el0, %1\nisb"
                     : : "r"(compare), "r"(enable) : "memory");
    unsigned result = apple_timer_wait(deadline, &apple_timer_report.delivered,
                                       &apple_timer_report.failure);
    disarm();
    __asm__ volatile("isb\nmrs %0, cntpct_el0" : "=r"(apple_timer_report.end));
    __asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(apple_timer_report.ctl_final));
    __asm__ volatile("mrs %0, daif" : "=r"(apple_timer_report.daif_after));
    if (apple_timer_report.failure) stop("timer-unexpected-source", apple_timer_report.failure);
    if (result == 1) stop("timer-timeout", 9);
    if (result || apple_timer_report.delivered != 1 ||
        (apple_timer_report.ctl_final & 3) != 2 ||
        (apple_timer_report.daif_after & 0x3c0) != 0x3c0 ||
        apple_timer_report.end < start)
        stop("timer-return-failed", 10);
    apple_timer_report.returned = 1; /* foreground executed after ERET */
    printk("[APPLE] TIMER CHECKPOINT: physical FIQ + register return passed\n");
#ifdef APPLE_USER_CHECKPOINT
    apple_timer_report.stage = 3;
    publish("timer-complete");
    apple_user_run();
#elif defined(APPLE_PREEMPT_CHECKPOINT)
    apple_timer_report.stage = 3;
    publish("timer-complete");
    apple_preempt_run();
#elif defined(APPLE_SCHED_CHECKPOINT)
    apple_timer_report.stage = 3;
    publish("timer-complete");
    extern void apple_sched_run(void) __attribute__((noreturn));
    apple_sched_run();
#endif
    printk("[APPLE] HALTED: timer disabled, no scheduler or device probes\n");
    stop("timer-complete", 0);
}
