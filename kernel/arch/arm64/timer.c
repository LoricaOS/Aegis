/*
 * timer.c — ARM64 generic timer (virtual timer, PPI 27) + timekeeping.
 *
 * One 100 Hz source does both jobs the x86 side splits between PIT
 * (timekeeping/polling) and LAPIC (preemption): each tick runs the
 * poller/waitq work (timer_bsp_tick equivalent) and then sched_tick.
 */

#include "arch.h"
#include "printk.h"
#include "random.h"
#include "poll.h"
#include "../../sched/waitq.h"
#include "../../sched/sched.h"
#include <stdint.h>

#define TIMER_HZ 100

static uint64_t s_freq;             /* CNTFRQ_EL0 */
static uint64_t s_ns_per_cnt_fp = 0;  /* (1e9 << 32) / cntfrq — ns/count Q32 */
static uint64_t s_interval;
static volatile uint64_t s_ticks;
static volatile int s_shutdown;
static uint64_t s_epoch_sec;        /* wall clock offset (NTP) */

void gic_enable_ppi(uint32_t intid);

static inline void
rearm(void)
{
    uint64_t now;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(now));
    __asm__ volatile("msr cntv_cval_el0, %0" : : "r"(now + s_interval));
}

void
timer_init(void)
{
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(s_freq));
    if (s_freq == 0)
        s_freq = 62500000;          /* QEMU default 62.5 MHz */
    s_interval = s_freq / TIMER_HZ;
    /* ns/count in Q32 fixed point — u128 multiply (inline) instead of u128
     * divide (__udivti3 libcall the freestanding kernel can't link). */
    s_ns_per_cnt_fp = (1000000000ULL << 32) / s_freq;

    rearm();
    __asm__ volatile("msr cntv_ctl_el0, %0" : : "r"(1UL));  /* enable, unmasked */
    /* The timer PPI (27) is enabled per-core in gic_cpu_init. */
    printk("[PIT] OK: timer at 100 Hz\n");
}

/* timer_ap_init — arm THIS AP's virtual timer (BSP timer_init already
 * computed s_interval). No print; the PPI is enabled by gic_cpu_init. */
void
timer_ap_init(void)
{
    rearm();
    __asm__ volatile("msr cntv_ctl_el0, %0" : : "r"(1UL));
}

/* timer_irq — INTID 27 handler (called from arm64_irq AFTER gic_eoi:
 * sched_tick may context-switch away and not return promptly). */
void
timer_irq(void)
{
    rearm();
    s_ticks++;
    random_add_interrupt_entropy();
    poll_sources_run();
    waitq_wake_all(&g_timer_waitq);
    if (s_shutdown)
        arch_debug_exit(0x01);
    sched_tick();
}

uint64_t
arch_get_ticks(void)
{
    return s_ticks;
}

void
arch_request_shutdown(void)
{
    s_shutdown = 1;
}

/* PSCI SYSTEM_OFF via HVC (QEMU virt PSCI conduit). Powers the VM off —
 * the arm64 equivalent of the x86 isa-debug-exit device. */
void
arch_debug_exit(unsigned char value)
{
    (void)value;
    register uint64_t x0 __asm__("x0") = 0x84000008UL;   /* SYSTEM_OFF */
    __asm__ volatile("hvc #0" : "+r"(x0) : : "x1", "x2", "x3", "memory");
    for (;;)
        arch_halt();
}

/* TSC-equivalent: the generic timer IS the calibrated clock. */
void
arch_tsc_calibrate(uint64_t cycles_per_10ms)
{
    (void)cycles_per_10ms;
}

uint64_t
arch_tsc_hz(void)
{
    return s_freq;
}

/* arch_clock_mono_ns — nanoseconds since counter start, from the generic
 * timer's free-running CNTVCT (ns resolution; the tick counter is 10 ms-
 * quantized, which made musl mkstemp temp names collide across processes —
 * see the x86 pit.c twin). 128-bit intermediate avoids v*1e9 overflow. */
uint64_t
arch_clock_mono_ns(void)
{
    if (!s_freq || !s_ns_per_cnt_fp)
        return s_ticks * (1000000000ULL / TIMER_HZ);
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return (uint64_t)(((__uint128_t)v * s_ns_per_cnt_fp) >> 32);
}

void
arch_clock_gettime(uint64_t *sec, uint64_t *nsec)
{
    uint64_t ns = arch_clock_mono_ns();
    if (sec)  *sec  = s_epoch_sec + ns / 1000000000ULL;
    if (nsec) *nsec = ns % 1000000000ULL;
}

void
arch_clock_settime(uint64_t sec)
{
    s_epoch_sec = sec - arch_clock_mono_ns() / 1000000000ULL;
}
