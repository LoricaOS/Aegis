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

/* Timer register + PPI selection. On real Pi 5 (entered at EL2, dropped to
 * EL1) the VIRTUAL timer PPI (27) does not deliver — the scheduler tick never
 * fires and no task past the idle loop runs. Use the PHYSICAL timer (cntp,
 * PPI 30) there instead: boot_probe.S sets CNTHCTL_EL2.EL1PC{EN,TEN} so EL1
 * may access it and zeros CNTVOFF. QEMU virt / Limine keep the virtual timer,
 * which works at EL1 on that path. The PPI number is mirrored in gic_v2.c
 * (enable) and traps.c (dispatch) under the same guard. */
#ifdef AEGIS_BOOT_NATIVE
#define TMR_CTL_EL0   "cntp_ctl_el0"
#define TMR_CVAL_EL0  "cntp_cval_el0"
#define TMR_CT_EL0    "cntpct_el0"
#else
#define TMR_CTL_EL0   "cntv_ctl_el0"
#define TMR_CVAL_EL0  "cntv_cval_el0"
#define TMR_CT_EL0    "cntvct_el0"
#endif

static uint64_t s_freq;             /* CNTFRQ_EL0 */
static uint64_t s_ns_per_cnt_fp = 0;  /* (1e9 << 32) / cntfrq — ns/count Q32 */
static uint64_t s_interval;
static volatile uint64_t s_ticks;
static volatile int s_shutdown;
static uint64_t s_epoch_sec;        /* wall clock offset (NTP) */

void gic_enable_ppi(uint32_t intid);
#ifdef AEGIS_BOOT_NATIVE
void pi5_fan_governor(void);   /* native/pi5_thermal.c — temp→fan-speed curve */
#endif

static inline void
rearm(void)
{
    uint64_t now;
    __asm__ volatile("mrs %0, " TMR_CT_EL0 : "=r"(now));
    __asm__ volatile("msr " TMR_CVAL_EL0 ", %0" : : "r"(now + s_interval));
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
    __asm__ volatile("msr " TMR_CTL_EL0 ", %0" : : "r"(1UL));  /* enable, unmasked */
    /* The timer PPI is enabled per-core in gic_cpu_init. */
#ifdef AEGIS_BOOT_NATIVE
    printk("[PIT] OK: timer at 100 Hz (physical, PPI 30)\n");
#else
    printk("[PIT] OK: timer at 100 Hz (virtual, PPI 27)\n");
#endif
}

/* timer_ap_init — arm THIS AP's virtual timer (BSP timer_init already
 * computed s_interval). No print; the PPI is enabled by gic_cpu_init. */
void
timer_ap_init(void)
{
    rearm();
    __asm__ volatile("msr " TMR_CTL_EL0 ", %0" : : "r"(1UL));
}

#ifdef AEGIS_BOOT_NATIVE
void native_watchdog_tick(void);   /* kernel/arch/arm64/main.c — petted watchdog */
#endif

/* timer_irq — INTID 27 handler (called from arm64_irq AFTER gic_eoi:
 * sched_tick may context-switch away and not return promptly). */
void
timer_irq(void)
{
    rearm();
    s_ticks++;
#ifdef AEGIS_BOOT_NATIVE
    native_watchdog_tick();     /* pet the BCM2712 watchdog while petting window open */
    {
        /* Temperature-based fan governor, ~1 Hz (MMIO-only, IRQ-context safe). */
        static uint32_t s_fan_ticks = 0;
        if (++s_fan_ticks >= TIMER_HZ) {
            s_fan_ticks = 0;
            pi5_fan_governor();
        }
    }
#endif
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

/* PSCI power control. value==1 => SYSTEM_RESET (reboot), else SYSTEM_OFF (power
 * off). Conduit differs: QEMU virt's PSCI is at EL2 (HVC); the real Pi 5's is at
 * EL3, reached via SMC — so the native build issues `smc` and shutdown/reboot
 * actually cut/cycle power instead of hanging in a WFI halt. */
void
arch_debug_exit(unsigned char value)
{
    uint64_t fn = (value == 1) ? 0x84000009UL   /* PSCI SYSTEM_RESET */
                               : 0x84000008UL;   /* PSCI SYSTEM_OFF   */
    register uint64_t x0 __asm__("x0") = fn;
#ifdef AEGIS_BOOT_NATIVE
    __asm__ volatile("smc #0" : "+r"(x0) : : "x1", "x2", "x3", "memory");
#else
    __asm__ volatile("hvc #0" : "+r"(x0) : : "x1", "x2", "x3", "memory");
#endif
    for (;;)
        arch_halt();
}

#ifdef AEGIS_BOOT_NATIVE
/* arch_native_reset — deliberate hard reboot of the real Pi 5.
 *
 * The BCM2712 PM watchdog is the *proven* reset path on this board (the whole
 * netboot dev-loop relies on it firing even a wedged CPU); the stock EL3 armstub
 * does not implement PSCI SYSTEM_RESET, so `smc` reboot just falls through to a
 * halt. Arm the watchdog with a tiny timeout (~10 ticks @ ~65 kHz ≈ 150 µs) and
 * set PM_RSTC WRCFG_FULL_RESET → the board resets almost immediately and re-runs
 * the firmware (→ TFTP netboot in dev). Register layout matches native_arm_
 * watchdog() in main.c: watchdog@7d200000 → CPU-phys 0x10_7d200000, password
 * 0x5a000000, PM_WDOG=+0x24, PM_RSTC=+0x1c. */
void
arch_native_reset(void)
{
    volatile uint8_t *pm = (volatile uint8_t *)arch_dmap(0x107d200000UL);
    *(volatile uint32_t *)(pm + 0x24) = 0x5a000000UL | 0x0000000aUL;   /* PM_WDOG ~10 ticks */
    uint32_t rstc = *(volatile uint32_t *)(pm + 0x1c);
    *(volatile uint32_t *)(pm + 0x1c) =
        0x5a000000UL | (rstc & 0xffffffcfUL) | 0x00000020UL;           /* WRCFG_FULL_RESET */
    for (;;)
        arch_halt();
}
#endif

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
    __asm__ volatile("mrs %0, " TMR_CT_EL0 : "=r"(v));
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
