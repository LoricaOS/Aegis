#include "pit.h"
#include "pic.h"
#include "lapic.h"
#include "arch.h"
#include "printk.h"
#include "random.h"
#include "hyperv.h"
#include "../../core/poll.h"
#include "../../sched/waitq.h"

#define PIT_CHANNEL0 0x40
#define PIT_CMD      0x43
/* Channel 0, lobyte/hibyte, mode 3 (square wave) */
#define PIT_MODE     0x36
/* 1193182 Hz / 100 = 11931.82 → round to 11932 */
#define PIT_DIVISOR  11932

/* File-static: never accessed outside pit.c.
 * kernel/core/ uses arch_get_ticks() declared in arch.h. */
static volatile uint64_t s_ticks = 0;

/* TSC-based timekeeping — fixes monotonic-clock lag under load.  The 100 Hz
 * interrupt counter (s_ticks) is NOT incremented while a long syscall runs with
 * interrupts disabled (eager file-backed mmap copies, fork page copies); under
 * heavy load this drops ~95% of ticks, so the monotonic clock crawls at ~5% of
 * real time and every userspace timeout (Core::Timer, curl) stretches ~20x —
 * which looks like a hang.  The TSC is a free-running cycle counter immune to
 * dropped interrupts; once calibrated (arch_tsc_calibrate, from
 * lapic_timer_init) the tick value is derived from it so time tracks reality
 * regardless of load.  Falls back to the interrupt counter when the CPU lacks
 * an invariant TSC (e.g. qemu64). */
static uint64_t s_tsc_hz         = 0;   /* TSC cycles/sec; 0 = uncalibrated     */
static uint64_t s_tsc_base       = 0;   /* TSC at calibration                   */
static uint64_t s_tsc_ticks_base = 0;   /* s_ticks at calibration (continuity)  */
static uint64_t s_ns_per_cyc_fp  = 0;   /* (1e9 << 32) / tsc_hz — ns/cycle Q32  */

/* cur_ticks — authoritative 100 Hz tick value: TSC-derived once calibrated,
 * else the raw interrupt counter. */
static inline uint64_t
cur_ticks(void)
{
    if (s_tsc_hz) {
        uint64_t cpt = s_tsc_hz / 100;          /* cycles per 10 ms tick */
        if (cpt)
            return s_tsc_ticks_base + (arch_get_cycles() - s_tsc_base) / cpt;
    }
    return s_ticks;
}

uint64_t
pit_ticks(void)
{
    return cur_ticks();
}

/* Set by arch_request_shutdown(); checked in pit_handler each tick.
 * When set, pit_handler calls arch_debug_exit from within the ISR
 * (IF=0, no task context) to avoid the race where the task context
 * continues running after the port write and outputs a second line. */
static volatile int s_shutdown = 0;

/* Wall clock: epoch_offset + (ticks / 100) = current Unix time in seconds.
 * Seeded from the CMOS RTC at boot (clock_seed_from_rtc), then refined by
 * sys_clock_settime (chronos NTP daemon). */
static volatile uint64_t s_epoch_offset = 0;

/* Forward decl: seed the wall clock from the CMOS RTC. Defined below, called
 * once from pit_init. Without it the wall clock starts at the Unix epoch
 * (1970), which makes every TLS certificate look "not yet valid". */
static void clock_seed_from_rtc(void);

/* Forward declaration: sched_tick is implemented in kernel/sched/sched.c.
 * We use a forward decl here to avoid a circular include dependency.
 * -Ikernel/sched is in CFLAGS so we could include sched.h, but the
 * forward decl is cleaner for a single-function dependency. */
void sched_tick(void);

/* PIT wakes g_timer_waitq each tick so timed pollers re-check their
 * deadline. Replaces the old single-slot g_poll_waiter (deleted). */

void
pit_init(void)
{
    /* Program PIT channel 0 */
    outb(PIT_CMD, PIT_MODE);
    outb(PIT_CHANNEL0, PIT_DIVISOR & 0xFF);        /* low byte  */
    outb(PIT_CHANNEL0, (PIT_DIVISOR >> 8) & 0xFF); /* high byte */

    /* Unmask IRQ0 so the PIT starts firing */
    pic_unmask(0);

    /* Seed the wall clock from the battery-backed CMOS RTC so cert/time checks
     * work before chronos (NTP) runs.  Silent (no boot-oracle line) and
     * best-effort — leaves epoch_offset at 0 if the RTC reads implausibly. */
    clock_seed_from_rtc();

    printk("[PIT] OK: timer at 100 Hz\n");
}

/* timer_bsp_tick — the once-per-tick timekeeping + device-polling work that
 * must run on exactly one CPU (the BSP).  Normally driven by the 8254 PIT
 * (pit_handler).  Hyper-V Gen 2 VMs have no PIT, so there the LAPIC timer
 * handler calls this directly on the BSP (see lapic_timer_handler).  Must NOT
 * run concurrently on multiple CPUs — the device pollers are single-producer. */
void
timer_bsp_tick(void)
{
    s_ticks++;
    random_add_interrupt_entropy();
    /* Run all registered device pollers in priority order (USB, Hyper-V ICs,
     * network RX, audio, virtio misc, loopback, TCP timer).  The list and its
     * ordering live in poll_sources_init (kernel/arch/x86_64/poll_sources.c),
     * not here — see kernel/core/poll.h. */
    poll_sources_run();
    /* Yield to QEMU's SLIRP event loop via port I/O (causes VM-exit on TCG).
     * The doorbell write in virtio_net_poll triggers virtio processing but not
     * SLIRP's connection accept loop.  A port I/O read forces QEMU's main event
     * loop to run select()/poll(), which processes SLIRP hostfwd connections.
     * Port 0x61 (PC speaker control) is safe to read in any state.  Skipped on
     * Hyper-V: there is no SLIRP there, and the port read would just burn a
     * VM-exit every tick (~100/s) for nothing. */
    if (!hyperv_present())
        inb(0x61);
    /* Wake all timed pollers so they can re-check their deadline. */
    waitq_wake_all(&g_timer_waitq);
    /* Check shutdown LAST so this tick's polling/wake work completes first.
     * Runs in ISR context (IF=0): no task code executes after the
     * debug-exit port write. */
    if (s_shutdown)
        arch_debug_exit(0x01);
}

void
pit_handler(void)
{
    /* Preemption is the LAPIC timer's job (vector 0x30 → lapic_timer_handler
     * → sched_tick), armed on the BSP in kernel_main before sched_start and
     * on each AP in ap_entry.  The PIT is timekeeping + device polling only;
     * calling sched_tick here as well gave the BSP two 100 Hz preemption
     * sources (~200 Hz, irregular ~5 ms slices, doubled overhead).
     * Fallback: if the LAPIC never initialized (kva_alloc failure in
     * lapic_init — never seen in practice), keep preempting from the PIT so
     * the system stays alive rather than wedging in the first hlt loop. */
    if (!lapic_active())
        sched_tick();
    timer_bsp_tick();
}

/* arch_request_shutdown — called from task context to request a clean exit.
 * The actual arch_debug_exit is deferred to the next pit_handler invocation
 * (ISR context, IF=0) so no task code runs after the debug_exit port write. */
void
arch_request_shutdown(void)
{
    s_shutdown = 1;
}

/* arch_get_ticks — arch-boundary accessor for the tick counter.
 * Declared in arch.h so kernel/core/ can call it without including pit.h. */
uint64_t
arch_get_ticks(void)
{
    return cur_ticks();
}

/* arch_tsc_calibrate — record the measured TSC rate so cur_ticks() derives time
 * from the free-running counter.  cycles_per_10ms is measured by
 * lapic_timer_init over its PIT/HV 10 ms window.  Engages only if the CPU
 * advertises an invariant TSC (CPUID 8000_0007h EDX bit 8) and the rate is sane
 * (0.1-100 GHz); otherwise the interrupt counter stays authoritative. */
void
arch_tsc_calibrate(uint64_t cycles_per_10ms)
{
    /* Don't require the invariant-TSC CPUID bit: QEMU leaves it off by default
     * (it blocks live migration) yet has a perfectly stable TSC, and every CPU
     * Aegis targets has an invariant TSC.  A sane measured rate is the gate. */
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(0x80000007u), "c"(0));
    int invariant = (edx & (1u << 8)) ? 1 : 0;
    uint64_t hz = cycles_per_10ms * 100ULL;
    if (hz < 100000000ULL || hz > 100000000000ULL) {
        printk("[TSC] WARN: implausible rate, keeping tick counter\n");
        return;
    }
    s_tsc_ticks_base = s_ticks;
    s_tsc_base       = arch_get_cycles();
    s_tsc_hz         = hz;
    /* ns/cycle in Q32 fixed point: (1e9 << 32) fits u64 (≈2^61.9), and the hz
     * range gate above keeps the result nonzero. Lets arch_clock_mono_ns use a
     * u128 multiply (inline mulq) instead of a u128 divide (__udivti3 libcall,
     * unlinkable in the freestanding kernel). */
    s_ns_per_cyc_fp  = (1000000000ULL << 32) / hz;
    printk("[TSC] OK: monotonic clock TSC-based, %lu MHz (invariant=%u)\n",
           (unsigned long)(hz / 1000000ULL), (unsigned)invariant);
}

/* arch_tsc_hz — calibrated TSC frequency (cycles/sec), 0 if uncalibrated.
 * For fine-grained timing (e.g. the ext2 perf bench) where the 100 Hz tick
 * counter is too coarse. */
uint64_t
arch_tsc_hz(void)
{
    return s_tsc_hz;
}

/* arch_clock_mono_ns — nanoseconds since boot, TSC-derived when calibrated
 * (else 10 ms tick granularity). The 10 ms-quantized clock broke concurrent
 * builds: musl's mkstemp derives temp names from clock_gettime nanoseconds, so
 * two gcc's spawned in the same tick got IDENTICAL /tmp/ccXXXXXX.s names — and
 * its 100 collision retries re-derived from the same frozen value.
 * ns = cycles * s_ns_per_cyc_fp >> 32 (fixed-point, precomputed at calibrate):
 * a u128 MULTIPLY inlines to one mulq at any -O level, whereas u128 DIVISION
 * emits a __udivti3 libcall the freestanding kernel can't link (-O0 selfhost). */
uint64_t
arch_clock_mono_ns(void)
{
    if (s_tsc_hz && s_ns_per_cyc_fp) {
        uint64_t d = arch_get_cycles() - s_tsc_base;
        return s_tsc_ticks_base * 10000000ULL +
               (uint64_t)(((__uint128_t)d * s_ns_per_cyc_fp) >> 32);
    }
    return s_ticks * 10000000ULL;
}

/* arch_clock_gettime — returns {seconds, nanoseconds} since Unix epoch.
 * Sub-second part is TSC-derived (see arch_clock_mono_ns), not tick-quantized. */
void
arch_clock_gettime(uint64_t *sec, uint64_t *nsec)
{
    uint64_t ns = arch_clock_mono_ns();
    *sec  = s_epoch_offset + ns / 1000000000ULL;
    *nsec = ns % 1000000000ULL;
}

/* arch_clock_settime — set wall clock. Offset derived from the same
 * mono-ns source arch_clock_gettime reads, so set/get stay consistent. */
void
arch_clock_settime(uint64_t sec)
{
    s_epoch_offset = sec - arch_clock_mono_ns() / 1000000000ULL;
}

/* ── CMOS RTC → wall-clock seed ─────────────────────────────────────────── */

#define CMOS_ADDR 0x70
#define CMOS_DATA 0x71

static uint8_t
cmos_read(uint8_t reg)
{
    /* Preserve the NMI-disable bit (0x80) state: read it back is overkill;
     * we select the register with the top bit clear (NMI enabled), which is
     * the conventional, safe choice for reading time registers at boot. */
    outb(CMOS_ADDR, reg);
    return inb(CMOS_DATA);
}

static int
cmos_update_in_progress(void)
{
    outb(CMOS_ADDR, 0x0A);
    return inb(CMOS_DATA) & 0x80;
}

/* Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
 * Valid for any Gregorian date; m in [1,12], d in [1,31]. */
static int64_t
days_from_civil(int64_t y, uint32_t m, uint32_t d)
{
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    uint32_t yoe = (uint32_t)(y - era * 400);                 /* [0, 399]    */
    uint32_t doy = (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u; /* [0,365] */
    uint32_t doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;  /* [0, 146096] */
    return era * 146097 + (int64_t)doe - 719468;
}

#define BCD2BIN(x) ((uint8_t)(((x) & 0x0Fu) + (((x) >> 4) * 10u)))

/* clock_seed_from_rtc — read the CMOS RTC and seed s_epoch_offset so that
 * arch_clock_gettime returns real wall time from boot.  Best-effort: any
 * implausible field leaves the clock at the epoch (chronos can still fix it). */
static void
clock_seed_from_rtc(void)
{
    /* Wait out an in-progress update so all fields are mutually consistent. */
    uint32_t guard = 0;
    while (cmos_update_in_progress() && guard++ < 1000000u)
        ;

    uint8_t sec  = cmos_read(0x00);
    uint8_t min  = cmos_read(0x02);
    uint8_t hour = cmos_read(0x04);
    uint8_t day  = cmos_read(0x07);
    uint8_t mon  = cmos_read(0x08);
    uint8_t year = cmos_read(0x09);
    uint8_t regB = cmos_read(0x0B);

    /* 12-hour mode (regB bit1 clear): bit7 of the hour byte is the PM flag.
     * Extract it BEFORE any BCD conversion masks it off. */
    int pm = 0;
    if (!(regB & 0x02)) {
        pm = hour & 0x80;
        hour &= 0x7F;
    }

    /* BCD encoding unless regB bit2 (DM) marks the values as already binary. */
    if (!(regB & 0x04)) {
        sec  = BCD2BIN(sec);
        min  = BCD2BIN(min);
        hour = BCD2BIN(hour);
        day  = BCD2BIN(day);
        mon  = BCD2BIN(mon);
        year = BCD2BIN(year);
    }

    /* 12-hour → 24-hour: 12AM=0, 1..11AM as-is, 12PM=12, 1..11PM +12. */
    if (!(regB & 0x02)) {
        hour = (uint8_t)(hour % 12);
        if (pm) hour = (uint8_t)(hour + 12);
    }

    /* Reject implausible fields rather than seed a garbage clock. */
    if (mon < 1 || mon > 12 || day < 1 || day > 31 ||
        hour > 23 || min > 59 || sec > 60)
        return;

    int64_t full_year = 2000 + (int64_t)year;   /* CMOS year is 2-digit */
    int64_t days = days_from_civil(full_year, mon, day);
    int64_t epoch = days * 86400 + (int64_t)hour * 3600 +
                    (int64_t)min * 60 + (int64_t)sec;

    /* Must be after 2020-01-01 (1577836800) to be believable — guards against a
     * dead/zeroed RTC battery seeding an only-slightly-wrong time. */
    if (epoch < 1577836800LL)
        return;

    s_epoch_offset = (uint64_t)epoch - cur_ticks() / 100;
}
