#ifndef AEGIS_PIT_H
#define AEGIS_PIT_H

#include <stdint.h>

/* Program PIT channel 0 at 100 Hz. Unmasks IRQ0.
 * Prints [PIT] OK: timer at 100 Hz. */
void pit_init(void);

/* Called by isr_dispatch on vector 0x20 (after EOI is sent).
 * Timekeeping + polling only: increments the tick counter, polls
 * xHCI/net/TCP, and wakes timed pollers.  Preemption (sched_tick) is
 * driven by the per-CPU LAPIC timer on vector 0x30; pit_handler calls
 * sched_tick only as a fallback when the LAPIC failed to initialize. */
void pit_handler(void);

/* The once-per-tick timekeeping + device-polling body (tick counter, xHCI/net/
 * TCP/loopback polling, timed-poller wake, shutdown check).  Driven by the PIT
 * on real hardware/QEMU; on Hyper-V Gen 2 (no 8254 PIT) it is driven from the
 * BSP's LAPIC timer handler instead.  Single-CPU only — never call concurrently. */
void timer_bsp_tick(void);

/* pit_ticks — monotonic 100 Hz tick count since boot (TSC-derived once
 * calibrated).  Each tick is 10 ms.  Used by printk for log timestamps. */
uint64_t pit_ticks(void);

#endif /* AEGIS_PIT_H */
