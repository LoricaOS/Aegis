#ifndef AEGIS_POLL_H
#define AEGIS_POLL_H

/* Per-tick device-poll registry.
 *
 * Aegis polls a set of devices once per timer tick (timer_bsp_tick, BSP only).
 * Historically that list was a hardcoded sequence of calls inside the timer
 * ISR, which (a) coupled the arch timer file to ~13 driver headers and (b) was
 * exactly the brittle shape behind the Hyper-V Gen 2 "polling silently died"
 * episode.  This registry decouples the two: the timer path calls
 * poll_sources_run(); the platform declares WHAT to poll, and in WHAT ORDER,
 * via poll_source_register() priorities.
 *
 * Ordering: sources run in ascending priority.  The ONE load-bearing
 * constraint is that network RX (POLL_PRIO_NETDEV / POLL_PRIO_LOOPBACK) runs
 * before the TCP timer (POLL_PRIO_TCP_TIMER), so inbound segments are delivered
 * before tcp_tick processes retransmits/acks.  All other pollers are
 * order-independent; the values below also preserve the historical call order
 * for bisectability.  Equal priorities keep registration order (stable insert).
 */

typedef void (*poll_fn_t)(void);

enum {
    POLL_PRIO_USB         = 10, /* xhci HID event ring                        */
    POLL_PRIO_HV_IC       = 20, /* Hyper-V synthetic kbd/mouse + IC channels  */
    POLL_PRIO_NETDEV      = 30, /* network RX — MUST be < POLL_PRIO_TCP_TIMER  */
    POLL_PRIO_AUDIO       = 40, /* HDA one-shot playback stop                 */
    POLL_PRIO_VIRTIO_MISC = 50, /* virtio balloon + input                     */
    POLL_PRIO_LOOPBACK    = 60, /* ip loopback queue — also < TCP_TIMER       */
    POLL_PRIO_TCP_TIMER   = 70, /* tcp_tick retransmit timer                  */
};

/* Register fn to be invoked once per timer tick, ordered by priority.
 *
 * INVARIANT: call only during single-threaded boot, before interrupts are
 * enabled (i.e. before sched_start).  The registry is read locklessly from the
 * timer ISR; this is safe precisely because all registration completes before
 * the first tick can fire.  Returns 0 on success, -1 if the table is full
 * (logged).  name is for diagnostics only and is not copied. */
int poll_source_register(poll_fn_t fn, int priority, const char *name);

/* Invoke all registered poll sources in priority order.  Called once per tick
 * from timer_bsp_tick (BSP only — the pollers are single-producer). */
void poll_sources_run(void);

/* Register the platform's device poll sources.  Defined per-arch
 * (kernel/arch/<arch>/poll_sources.c) — that file owns the driver includes so
 * the timer path doesn't have to.  Called once from kernel_main after the
 * device inits, before interrupts are enabled. */
void poll_sources_init(void);

#endif /* AEGIS_POLL_H */
