#include "poll.h"

/* Defined in net/netdev.c (or net/net_stub.c when CONFIG_NET=n). */
extern volatile int g_in_isr_poll;
#include "printk.h"

/* Generic per-tick poll-source registry.  See poll.h for the contract.
 * No driver dependencies live here — this is portable core logic.  The actual
 * device list is in the per-arch poll_sources.c (poll_sources_init). */

#define MAX_POLL_SOURCES 32

struct poll_source {
    poll_fn_t   fn;
    int         priority;
    const char *name;
};

static struct poll_source s_sources[MAX_POLL_SOURCES];
static int s_count = 0;

int
poll_source_register(poll_fn_t fn, int priority, const char *name)
{
    if (!fn)
        return -1;
    if (s_count >= MAX_POLL_SOURCES) {
        printk("[POLL] FAIL: too many poll sources (max %u), dropped %s\n",
               (unsigned)MAX_POLL_SOURCES, name ? name : "?");
        return -1;
    }
    /* Insertion sort by priority.  Strict '>' so equal priorities do not
     * shift — the new entry lands AFTER existing equal-priority ones, i.e. a
     * stable insert that preserves registration order within a priority.
     * The table is tiny and built once at boot, so this keeps poll_sources_run
     * a flat indirect-call walk with zero per-tick sorting. */
    int i = s_count;
    while (i > 0 && s_sources[i - 1].priority > priority) {
        s_sources[i] = s_sources[i - 1];
        i--;
    }
    s_sources[i].fn       = fn;
    s_sources[i].priority = priority;
    s_sources[i].name     = name;
    s_count++;
    return 0;
}

/* NOTE: on arm64 the timer PPI is per-core, so this runs on ALL cores at 100 Hz
 * — x86 is deliberately the opposite (pit.c: "Must NOT run concurrently").
 * Every poll source that walks shared device state must therefore be
 * individually SMP-safe. xhci_poll and gem_poll each take a single-flight
 * trylock; netdev_poll_all is serialised by netdev_lock.
 *
 * (This comment previously asserted xhci_poll's trylock as existing fact when
 * it did not — the change had been reverted and the comment left behind. It is
 * true now. If you revert one of those guards, fix this comment in the same
 * commit: a false claim here is worse than no comment, because it stops the
 * next person looking.)
 *
 * Do NOT add a global lock here: it would serialise a slow source (netdev
 * during DHCP) against the fast ones and starve them. */
void
poll_sources_run(void)
{
    /* Mark the whole tick as ISR/poll context, not just the netdev source.
     *
     * g_in_isr_poll is what arp_resolve consults to decide whether it may
     * BLOCK (arch_wait_for_irq() = `sti; hlt; cli`, then dev->poll()). It used
     * to be set only inside netdev_poll_all, whose name it then carried — but
     * every source in this loop runs in the same PIT-ISR context with
     * interrupts disabled, and one of them, tcp_tick, sends.
     *
     * tcp_tick (PRIO 70) is a SIBLING of netdev_poll_all (PRIO 30) here, not
     * nested inside it, so the flag was clear when it ran. tcp_tick holds
     * tcp_lock across its retransmit; if the destination's ARP entry had
     * expired, arp_resolve took the blocking path, re-enabled interrupts inside
     * the ISR while tcp_lock was held, and called dev->poll() — which drives RX
     * straight into tcp_rx and its spin_lock_irqsave(&tcp_lock). Same CPU,
     * non-recursive ticket lock: a permanent IRQs-off hard lockup, taking the
     * machine with it. The comments at tcp.c:349 and :1121 asserting
     * "arp_resolve does not block in ISR context" were true only for the RX
     * path they were written against. (audit 2026-08-01 C-2 / A4-C3.)
     *
     * Setting it here covers every source once, at the real boundary. The
     * per-driver save/restore hacks in xhci_poll and virtio_net_poll — added
     * because those are likewise reached outside netdev_poll_all — become
     * redundant but stay harmless, since they restore rather than clear.
     * Save/restore rather than clear-to-zero for the same reason: this runs
     * around calls that may set it themselves. */
    int prev = g_in_isr_poll;
    g_in_isr_poll = 1;
    for (int i = 0; i < s_count; i++)
        s_sources[i].fn();
    g_in_isr_poll = prev;
}
