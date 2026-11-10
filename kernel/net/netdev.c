/* netdev.c — Network device registry
 *
 * Static table of up to NETDEV_MAX registered network devices.
 * netdev_rx_deliver() dispatches received frames to the Ethernet layer.
 */
#include "netdev.h"
#include "eth.h"
#include "spinlock.h"
#include <stddef.h>

static netdev_t *s_devices[NETDEV_MAX];
static int        s_count = 0;
static spinlock_t netdev_lock = SPINLOCK_INIT;

/* Atomic nesting depth across all CPUs. Non-zero in ISR/poll context, where
 * arp_resolve must not block (see core/poll.c poll_sources_run for the whole
 * tick, and net/eth.c which consults it). Formerly g_in_netdev_poll, set only
 * inside netdev_poll_all — a narrower property than its consumers needed, which
 * is how tcp_tick came to block in an ISR while holding tcp_lock. */
/* ponytail: global depth also defers task-context ARP/NDP on other CPUs;
 * use per-CPU depth if those conservative retries affect throughput. */
volatile int g_in_isr_poll = 0;

int
netdev_register(netdev_t *dev)
{
    irqflags_t fl = spin_lock_irqsave(&netdev_lock);
    if (s_count >= NETDEV_MAX || dev == NULL) {
        spin_unlock_irqrestore(&netdev_lock, fl);
        return -1;
    }
    s_devices[s_count++] = dev;
    spin_unlock_irqrestore(&netdev_lock, fl);
    return 0;
}

netdev_t *
netdev_get(const char *name)
{
    irqflags_t fl = spin_lock_irqsave(&netdev_lock);
    int i;
    for (i = 0; i < s_count; i++) {
        const char *a = s_devices[i]->name;
        const char *b = name;
        while (*a && *a == *b) { a++; b++; }
        if (*a == *b) {
            netdev_t *dev = s_devices[i];
            spin_unlock_irqrestore(&netdev_lock, fl);
            return dev;
        }
    }
    spin_unlock_irqrestore(&netdev_lock, fl);
    return NULL;
}

void
netdev_poll_all(void)
{
    irqflags_t fl = spin_lock_irqsave(&netdev_lock);
    /* Nested under the tick and sometimes entered from task context. */
    __atomic_fetch_add(&g_in_isr_poll, 1, __ATOMIC_SEQ_CST);
    int i;
    for (i = 0; i < s_count; i++) {
        if (s_devices[i]->poll)
            s_devices[i]->poll(s_devices[i]);
    }
    __atomic_fetch_sub(&g_in_isr_poll, 1, __ATOMIC_SEQ_CST);
    spin_unlock_irqrestore(&netdev_lock, fl);
}

void
netdev_rx_deliver(netdev_t *dev, const void *frame, uint16_t len)
{
    eth_rx(dev, frame, len);
}
