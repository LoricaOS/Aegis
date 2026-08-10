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

/* Non-zero while executing in PIT-ISR / poll context, where arp_resolve must
 * not block (see core/poll.c poll_sources_run, which sets it for the whole
 * tick, and net/eth.c which consults it). Formerly g_in_netdev_poll, set only
 * inside netdev_poll_all — a narrower property than its consumers needed, which
 * is how tcp_tick came to block in an ISR while holding tcp_lock. */
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
    /* Save/restore, never clear: poll_sources_run has already set this for the
     * whole tick, and clearing it on exit would leave the LATER sources (most
     * importantly tcp_tick) believing they may block. */
    int prev = g_in_isr_poll;
    g_in_isr_poll = 1;
    int i;
    for (i = 0; i < s_count; i++) {
        if (s_devices[i]->poll)
            s_devices[i]->poll(s_devices[i]);
    }
    g_in_isr_poll = prev;
    spin_unlock_irqrestore(&netdev_lock, fl);
}

void
netdev_rx_deliver(netdev_t *dev, const void *frame, uint16_t len)
{
    eth_rx(dev, frame, len);
}
