/* poll_sources.c — the arm64 per-tick poll list (see the x86 twin for the
 * pattern). No polled devices yet beyond the network stack's loopback and
 * TCP timers — the PL011 and generic timer are interrupt-driven. */

#include "../../core/poll.h"
#include "ip.h"
#include "tcp.h"
#include "netdev.h"

void virtio_input_poll(void);

void
poll_sources_init(void)
{
    poll_source_register(ip_loopback_poll, POLL_PRIO_LOOPBACK,  "ip_loopback");
    /* eth0 (virtio-net) RX drain — poll-mode on arm64 (no MSI); MUST run
     * before the TCP timer so inbound segments land first. x86 drives this
     * from the PIT ISR instead. */
    poll_source_register(netdev_poll_all,  POLL_PRIO_NETDEV,    "netdev");
    poll_source_register(tcp_tick,         POLL_PRIO_TCP_TIMER, "tcp_tick");
    /* virtio-input (keyboard + mouse) — drained each tick, like x86. */
    poll_source_register(virtio_input_poll, POLL_PRIO_VIRTIO_MISC, "virtio_input");
}
