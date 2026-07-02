/* poll_sources.c — the arm64 per-tick poll list (see the x86 twin for the
 * pattern). No polled devices yet beyond the network stack's loopback and
 * TCP timers — the PL011 and generic timer are interrupt-driven. */

#include "../../core/poll.h"
#include "ip.h"
#include "tcp.h"

void
poll_sources_init(void)
{
    poll_source_register(ip_loopback_poll, POLL_PRIO_LOOPBACK,  "ip_loopback");
    poll_source_register(tcp_tick,         POLL_PRIO_TCP_TIMER, "tcp_tick");
}
