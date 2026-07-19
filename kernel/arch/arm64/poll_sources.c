/* poll_sources.c — the arm64 per-tick poll list (see the x86 twin for the
 * pattern). No polled devices yet beyond the network stack's loopback and
 * TCP timers — the PL011 and generic timer are interrupt-driven. */

#include "../../core/poll.h"
#include "ip.h"
#include "tcp.h"
#include "netdev.h"

void virtio_input_poll(void);
void xhci_poll(void);

void
poll_sources_init(void)
{
    poll_source_register(ip_loopback_poll, POLL_PRIO_LOOPBACK,  "ip_loopback");
    /* xHCI HID event-ring drain — the real-hardware (RP1 dwc3) USB keyboard/
     * mouse path. Without this, devices enumerate (init busy-polls the ring)
     * but their interrupt-IN reports are never consumed, so no keystrokes or
     * pointer motion ever reach userland. x86 registers the same source in its
     * poll_sources.c; it was missing here, which is why USB HID input was dead
     * on native Pi 5 while the PL011 serial console (kbd_poll) still worked.
     * xhci_poll() no-ops when !s_xhci_active, so it's safe on virtio-only QEMU. */
    poll_source_register(xhci_poll,        POLL_PRIO_USB,       "xhci");
    /* eth0 (virtio-net) RX drain — poll-mode on arm64 (no MSI); MUST run
     * before the TCP timer so inbound segments land first. x86 drives this
     * from the PIT ISR instead. */
    poll_source_register(netdev_poll_all,  POLL_PRIO_NETDEV,    "netdev");
    poll_source_register(tcp_tick,         POLL_PRIO_TCP_TIMER, "tcp_tick");
    /* virtio-input (keyboard + mouse) — drained each tick, like x86. */
    poll_source_register(virtio_input_poll, POLL_PRIO_VIRTIO_MISC, "virtio_input");
}
