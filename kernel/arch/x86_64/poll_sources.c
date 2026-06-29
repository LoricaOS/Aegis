/* poll_sources.c — the x86-64 per-tick device poll list.
 *
 * This is the one file that knows WHICH devices Aegis polls every timer tick
 * and in WHAT ORDER.  It exists so the timer path (pit.c / lapic.c) does not
 * have to include a dozen driver headers just to drive polling — that coupling
 * lives here, where the device list belongs.  pit.c calls poll_sources_run();
 * kernel_main calls poll_sources_init() once, before interrupts are enabled.
 *
 * Each poller is a no-op when its device is absent, so registering them all
 * unconditionally is behaviourally identical to the old hardcoded sequence in
 * timer_bsp_tick — but the ordering is now explicit via priorities (see
 * poll.h), and a driver may later move its registration into its own init.
 *
 * To add a poller: register it here with the appropriate priority.  To enforce
 * a new ordering constraint, add a priority to poll.h.  Do NOT reach back into
 * the timer ISR. */

#include "../../core/poll.h"
#include "xhci.h"
#include "hv_kbd.h"
#include "hv_timesync.h"
#include "hv_mouse.h"
#include "hv_heartbeat.h"
#include "hv_shutdown.h"
#include "hv_kvp.h"
#include "netdev.h"
#include "hda.h"
#include "virtio.h"
#include "ip.h"
#include "tcp.h"

void
poll_sources_init(void)
{
    poll_source_register(xhci_poll,           POLL_PRIO_USB,         "xhci");
    poll_source_register(hv_kbd_poll,         POLL_PRIO_HV_IC,       "hv_kbd");
    poll_source_register(hv_timesync_poll,    POLL_PRIO_HV_IC,       "hv_timesync");
    poll_source_register(hv_mouse_poll,       POLL_PRIO_HV_IC,       "hv_mouse");
    poll_source_register(hv_heartbeat_poll,   POLL_PRIO_HV_IC,       "hv_heartbeat");
    poll_source_register(hv_shutdown_poll,    POLL_PRIO_HV_IC,       "hv_shutdown");
    poll_source_register(hv_kvp_poll,         POLL_PRIO_HV_IC,       "hv_kvp");
    poll_source_register(netdev_poll_all,     POLL_PRIO_NETDEV,      "netdev");
    poll_source_register(hda_poll,            POLL_PRIO_AUDIO,       "hda");
    poll_source_register(virtio_balloon_poll, POLL_PRIO_VIRTIO_MISC, "virtio_balloon");
    poll_source_register(virtio_input_poll,   POLL_PRIO_VIRTIO_MISC, "virtio_input");
    poll_source_register(ip_loopback_poll,    POLL_PRIO_LOOPBACK,    "ip_loopback");
    poll_source_register(tcp_tick,            POLL_PRIO_TCP_TIMER,   "tcp_tick");
}
