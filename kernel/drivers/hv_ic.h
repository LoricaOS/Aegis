/* hv_ic.h — Hyper-V Integration Component (IC) shared framing.
 *
 * Time Sync, Heartbeat, Shutdown, KVP and VSS all speak the same wire protocol
 * over their VMBus channels: each message is
 *   [ vmbuspipe_hdr (8) ][ icmsg_hdr (20) ][ body ]
 * The host opens with a NEGOTIATE (version handshake), and every message must be
 * echoed back with the RESPONSE flag and a status.  This file factors that out:
 * a driver opens its channel, then calls hv_ic_poll() each tick with a callback
 * that handles its own message body.
 */
#ifndef HV_IC_H
#define HV_IC_H

#include "vmbus.h"
#include <stdint.h>

/* IC message types (icmsg_hdr.icmsgtype). */
#define ICMSGTYPE_NEGOTIATE   0u
#define ICMSGTYPE_HEARTBEAT   1u
#define ICMSGTYPE_KVPEXCHANGE 2u
#define ICMSGTYPE_SHUTDOWN    3u
#define ICMSGTYPE_TIMESYNC    4u
#define ICMSGTYPE_VSS         5u

/* Handler for a non-NEGOTIATE IC message.  `body`/`bodylen` is the payload after
 * the icmsg_hdr; the handler may modify it in place (the whole message is echoed
 * back to the host).  Returns the IC status to report (0 = HV_S_OK). */
typedef int (*hv_ic_body_fn)(uint16_t msgtype, uint8_t *body, uint32_t bodylen);

/* Poll an IC channel: service the version NEGOTIATE, dispatch other messages to
 * `body`, and echo each one back with TRANSACTION|RESPONSE.  Safe to call every
 * tick; drains up to a few messages per call. */
void hv_ic_poll(vmbus_channel_t *ch, hv_ic_body_fn body);

/* Same, with a caller-supplied scratch buffer (for ICs whose messages exceed
 * the small default — e.g. KVP at ~2.6 KB). */
void hv_ic_poll_buf(vmbus_channel_t *ch, hv_ic_body_fn body, uint8_t *buf, uint32_t buflen);

#endif /* HV_IC_H */
