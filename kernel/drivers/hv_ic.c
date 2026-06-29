/* hv_ic.c — Hyper-V Integration Component shared framing. See hv_ic.h.
 *
 * Transcribed from Linux include/linux/hyperv.h + drivers/hv/hv_util.c.  Reuses
 * the VMBus inband ring proven by StorVSC/NetVSC.
 */
#include "hv_ic.h"
#include "printk.h"
#include "arch.h"
#include <stdint.h>
#include <stddef.h>

typedef struct __attribute__((packed)) { uint32_t flags; uint32_t msgsize; } vmbuspipe_hdr_t;
typedef struct __attribute__((packed)) { uint16_t major; uint16_t minor; } ic_version_t;
typedef struct __attribute__((packed)) {
    ic_version_t icverframe;
    uint16_t     icmsgtype;
    ic_version_t icvermsg;
    uint16_t     icmsgsize;
    uint32_t     status;
    uint8_t      ictransaction_id;
    uint8_t      icflags;
    uint8_t      reserved[2];
} icmsg_hdr_t;
_Static_assert(sizeof(icmsg_hdr_t) == 20, "icmsg_hdr");
_Static_assert(sizeof(vmbuspipe_hdr_t) == 8, "vmbuspipe_hdr");

typedef struct __attribute__((packed)) {
    uint16_t icframe_vercnt;
    uint16_t icmsg_vercnt;
    uint32_t reserved;
    ic_version_t versions[];      /* icframe_vercnt framework + icmsg_vercnt message */
} icmsg_negotiate_t;

#define ICMSGHDRFLAG_TRANSACTION   1u
#define ICMSGHDRFLAG_REQUEST       2u
#define ICMSGHDRFLAG_RESPONSE      4u

#define IC_PIPE_OFF  (sizeof(vmbuspipe_hdr_t))                 /* icmsg_hdr here  */
#define IC_BODY_OFF  (IC_PIPE_OFF + sizeof(icmsg_hdr_t))       /* IC body here    */

/* Highest version in offered[0..cnt) that is <= {3,0} (we parse the v1/v3
 * layouts, never the v4 ref-data layouts).  Defaults to {1,0}. */
static ic_version_t
pick_version(const ic_version_t *offered, uint32_t cnt)
{
    ic_version_t best = { 1, 0 };
    int found = 0;
    for (uint32_t i = 0; i < cnt && i < 16u; i++) {
        uint16_t maj = offered[i].major, min = offered[i].minor;
        if (maj > 3u)
            continue;
        if (!found || maj > best.major || (maj == best.major && min > best.minor)) {
            best = offered[i];
            found = 1;
        }
    }
    return best;
}

/* Fill a NEGOTIATE response in place: select one framework + one message
 * version both sides support. */
static void
hv_ic_negotiate(uint8_t *buf, uint32_t len)
{
    if (len < IC_BODY_OFF + sizeof(icmsg_negotiate_t))
        return;
    icmsg_negotiate_t *neg = (icmsg_negotiate_t *)(buf + IC_BODY_OFF);
    uint32_t fw_cnt  = neg->icframe_vercnt;
    uint32_t msg_cnt = neg->icmsg_vercnt;
    uint32_t avail   = (len - IC_BODY_OFF - 8u) / sizeof(ic_version_t);
    if (fw_cnt + msg_cnt > avail) { fw_cnt = 0; msg_cnt = 0; }
    ic_version_t fw  = pick_version(neg->versions, fw_cnt);
    ic_version_t msg = pick_version(neg->versions + fw_cnt, msg_cnt);
    neg->icframe_vercnt = 1;
    neg->icmsg_vercnt   = 1;
    neg->versions[0] = fw;
    neg->versions[1] = msg;
}

void
hv_ic_poll(vmbus_channel_t *ch, hv_ic_body_fn body)
{
    static uint8_t buf[256];   /* timer-thread only; small ICs fit */
    hv_ic_poll_buf(ch, body, buf, sizeof(buf));
}

/* Same as hv_ic_poll but with a caller-supplied buffer — KVP messages are
 * ~2.6 KB and do not fit the small shared buffer. */
void
hv_ic_poll_buf(vmbus_channel_t *ch, hv_ic_body_fn body, uint8_t *buf, uint32_t buflen)
{
    uint32_t len; uint16_t type; uint64_t tid;
    for (int n = 0; n < 8 && vmbus_recv(ch, buf, buflen, &len, &type, &tid); n++) {
        if (type != VMBUS_PKT_DATA_INBAND || len < IC_BODY_OFF)
            continue;
        icmsg_hdr_t *ic = (icmsg_hdr_t *)(buf + IC_PIPE_OFF);
        int status = 0;
        if (ic->icmsgtype == ICMSGTYPE_NEGOTIATE)
            hv_ic_negotiate(buf, len);
        else if (body)
            status = body(ic->icmsgtype, buf + IC_BODY_OFF, len - IC_BODY_OFF);
        ic->status  = (uint32_t)status;
        ic->icflags = ICMSGHDRFLAG_TRANSACTION | ICMSGHDRFLAG_RESPONSE;
        vmbus_send_inband(ch, buf, len, tid, 0);
    }
}
