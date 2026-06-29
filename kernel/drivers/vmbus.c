/* vmbus.c — Hyper-V VMBus channel transport. See vmbus.h.
 *
 * Researched against Linux drivers/hv (connection.c, channel_mgmt.c,
 * ring_buffer.c, include/linux/hyperv.h) and iPXE interface/hyperv/vmbus.c.
 * Built blind (no Hyper-V to test on) — every step logs over serial.
 */
#include "vmbus.h"
#include "hyperv.h"
#include "kva.h"
#include "printk.h"
#include "arch.h"
#include "../lib/string.h"
#include <stdint.h>
#include <stddef.h>

#define VMBUS_MAX_CHANNELS 32u
#define VMBUS_POLL_BUDGET  200000000u
#define VMBUS_TARGET_VCPU  0u

/* ── wire structs (transcribed; sizes asserted) ───────────────────────────── */
typedef struct __attribute__((packed)) {
    uint32_t msgtype;
    uint32_t padding;
} chan_msg_hdr_t;

typedef struct __attribute__((packed)) {
    chan_msg_hdr_t header;
    uint32_t vmbus_version_requested;
    uint32_t target_vcpu;
    uint64_t interrupt_page;     /* union slot (we target < WIN10_V5) */
    uint64_t monitor_page1;
    uint64_t monitor_page2;
} initiate_contact_t;
_Static_assert(sizeof(initiate_contact_t) == 40, "initiate_contact");

typedef struct __attribute__((packed)) {
    chan_msg_hdr_t header;
    uint8_t  version_supported;
    uint8_t  connection_state;
    uint16_t padding;
    uint32_t msg_conn_id;
} version_response_t;

typedef struct __attribute__((packed)) {
    chan_msg_hdr_t header;
    vmbus_guid_t if_type;
    vmbus_guid_t if_instance;
    uint64_t reserved1;
    uint64_t reserved2;
    uint16_t chn_flags;
    uint16_t mmio_megabytes;
    uint8_t  user_def[120];
    uint16_t sub_channel_index;
    uint16_t reserved3;
    uint32_t child_relid;
    uint8_t  monitorid;
    uint8_t  monitor_alloc;
    uint16_t dedicated;
    uint32_t connection_id;
} offer_channel_t;
_Static_assert(sizeof(offer_channel_t) == 196, "offer_channel");

typedef struct __attribute__((packed)) {
    chan_msg_hdr_t header;
    uint32_t child_relid;
    uint32_t openid;
    uint32_t ringbuffer_gpadlhandle;
    uint32_t target_vp;
    uint32_t downstream_ringbuffer_pageoffset;
    uint8_t  userdata[120];
} open_channel_t;
_Static_assert(sizeof(open_channel_t) == 148, "open_channel");

typedef struct __attribute__((packed)) {
    chan_msg_hdr_t header;
    uint32_t child_relid;
    uint32_t openid;
    uint32_t status;
} open_result_t;

typedef struct __attribute__((packed)) {
    chan_msg_hdr_t header;
    uint32_t child_relid;
    uint32_t gpadl;
    uint16_t range_buflen;
    uint16_t rangecount;
    uint32_t byte_count;
    uint32_t byte_offset;
    uint64_t pfn[26];
} gpadl_header_t;

typedef struct __attribute__((packed)) {
    chan_msg_hdr_t header;
    uint32_t child_relid;
    uint32_t gpadl;
    uint32_t creation_status;
} gpadl_created_t;

/* GPA-direct ring descriptor prefix (precedes the inband payload). */
typedef struct __attribute__((packed)) {
    vmbus_pkt_hdr_t hdr;
    uint32_t reserved;
    uint32_t rangecount;
    uint32_t range_len;
    uint32_t range_offset;
    uint64_t pfn[];
} gpa_desc_t;

/* ── state ────────────────────────────────────────────────────────────────── */
static vmbus_channel_t s_chans[VMBUS_MAX_CHANNELS];
static int             s_connected;
static uint32_t        s_version;
static uint32_t        s_gpadl_counter = 0xA0000000u;
static uint32_t        s_openid_counter = 1;


/* ── ring helpers (data_len is a power of two) ────────────────────────────── */
static uint32_t
ring_put(uint8_t *data, uint32_t dlen, uint32_t off, const void *src, uint32_t n)
{
    const uint8_t *s = src;
    for (uint32_t i = 0; i < n; i++) data[(off + i) & (dlen - 1)] = s[i];
    return (off + n) & (dlen - 1);
}
static void
ring_get(uint8_t *data, uint32_t dlen, uint32_t off, void *dst, uint32_t n)
{
    uint8_t *d = dst;
    for (uint32_t i = 0; i < n; i++) d[i] = data[(off + i) & (dlen - 1)];
}

/* Write [prefix][payload][pad][footer] to the outbound ring + signal host.
 * The caller has already filled prefix's vmbus_pkt_hdr (type/offset8/len8/
 * flags/trans_id) consistently with these lengths. Returns 0 on success. */
static int
ring_send(vmbus_channel_t *ch, const void *prefix, uint32_t prefix_len,
          const void *payload, uint32_t payload_len)
{
    uint32_t total = prefix_len + payload_len;
    uint32_t pad   = (8u - (total & 7u)) & 7u;
    uint32_t need  = total + pad + 8u;            /* + 8-byte footer */

    vmbus_ring_t *h = ch->out_hdr;
    uint32_t w = h->write_index, r = h->read_index;
    uint32_t used = (w - r) & (ch->data_len - 1);
    uint32_t freeb = ch->data_len - used;
    if (need >= freeb)
        return -1;                                 /* ring full */

    uint32_t off = w;
    off = ring_put(ch->out_data, ch->data_len, off, prefix, prefix_len);
    if (payload_len)
        off = ring_put(ch->out_data, ch->data_len, off, payload, payload_len);
    if (pad) { uint8_t z[8] = {0}; off = ring_put(ch->out_data, ch->data_len, off, z, pad); }
    uint64_t footer = (uint64_t)w << 32;           /* start offset of this packet */
    off = ring_put(ch->out_data, ch->data_len, off, &footer, 8);

    arch_wmb();
    h->write_index = off;
    arch_wmb();
    hv_signal_event(ch->connection_id);
    return 0;
}

int
vmbus_send_inband(vmbus_channel_t *ch, const void *payload, uint32_t len,
                  uint64_t trans_id, int need_completion)
{
    uint32_t total = 16u + len;
    uint32_t pad   = (8u - (total & 7u)) & 7u;
    vmbus_pkt_hdr_t hdr;
    hdr.type     = VMBUS_PKT_DATA_INBAND;
    hdr.offset8  = 16u / 8u;                        /* payload right after header */
    hdr.len8     = (uint16_t)((total + pad) / 8u);
    hdr.flags    = need_completion ? VMBUS_PKT_FLAG_COMPLETION : 0u;
    hdr.trans_id = trans_id;
    return ring_send(ch, &hdr, 16, payload, len);
}

int
vmbus_send_gpa(vmbus_channel_t *ch, const void *payload, uint32_t len,
               uint64_t buf_pa, uint32_t buf_len, uint64_t trans_id)
{
    uint64_t first = buf_pa & ~0xFFFull;
    uint64_t last  = (buf_pa + buf_len - 1) & ~0xFFFull;
    uint32_t npages = (uint32_t)((last - first) / 4096u) + 1u;
    if (npages > 32u) return -1;

    uint8_t buf[16 + 16 + 32 * 8];                 /* hdr + fixed + 32 pfns */
    gpa_desc_t *g = (gpa_desc_t *)buf;
    uint32_t prefix_len = (uint32_t)sizeof(gpa_desc_t) + npages * 8u; /* 32 + npages*8 */
    uint32_t total = prefix_len + len;
    uint32_t pad   = (8u - (total & 7u)) & 7u;

    g->hdr.type     = VMBUS_PKT_DATA_GPA_DIRECT;
    g->hdr.offset8  = (uint16_t)(prefix_len / 8u);
    g->hdr.len8     = (uint16_t)((total + pad) / 8u);
    g->hdr.flags    = VMBUS_PKT_FLAG_COMPLETION;
    g->hdr.trans_id = trans_id;
    g->reserved     = 0;
    g->rangecount   = 1;
    g->range_len    = buf_len;
    g->range_offset = (uint32_t)(buf_pa & 0xFFFu);
    for (uint32_t i = 0; i < npages; i++)
        g->pfn[i] = (first >> 12) + i;

    return ring_send(ch, buf, prefix_len, payload, len);
}

int
vmbus_recv(vmbus_channel_t *ch, void *buf, uint32_t buflen,
           uint32_t *out_len, uint16_t *out_type, uint64_t *out_transid)
{
    vmbus_ring_t *h = ch->in_hdr;
    uint32_t r = h->read_index, w = h->write_index;
    if (r == w)
        return 0;

    vmbus_pkt_hdr_t hdr;
    ring_get(ch->in_data, ch->data_len, r, &hdr, 16);
    uint32_t total = (uint32_t)hdr.len8 * 8u;       /* excl. footer */
    uint32_t poff  = (uint32_t)hdr.offset8 * 8u;
    uint32_t plen  = total > poff ? total - poff : 0u;
    uint32_t copy  = plen < buflen ? plen : buflen;
    ring_get(ch->in_data, ch->data_len, (r + poff) & (ch->data_len - 1), buf, copy);

    if (out_len)     *out_len = plen;
    if (out_type)    *out_type = hdr.type;
    if (out_transid) *out_transid = hdr.trans_id;

    arch_wmb();
    h->read_index = (r + total + 8u) & (ch->data_len - 1);   /* +8 footer */
    arch_wmb();
    return 1;
}

int
vmbus_recv_wait(vmbus_channel_t *ch, void *buf, uint32_t buflen,
                uint32_t *out_len, uint16_t *out_type, uint64_t *out_transid)
{
    for (uint32_t i = 0; i < VMBUS_POLL_BUDGET; i++) {
        if (vmbus_recv(ch, buf, buflen, out_len, out_type, out_transid))
            return 1;
        arch_pause();
    }
    return 0;
}

/* ── connect-time message polling ─────────────────────────────────────────── */
static int
vmbus_wait_chan_msg(uint32_t want_msgtype, void *out, uint32_t outlen)
{
    hv_message_t msg;
    for (uint32_t i = 0; i < VMBUS_POLL_BUDGET; i++) {
        if (hv_get_vmbus_message(&msg)) {
            chan_msg_hdr_t *h = (chan_msg_hdr_t *)msg.payload;
            if (h->msgtype == want_msgtype) {
                kmemcpy(out, msg.payload, outlen);
                return 1;
            }
            /* Unexpected message at this phase — log and keep waiting. */
            printk("[VMBUS] unexpected msg %u while waiting for %u\n",
                   (unsigned)h->msgtype, (unsigned)want_msgtype);
        }
        arch_pause();
    }
    return 0;
}

static void
log_guid(const char *tag, const vmbus_guid_t *g)
{
    /* Print as the canonical mixed-endian GUID string. */
    const uint8_t *b = g->b;
    printk("[VMBUS] %s %x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x\n", tag,
           b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
           b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

/* Well-known interface-type GUIDs for the offers we name in the log. */
static const uint8_t GUID_STORVSC[16] = {
    0xd9,0x63,0x61,0xba,0xa1,0x04,0x29,0x4d,0xb6,0x05,0x72,0xe2,0xff,0xb1,0xdc,0x7f };
static const uint8_t GUID_NETVSC[16] = {
    0x63,0x51,0x61,0xf8,0x3e,0xdf,0xc5,0x46,0x91,0x3f,0xf2,0xd2,0xf9,0x65,0xed,0x0e };

static int guid_eq(const vmbus_guid_t *g, const uint8_t k[16]){
    for (int i = 0; i < 16; i++) { if (g->b[i] != k[i]) return 0; }
    return 1;
}

void
vmbus_init(void)
{
    if (!hyperv_present())
        return;

    /* Interrupt page + 2 monitor pages (host needs valid GPAs even though we
     * poll the rings and signal via HvSignalEvent). */
    uint64_t int_pa, mon1_pa, mon2_pa;
    void *intp = kva_alloc_pages_low(1);
    void *mon1 = kva_alloc_pages_low(1);
    void *mon2 = kva_alloc_pages_low(1);
    if (!intp || !mon1 || !mon2) { printk("[VMBUS] FAIL: page alloc\n"); return; }
    kmemset(intp, 0, 4096); kmemset(mon1, 0, 4096); kmemset(mon2, 0, 4096);
    int_pa  = kva_page_phys(intp);
    mon1_pa = kva_page_phys(mon1);
    mon2_pa = kva_page_phys(mon2);

    /* Negotiate a version (newest → oldest), all < WIN10_V5 (conn id 1). */
    static const uint32_t versions[] = {
        VMBUS_VERSION_WIN10, VMBUS_VERSION_WIN8_1, VMBUS_VERSION_WIN8 };
    for (uint32_t vi = 0; vi < sizeof(versions)/sizeof(versions[0]); vi++) {
        initiate_contact_t ic;
        kmemset(&ic, 0, sizeof(ic));
        ic.header.msgtype           = CHANNELMSG_INITIATE_CONTACT;
        ic.vmbus_version_requested  = versions[vi];
        ic.target_vcpu              = VMBUS_TARGET_VCPU;
        ic.interrupt_page           = int_pa;
        ic.monitor_page1            = mon1_pa;
        ic.monitor_page2            = mon2_pa;
        uint64_t st = hv_post_message(VMBUS_MSG_CONN_ID_1, &ic, sizeof(ic));
        if (st != 0) { printk("[VMBUS] post InitiateContact status=0x%lx\n", (unsigned long)st); }

        version_response_t vr;
        if (!vmbus_wait_chan_msg(CHANNELMSG_VERSION_RESPONSE, &vr, sizeof(vr))) {
            printk("[VMBUS] no VERSION_RESPONSE for 0x%x\n", (unsigned)versions[vi]);
            continue;
        }
        if (vr.version_supported) {
            s_version = versions[vi];
            s_connected = 1;
            printk("[VMBUS] connected, version 0x%x\n", (unsigned)s_version);
            break;
        }
        printk("[VMBUS] version 0x%x not supported, trying older\n", (unsigned)versions[vi]);
    }
    if (!s_connected) { printk("[VMBUS] FAIL: no supported version\n"); return; }

    /* Request the channel offers and enumerate them. */
    chan_msg_hdr_t req = { CHANNELMSG_REQUESTOFFERS, 0 };
    hv_post_message(VMBUS_MSG_CONN_ID_1, &req, sizeof(req));

    uint32_t nchan = 0;
    hv_message_t msg;
    for (uint32_t i = 0; i < VMBUS_POLL_BUDGET; i++) {
        if (!hv_get_vmbus_message(&msg)) { arch_pause(); continue; }
        chan_msg_hdr_t *h = (chan_msg_hdr_t *)msg.payload;
        if (h->msgtype == CHANNELMSG_ALLOFFERS_DELIVERED) {
            printk("[VMBUS] all offers delivered (%u channels)\n", (unsigned)nchan);
            break;
        }
        if (h->msgtype != CHANNELMSG_OFFERCHANNEL)
            continue;
        offer_channel_t *o = (offer_channel_t *)msg.payload;
        if (nchan >= VMBUS_MAX_CHANNELS) continue;
        vmbus_channel_t *ch = &s_chans[nchan++];
        ch->in_use        = 1;
        ch->child_relid   = o->child_relid;
        ch->connection_id = o->connection_id;
        ch->if_type       = o->if_type;
        ch->if_instance   = o->if_instance;
        const char *name = guid_eq(&o->if_type, GUID_STORVSC) ? "StorVSC"
                         : guid_eq(&o->if_type, GUID_NETVSC)  ? "NetVSC"
                         : "device";
        printk("[VMBUS] offer: %s relid=%u conn=%u\n",
               name, (unsigned)o->child_relid, (unsigned)o->connection_id);
        log_guid("  if_type", &o->if_type);
        i = 0;   /* reset budget while offers keep arriving */
    }
}

int
vmbus_connected(void)
{
    return s_connected;
}

vmbus_channel_t *
vmbus_find_channel(const vmbus_guid_t *if_type)
{
    for (uint32_t i = 0; i < VMBUS_MAX_CHANNELS; i++)
        if (s_chans[i].in_use && guid_eq(&s_chans[i].if_type, if_type->b))
            return &s_chans[i];
    return NULL;
}

int
vmbus_open(vmbus_channel_t *ch, uint32_t data_pages)
{
    if (!ch || ch->opened) return -1;

    uint32_t total_pages = 2u * (1u + data_pages);   /* (ctrl+data) per direction */
    uint8_t *va = (uint8_t *)kva_alloc_pages_low(total_pages);
    if (!va) { printk("[VMBUS] open: ring alloc failed\n"); return -1; }
    kmemset(va, 0, total_pages * 4096u);

    ch->ring_va     = va;
    ch->ring_pages  = total_pages;
    ch->data_pages  = data_pages;
    ch->data_len    = data_pages * 4096u;
    ch->out_hdr     = (vmbus_ring_t *)va;
    ch->out_data    = va + 4096u;
    uint32_t in_off = (1u + data_pages) * 4096u;
    ch->in_hdr      = (vmbus_ring_t *)(va + in_off);
    ch->in_data     = va + in_off + 4096u;

    /* GPADL covering the whole ring region (pfns in virtual order). */
    ch->gpadl = ++s_gpadl_counter;
    gpadl_header_t gp;
    kmemset(&gp, 0, sizeof(gp));
    gp.header.msgtype = CHANNELMSG_GPADL_HEADER;
    gp.child_relid    = ch->child_relid;
    gp.gpadl          = ch->gpadl;
    gp.rangecount     = 1;
    gp.byte_count     = total_pages * 4096u;
    gp.byte_offset    = 0;
    for (uint32_t i = 0; i < total_pages && i < 26u; i++)
        gp.pfn[i] = kva_page_phys(va + i * 4096u) >> 12;
    gp.range_buflen = (uint16_t)(8u + total_pages * 8u);
    uint32_t gp_len = 8u + 4u + 4u + 2u + 2u + 8u + total_pages * 8u;
    hv_post_message(VMBUS_MSG_CONN_ID_1, &gp, gp_len);

    gpadl_created_t gc;
    if (!vmbus_wait_chan_msg(CHANNELMSG_GPADL_CREATED, &gc, sizeof(gc))) {
        printk("[VMBUS] open: no GPADL_CREATED\n"); return -1;
    }
    if (gc.creation_status != 0) {
        printk("[VMBUS] open: GPADL_CREATED status=%u\n", (unsigned)gc.creation_status);
        return -1;
    }

    open_channel_t oc;
    kmemset(&oc, 0, sizeof(oc));
    oc.header.msgtype                      = CHANNELMSG_OPENCHANNEL;
    oc.child_relid                         = ch->child_relid;
    oc.openid                              = s_openid_counter++;
    oc.ringbuffer_gpadlhandle              = ch->gpadl;
    oc.target_vp                           = VMBUS_TARGET_VCPU;
    oc.downstream_ringbuffer_pageoffset    = 1u + data_pages;
    hv_post_message(VMBUS_MSG_CONN_ID_1, &oc, sizeof(oc));

    open_result_t orr;
    if (!vmbus_wait_chan_msg(CHANNELMSG_OPENCHANNEL_RESULT, &orr, sizeof(orr))) {
        printk("[VMBUS] open: no OPENCHANNEL_RESULT\n"); return -1;
    }
    if (orr.status != 0) {
        printk("[VMBUS] open: OPENCHANNEL_RESULT status=%u\n", (unsigned)orr.status);
        return -1;
    }
    ch->opened = 1;
    printk("[VMBUS] channel relid=%u opened (%u data pages/dir)\n",
           (unsigned)ch->child_relid, (unsigned)data_pages);
    return 0;
}

int
vmbus_recv_raw(vmbus_channel_t *ch, void *buf, uint32_t buflen,
               uint32_t *out_total, uint32_t *out_off8,
               uint16_t *out_type, uint64_t *out_transid)
{
    vmbus_ring_t *h = ch->in_hdr;
    uint32_t r = h->read_index, w = h->write_index;
    if (r == w)
        return 0;
    vmbus_pkt_hdr_t hdr;
    ring_get(ch->in_data, ch->data_len, r, &hdr, 16);
    uint32_t total = (uint32_t)hdr.len8 * 8u;       /* descriptor+body, excl footer */
    uint32_t copy  = total < buflen ? total : buflen;
    ring_get(ch->in_data, ch->data_len, r, buf, copy);   /* full packet from start */

    if (out_total)   *out_total = total;
    if (out_off8)    *out_off8 = (uint32_t)hdr.offset8 * 8u;
    if (out_type)    *out_type = hdr.type;
    if (out_transid) *out_transid = hdr.trans_id;

    arch_wmb();
    h->read_index = (r + total + 8u) & (ch->data_len - 1);   /* +8 footer */
    arch_wmb();
    return 1;
}

int
vmbus_send_completion(vmbus_channel_t *ch, const void *payload, uint32_t len,
                      uint64_t trans_id)
{
    uint32_t total = 16u + len;
    uint32_t pad   = (8u - (total & 7u)) & 7u;
    vmbus_pkt_hdr_t hdr;
    hdr.type     = VMBUS_PKT_COMPLETION;
    hdr.offset8  = 16u / 8u;
    hdr.len8     = (uint16_t)((total + pad) / 8u);
    hdr.flags    = 0;
    hdr.trans_id = trans_id;
    return ring_send(ch, &hdr, 16, payload, len);
}

int
vmbus_create_gpadl(vmbus_channel_t *ch, void *va, uint32_t num_pages,
                   uint32_t *out_handle)
{
    if (num_pages > 26u)
        return -1;                                   /* single-message GPADL only */
    uint32_t gpadl = ++s_gpadl_counter;
    gpadl_header_t gp;
    kmemset(&gp, 0, sizeof(gp));
    gp.header.msgtype = CHANNELMSG_GPADL_HEADER;
    gp.child_relid    = ch->child_relid;
    gp.gpadl          = gpadl;
    gp.rangecount     = 1;
    gp.byte_count     = num_pages * 4096u;
    gp.byte_offset    = 0;
    for (uint32_t i = 0; i < num_pages; i++)
        gp.pfn[i] = kva_page_phys((uint8_t *)va + i * 4096u) >> 12;
    gp.range_buflen = (uint16_t)(8u + num_pages * 8u);
    uint32_t gp_len = 8u + 4u + 4u + 2u + 2u + 8u + num_pages * 8u;
    hv_post_message(VMBUS_MSG_CONN_ID_1, &gp, gp_len);

    gpadl_created_t gc;
    if (!vmbus_wait_chan_msg(CHANNELMSG_GPADL_CREATED, &gc, sizeof(gc)))
        return -1;
    if (gc.creation_status != 0)
        return -1;
    *out_handle = gpadl;
    return 0;
}
