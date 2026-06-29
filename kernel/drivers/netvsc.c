/* netvsc.c — Hyper-V synthetic NIC (NetVSC) over VMBus → netdev "eth0".
 *
 * Two protocol layers on the VMBus channel:
 *   NVSP  — set up the channel + a shared receive buffer (GPADL).
 *   RNDIS — the actual NIC control (init, query MAC, set packet filter) and
 *           data (Ethernet frames wrapped in RNDIS_MSG_PACKET).
 *
 * Frames are sent via GPA-direct (the frame buffer's pages handed to the host).
 * Frames are received via transfer-pages packets (the host writes into our
 * GPADL'd receive buffer and tells us which sub-ranges hold packets).
 *
 * Researched against Linux drivers/net/hyperv + include/linux/rndis.h. Built
 * blind; logs each handshake step. Reuses the VMBus ring/GPADL plumbing already
 * proven on real Hyper-V by StorVSC.
 */
#include "vmbus.h"
#include "netdev.h"
#include "kva.h"
#include "printk.h"
#include "arch.h"
#include "spinlock.h"
#include "../lib/string.h"
#include <stdint.h>
#include <stddef.h>

/* ── NVSP ─────────────────────────────────────────────────────────────────── */
#define NVSP_MSG_TYPE_INIT                  1u
#define NVSP_MSG_TYPE_INIT_COMPLETE         2u
#define NVSP_MSG1_TYPE_SEND_NDIS_VER        100u
#define NVSP_MSG1_TYPE_SEND_RECV_BUF        101u
#define NVSP_MSG1_TYPE_SEND_RECV_BUF_COMPL  102u
#define NVSP_MSG1_TYPE_SEND_RNDIS_PKT       107u
#define NVSP_MSG1_TYPE_SEND_RNDIS_PKT_COMPL 108u
#define NVSP_STAT_SUCCESS                   1u
#define NVSP_VERSION_1                      2u
#define NETVSC_RECV_BUFFER_ID               0xcafeu
#define NVSP_RNDIS_DATA                     0u
#define NVSP_RNDIS_CONTROL                  1u

/* ── RNDIS ────────────────────────────────────────────────────────────────── */
#define RNDIS_MSG_PACKET   0x00000001u
#define RNDIS_MSG_INIT     0x00000002u
#define RNDIS_MSG_INIT_C   0x80000002u
#define RNDIS_MSG_QUERY    0x00000004u
#define RNDIS_MSG_QUERY_C  0x80000004u
#define RNDIS_MSG_SET      0x00000005u
#define RNDIS_MSG_SET_C    0x80000005u
#define RNDIS_STATUS_SUCCESS 0x00000000u
#define OID_GEN_CURRENT_PACKET_FILTER 0x0001010Eu
#define OID_802_3_PERMANENT_ADDRESS   0x01010101u
#define RNDIS_FILTER (0x01u | 0x08u | 0x04u)   /* DIRECTED | BROADCAST | ALL_MULTICAST */

#define RECV_BUF_PAGES  16u        /* 64 KiB shared receive buffer */
#define NET_DATA_PAGES  8u         /* 32 KiB rings */
#define POLL_BUDGET     200000000u

typedef struct __attribute__((packed)) {
    uint32_t msg_type;
    union {
        struct __attribute__((packed)) { uint32_t min_ver, max_ver; } init;
        struct __attribute__((packed)) { uint32_t neg_ver, max_mdl, status; } init_c;
        struct __attribute__((packed)) { uint32_t major, minor; } ndis_ver;
        struct __attribute__((packed)) { uint32_t gpadl; uint16_t id; } recv_buf;
        struct __attribute__((packed)) { uint32_t status, num_sections; } recv_buf_c;
        struct __attribute__((packed)) { uint32_t channel_type, sbi, sbs; } rndis;
        struct __attribute__((packed)) { uint32_t status; } rndis_c;
        uint8_t raw[40];
    } u;
} nvsp_t;

typedef struct __attribute__((packed)) { uint32_t type, len; } rndis_hdr_t;
typedef struct __attribute__((packed)) {
    uint32_t data_offset, data_len, oob_off, oob_len, num_oob,
             ppi_off, ppi_len, vc, reserved;
} rndis_packet_t;
_Static_assert(sizeof(rndis_packet_t) == 36, "rndis_packet");

/* transfer-pages descriptor (after the 16-byte vmbus_pkt_hdr). */
typedef struct __attribute__((packed)) {
    uint16_t xfer_pageset_id;
    uint8_t  sender_owns_set;
    uint8_t  reserved;
    uint32_t range_cnt;
    struct __attribute__((packed)) { uint32_t byte_count, byte_offset; } ranges[];
} xfer_hdr_t;

static vmbus_channel_t *s_ch;
static uint8_t  *s_recv_buf;        /* GPADL'd host->guest buffer */
static uint8_t  *s_tx_buf;          /* RNDIS message staging (GPA-direct out) */
static uint64_t  s_tx_pa;
static uint32_t  s_recv_gpadl;
static uint64_t  s_trans = 1;
static uint32_t  s_rndis_req = 1;
static spinlock_t s_tx_lock;
static netdev_t  s_nd;
static int       s_up;

/* control-response capture (set by the RX path during a control request) */
static volatile uint32_t s_wait_req;
static volatile int      s_got_ctrl;
static uint8_t           s_ctrl_buf[256];
static uint32_t          s_ctrl_len;
static volatile uint32_t s_poll_n, s_rx_n, s_tx_n;   /* DIAG counters */


/* ── NVSP control: send inband, wait for the completion carrying the reply ─── */
static int
nvsp_send_wait(nvsp_t *msg, uint32_t len, int want_reply, nvsp_t *reply)
{
    (void)len;   /* NVSP messages are sent at the full fixed struct size */
    if (vmbus_send_inband(s_ch, msg, sizeof(*msg), s_trans++, want_reply ? 1 : 0) < 0)
        return -1;
    if (!want_reply)
        return 0;
    uint8_t buf[256];
    for (uint32_t i = 0; i < POLL_BUDGET; i++) {
        uint32_t total, off8; uint16_t type; uint64_t tid;
        if (vmbus_recv_raw(s_ch, buf, sizeof(buf), &total, &off8, &type, &tid)) {
            uint32_t plen = total > off8 ? total - off8 : 0;
            kmemset(reply, 0, sizeof(*reply));
            kmemcpy(reply, buf + off8, plen < sizeof(*reply) ? plen : sizeof(*reply));
            return 0;
        }
        arch_pause();
    }
    return -1;
}

/* Deliver/capture one received RNDIS message sitting at recv_buf+offset. */
static void
netvsc_consume_rndis(uint32_t offset, uint32_t length)
{
    if (length < sizeof(rndis_hdr_t)) return;
    rndis_hdr_t *rh = (rndis_hdr_t *)(s_recv_buf + offset);
    if (rh->type == RNDIS_MSG_PACKET) {
        rndis_packet_t *rp = (rndis_packet_t *)(s_recv_buf + offset + sizeof(rndis_hdr_t));
        uint32_t fo = offset + sizeof(rndis_hdr_t) + rp->data_offset;
        if (rp->data_len > 0 && rp->data_len <= 2048u)
            netdev_rx_deliver(&s_nd, s_recv_buf + fo, (uint16_t)rp->data_len);
    } else {
        /* control completion (INIT_C / QUERY_C / SET_C): req_id is first body word */
        uint32_t req = *(uint32_t *)(s_recv_buf + offset + sizeof(rndis_hdr_t));
        if (req == s_wait_req) {
            uint32_t c = length < sizeof(s_ctrl_buf) ? length : sizeof(s_ctrl_buf);
            kmemcpy(s_ctrl_buf, s_recv_buf + offset, c);
            s_ctrl_len = c;
            s_got_ctrl = 1;
        }
    }
}

/* Process one inbound packet. Returns 1 if a packet was handled, 0 if empty. */
static int
netvsc_poll_one(void)
{
    uint8_t buf[256];
    uint32_t total, off8; uint16_t type; uint64_t tid;
    if (!vmbus_recv_raw(s_ch, buf, sizeof(buf), &total, &off8, &type, &tid))
        return 0;
    s_rx_n++;
    if (type == VMBUS_PKT_DATA_XFER_PAGES) {
        xfer_hdr_t *x = (xfer_hdr_t *)(buf + 16);
        uint32_t rc = x->range_cnt;
        if (rc > 16u) rc = 16u;
        for (uint32_t i = 0; i < rc; i++)
            netvsc_consume_rndis(x->ranges[i].byte_offset, x->ranges[i].byte_count);
        /* ack so the host can reuse the receive sections */
        nvsp_t c; kmemset(&c, 0, sizeof(c));
        c.msg_type = NVSP_MSG1_TYPE_SEND_RNDIS_PKT_COMPL;
        c.u.rndis_c.status = NVSP_STAT_SUCCESS;
        irqflags_t fl = spin_lock_irqsave(&s_tx_lock);
        vmbus_send_completion(s_ch, &c, 8, tid);
        spin_unlock_irqrestore(&s_tx_lock, fl);
    }
    /* VMBUS_PKT_COMPLETION (our TX acks) and others: ignore */
    return 1;
}

/* Send an RNDIS control message and wait for its matching *_C response. */
static int
rndis_control(void *rmsg, uint32_t rlen, uint32_t req_id, void *resp, uint32_t resp_max)
{
    irqflags_t fl = spin_lock_irqsave(&s_tx_lock);
    kmemcpy(s_tx_buf, rmsg, rlen);
    nvsp_t nv; kmemset(&nv, 0, sizeof(nv));
    nv.msg_type = NVSP_MSG1_TYPE_SEND_RNDIS_PKT;
    nv.u.rndis.channel_type = NVSP_RNDIS_CONTROL;
    nv.u.rndis.sbi = 0xFFFFFFFFu;
    nv.u.rndis.sbs = rlen;
    s_wait_req = req_id;
    s_got_ctrl = 0;
    vmbus_send_gpa(s_ch, &nv, sizeof(nv), s_tx_pa, rlen, s_trans++);
    spin_unlock_irqrestore(&s_tx_lock, fl);

    for (uint32_t i = 0; i < POLL_BUDGET; i++) {
        netvsc_poll_one();
        if (s_got_ctrl) {
            uint32_t c = s_ctrl_len < resp_max ? s_ctrl_len : resp_max;
            kmemcpy(resp, s_ctrl_buf, c);
            return 0;
        }
        arch_pause();
    }
    return -1;
}

static int
netvsc_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    (void)dev;
    if (!s_up || len > 1514u) return -1;
    irqflags_t fl = spin_lock_irqsave(&s_tx_lock);
    rndis_hdr_t *rh = (rndis_hdr_t *)s_tx_buf;
    rndis_packet_t *rp = (rndis_packet_t *)(s_tx_buf + sizeof(rndis_hdr_t));
    kmemset(rp, 0, sizeof(*rp));
    rp->data_offset = sizeof(rndis_packet_t);          /* frame right after rndis_packet */
    rp->data_len    = len;
    kmemcpy(s_tx_buf + sizeof(rndis_hdr_t) + sizeof(rndis_packet_t), pkt, len);
    uint32_t rlen = sizeof(rndis_hdr_t) + sizeof(rndis_packet_t) + len;
    rh->type = RNDIS_MSG_PACKET;
    rh->len  = rlen;

    nvsp_t nv; kmemset(&nv, 0, sizeof(nv));
    nv.msg_type = NVSP_MSG1_TYPE_SEND_RNDIS_PKT;
    nv.u.rndis.channel_type = NVSP_RNDIS_DATA;
    nv.u.rndis.sbi = 0xFFFFFFFFu;
    nv.u.rndis.sbs = rlen;
    int rc = vmbus_send_gpa(s_ch, &nv, sizeof(nv), s_tx_pa, rlen, s_trans++);
    s_tx_n++;
    spin_unlock_irqrestore(&s_tx_lock, fl);
    return rc;
}

static void
netvsc_poll(netdev_t *dev)
{
    (void)dev;
    if (!s_up) return;
    for (int i = 0; i < 32 && netvsc_poll_one(); i++)
        ;
    if ((++s_poll_n % 300u) == 0u)
        printk("[NETVSC] diag poll=%u rx=%u tx=%u in_w=%u\n",
               (unsigned)s_poll_n, (unsigned)s_rx_n, (unsigned)s_tx_n,
               (unsigned)s_ch->in_hdr->write_index);
}

/* NetVSC interface type GUID {f8615163-df3e-46c5-913f-f2d2f965ed0e}. */
static const vmbus_guid_t GUID_NETVSC = {{
    0x63,0x51,0x61,0xf8,0x3e,0xdf,0xc5,0x46,0x91,0x3f,0xf2,0xd2,0xf9,0x65,0xed,0x0e }};

void
netvsc_init(void)
{
    if (!vmbus_connected())
        return;
    s_ch = vmbus_find_channel(&GUID_NETVSC);
    if (!s_ch) { printk("[NETVSC] no NetVSC channel offered\n"); return; }
    if (vmbus_open(s_ch, NET_DATA_PAGES) != 0) {
        printk("[NETVSC] channel open failed\n"); return; }
    s_tx_lock = (spinlock_t)SPINLOCK_INIT;

    /* NVSP INIT (force v1). */
    nvsp_t msg, rep;
    kmemset(&msg, 0, sizeof(msg));
    msg.msg_type = NVSP_MSG_TYPE_INIT;
    msg.u.init.min_ver = NVSP_VERSION_1;
    msg.u.init.max_ver = 0x00050000u;          /* allow up to NVSP v5; host picks */
    if (nvsp_send_wait(&msg, 12, 1, &rep) != 0 || rep.u.init_c.status != NVSP_STAT_SUCCESS) {
        printk("[NETVSC] NVSP INIT failed (status=%u)\n", (unsigned)rep.u.init_c.status); return; }
    printk("[NETVSC] NVSP v0x%x\n", (unsigned)rep.u.init_c.neg_ver);

    /* SEND_NDIS_VER (6.1), no reply. */
    kmemset(&msg, 0, sizeof(msg));
    msg.msg_type = NVSP_MSG1_TYPE_SEND_NDIS_VER;
    msg.u.ndis_ver.major = 6; msg.u.ndis_ver.minor = 1;
    nvsp_send_wait(&msg, 12, 0, &rep);

    /* Receive buffer: allocate + GPADL + SEND_RECV_BUF. */
    s_recv_buf = (uint8_t *)kva_alloc_pages_low(RECV_BUF_PAGES);
    s_tx_buf   = (uint8_t *)kva_alloc_pages_low(1);
    if (!s_recv_buf || !s_tx_buf) { printk("[NETVSC] buffer alloc failed\n"); return; }
    kmemset(s_recv_buf, 0, RECV_BUF_PAGES * 4096u);
    s_tx_pa = kva_page_phys(s_tx_buf);
    if (vmbus_create_gpadl(s_ch, s_recv_buf, RECV_BUF_PAGES, &s_recv_gpadl) != 0) {
        printk("[NETVSC] recv buffer GPADL failed\n"); return; }

    kmemset(&msg, 0, sizeof(msg));
    msg.msg_type = NVSP_MSG1_TYPE_SEND_RECV_BUF;
    msg.u.recv_buf.gpadl = s_recv_gpadl;
    msg.u.recv_buf.id = NETVSC_RECV_BUFFER_ID;
    if (nvsp_send_wait(&msg, 10, 1, &rep) != 0 || rep.u.recv_buf_c.status != NVSP_STAT_SUCCESS) {
        printk("[NETVSC] SEND_RECV_BUF failed (status=%u)\n", (unsigned)rep.u.recv_buf_c.status); return; }
    printk("[NETVSC] recv buffer ready (%u sections)\n", (unsigned)rep.u.recv_buf_c.num_sections);

    /* RNDIS INITIALIZE. */
    {
        uint8_t r[64]; kmemset(r, 0, sizeof(r));
        rndis_hdr_t *h = (rndis_hdr_t *)r;
        uint32_t *b = (uint32_t *)(r + sizeof(rndis_hdr_t));   /* req_id, major, minor, max_xfer */
        uint32_t req = s_rndis_req++;
        b[0] = req; b[1] = 1; b[2] = 0; b[3] = 0x4000;
        h->type = RNDIS_MSG_INIT; h->len = sizeof(rndis_hdr_t) + 16u;
        uint8_t resp[64];
        if (rndis_control(r, h->len, req, resp, sizeof(resp)) != 0) {
            printk("[NETVSC] RNDIS INIT no response\n"); return; }
        printk("[NETVSC] RNDIS init ok\n");
    }

    /* RNDIS QUERY OID_802_3_PERMANENT_ADDRESS → MAC. */
    {
        uint8_t r[64]; kmemset(r, 0, sizeof(r));
        rndis_hdr_t *h = (rndis_hdr_t *)r;
        uint32_t *b = (uint32_t *)(r + sizeof(rndis_hdr_t));  /* req_id, oid, infolen, infooff, devvc */
        uint32_t req = s_rndis_req++;
        b[0] = req; b[1] = OID_802_3_PERMANENT_ADDRESS; b[2] = 0; b[3] = 20; b[4] = 0;
        h->type = RNDIS_MSG_QUERY; h->len = sizeof(rndis_hdr_t) + 20u;
        uint8_t resp[128];
        if (rndis_control(r, h->len, req, resp, sizeof(resp)) != 0) {
            printk("[NETVSC] RNDIS QUERY MAC no response\n"); return; }
        /* query_complete: req_id,status,info_buflen,info_buf_offset; MAC at hdr+8+off */
        uint32_t *qc = (uint32_t *)(resp + sizeof(rndis_hdr_t));
        uint32_t infolen = qc[2], infooff = qc[3];
        if (infolen >= 6) {
            uint8_t *mac = resp + sizeof(rndis_hdr_t) + infooff;
            for (int i = 0; i < 6; i++) s_nd.mac[i] = mac[i];
        }
    }

    /* RNDIS SET OID_GEN_CURRENT_PACKET_FILTER. */
    {
        uint8_t r[64]; kmemset(r, 0, sizeof(r));
        rndis_hdr_t *h = (rndis_hdr_t *)r;
        uint32_t *b = (uint32_t *)(r + sizeof(rndis_hdr_t));  /* req_id, oid, infolen, infooff, devvc */
        uint32_t req = s_rndis_req++;
        b[0] = req; b[1] = OID_GEN_CURRENT_PACKET_FILTER; b[2] = 4; b[3] = 20; b[4] = 0;
        *(uint32_t *)(r + sizeof(rndis_hdr_t) + 20) = RNDIS_FILTER;
        h->type = RNDIS_MSG_SET; h->len = sizeof(rndis_hdr_t) + 24u;
        uint8_t resp[64];
        if (rndis_control(r, h->len, req, resp, sizeof(resp)) != 0) {
            printk("[NETVSC] RNDIS SET filter no response\n"); return; }
    }

    s_nd.name[0]='e'; s_nd.name[1]='t'; s_nd.name[2]='h'; s_nd.name[3]='0'; s_nd.name[4]='\0';
    s_nd.send = netvsc_send;
    s_nd.poll = netvsc_poll;
    netdev_register(&s_nd);
    s_up = 1;
    printk("[NETVSC] OK: eth0 mac=%x:%x:%x:%x:%x:%x\n",
           s_nd.mac[0], s_nd.mac[1], s_nd.mac[2], s_nd.mac[3], s_nd.mac[4], s_nd.mac[5]);
}
