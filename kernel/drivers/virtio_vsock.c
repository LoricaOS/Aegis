/* virtio_vsock.c — virtio-vsock host↔guest socket transport, on the shared core.
 *
 * vsock is the agentless host↔guest channel (AF_VSOCK) used by cloud/Proxmox
 * guest agents: no IP, no NIC, no firewall — just a CID:port pair. This driver
 * brings up the device (rx/tx/event queues), reads the host-assigned guest CID
 * from device config, and performs a one-shot guest→host stream exchange at
 * boot to prove the transport end to end:
 *
 *   guest --REQUEST--> host(CID 2):port   (connect)
 *   host  --RESPONSE-> guest                (accept)
 *   guest --RW------->  host                 ("hello from aegis\n")
 *   guest --SHUTDOWN-> host
 *
 * Verify (must run where /dev/vhost-vsock exists — the hypervisor host, not an
 * LXC build container): start a Python AF_VSOCK listener on port 9999, boot the
 * guest with `-device vhost-vsock-pci,guest-cid=<N>`; the listener prints the
 * payload and the guest logs `[VSOCK] OK: cid=<N> sent N bytes to host`.
 *
 * Header/op layout per VIRTIO v1.1 §5.10 / linux uapi virtio_vsock.h.
 */
#include "virtio.h"
#include "arch.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

#define VIRTIO_VSOCK_MODERN  0x1053u    /* 0x1040 + device type 19 */

#define VSOCK_RXQ  0u
#define VSOCK_TXQ  1u
#define VSOCK_EVTQ 2u

#define VMADDR_CID_HOST 2ull

#define VSOCK_TYPE_STREAM 1u
#define VSOCK_OP_REQUEST  1u
#define VSOCK_OP_RESPONSE 2u
#define VSOCK_OP_RST      3u
#define VSOCK_OP_SHUTDOWN 4u
#define VSOCK_OP_RW       5u

#define VSOCK_GUEST_PORT 1234u
#define VSOCK_HOST_PORT  9999u
#define VSOCK_BUF_ALLOC  262144u        /* advertised receive credit */

#define VSOCK_RX_BUFS    8u
#define VSOCK_POLL_BUDGET 200000000u

typedef struct __attribute__((packed)) {
    uint64_t src_cid;
    uint64_t dst_cid;
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t len;
    uint16_t type;
    uint16_t op;
    uint32_t flags;
    uint32_t buf_alloc;
    uint32_t fwd_cnt;
} vsock_hdr_t;
_Static_assert(sizeof(vsock_hdr_t) == 44, "vsock_hdr must be 44 bytes");

static virtio_dev_t s_dev;
static virtq_t      s_rxq, s_txq, s_evtq;
static uint64_t     s_cid;

/* RX buffers, indexed by descriptor id. */
static uintptr_t s_rx_va[VIRTQ_SIZE];
static uint64_t  s_rx_pa[VIRTQ_SIZE];

/* One TX scratch page (hdr + small payload). */
static uintptr_t s_tx_va;
static uint64_t  s_tx_pa;

static void
_memset(void *d, int v, uint32_t n)
{
    uint8_t *p = d;
    while (n--) *p++ = (uint8_t)v;
}
static void
_memcpy(void *d, const void *s, uint32_t n)
{
    uint8_t *dd = d; const uint8_t *ss = s;
    while (n--) *dd++ = *ss++;
}

/* Post one RX buffer (device-writable) using descriptor id; record its VA. */
static void
vsock_post_rx(uint16_t id, uint64_t pa, uintptr_t va)
{
    s_rx_va[id] = va;
    s_rx_pa[id] = pa;
    virtq_publish_single(&s_rxq, id, pa, 4096u, 1 /*device writes*/);
}

/* Fill the TX scratch with a header (+optional payload) and send it on the TX
 * queue. Returns 0 once the device consumes it. */
static int
vsock_send(uint16_t op, const void *payload, uint32_t plen)
{
    vsock_hdr_t *h = (vsock_hdr_t *)s_tx_va;
    _memset(h, 0, sizeof(*h));
    h->src_cid   = s_cid;
    h->dst_cid   = VMADDR_CID_HOST;
    h->src_port  = VSOCK_GUEST_PORT;
    h->dst_port  = VSOCK_HOST_PORT;
    h->len       = plen;
    h->type      = VSOCK_TYPE_STREAM;
    h->op        = op;
    h->buf_alloc = VSOCK_BUF_ALLOC;
    h->fwd_cnt   = 0;
    if (plen)
        _memcpy((uint8_t *)s_tx_va + sizeof(*h), payload, plen);

    virtq_buf_t seg = { s_tx_pa, sizeof(*h) + plen, 0 };
    uint16_t head;
    if (virtq_publish_chain(&s_txq, &seg, 1, &head) < 0)
        return -1;
    virtq_notify(&s_txq);

    uint16_t id; uint32_t len;
    for (uint32_t b = 0; b < VSOCK_POLL_BUDGET; b++) {
        if (virtq_poll_used(&s_txq, &id, &len)) {
            virtq_free_chain(&s_txq, id);
            return 0;
        }
        arch_pause();
    }
    return -1;
}

/* Wait for an RX packet with the given op (e.g. RESPONSE). Returns 0 on match,
 * -1 on timeout or an RST. Re-posts each consumed RX buffer. */
static int
vsock_wait_op(uint16_t want_op)
{
    uint16_t id; uint32_t len;
    for (uint32_t b = 0; b < VSOCK_POLL_BUDGET; b++) {
        if (virtq_poll_used(&s_rxq, &id, &len)) {
            int rc = -2;
            if (len >= sizeof(vsock_hdr_t)) {
                vsock_hdr_t *h = (vsock_hdr_t *)s_rx_va[id];
                if (h->op == want_op)       rc = 0;
                else if (h->op == VSOCK_OP_RST) rc = -1;
            }
            /* Recycle the buffer for further receives. */
            virtq_publish_single(&s_rxq, id, s_rx_pa[id], 4096u, 1);
            virtq_notify(&s_rxq);
            if (rc != -2)
                return rc;
        }
        arch_pause();
    }
    return -1;
}

void
virtio_vsock_init(void)
{
    if (virtio_pci_find(VIRTIO_VSOCK_MODERN, VIRTIO_VSOCK_MODERN, &s_dev) < 0)
        return;                              /* not present → silent */

    virtio_reset(&s_dev);
    if (virtio_negotiate(&s_dev, 0) < 0)
        return;
    if (virtio_setup_queue(&s_dev, VSOCK_RXQ, &s_rxq) < 0 ||
        virtio_setup_queue(&s_dev, VSOCK_TXQ, &s_txq) < 0 ||
        virtio_setup_queue(&s_dev, VSOCK_EVTQ, &s_evtq) < 0) {
        s_dev.common->device_status = VIRTIO_STATUS_FAILED;
        return;
    }
    virtio_driver_ok(&s_dev);

    /* guest CID: little-endian u64 at device-config offset 0. */
    s_cid = 0;
    for (int i = 0; i < 8; i++)
        s_cid |= (uint64_t)s_dev.devcfg[i] << (8 * i);

    /* Post RX buffers so the device can deliver RESPONSE/RW back to us. */
    for (uint32_t i = 0; i < VSOCK_RX_BUFS; i++) {
        uint64_t pa; uintptr_t va;
        if (virtio_alloc_dma_page(&pa, &va) < 0)
            break;
        int id = virtq_alloc_desc(&s_rxq);
        if (id < 0) break;
        vsock_post_rx((uint16_t)id, pa, va);
    }
    virtq_notify(&s_rxq);

    if (virtio_alloc_dma_page(&s_tx_pa, &s_tx_va) < 0)
        return;

    printk("[VSOCK] OK: guest cid=%lu ready\n", (unsigned long)s_cid);

    /* Boot-time connectivity self-test is opt-in via fw_cfg so production boots
     * never auto-dial a host port. Trigger with
     * `-fw_cfg name=opt/aegis.vsock_test,string=1` + a vhost-vsock device and a
     * host AF_VSOCK listener on VSOCK_HOST_PORT. (A full AF_VSOCK socket family
     * is the follow-on; this proves the transport.) */
    char gate[8];
    if (fw_cfg_read_file("opt/aegis.vsock_test", gate, sizeof(gate)) <= 0)
        return;

    printk("[VSOCK] selftest: connecting to host:%u\n", (unsigned)VSOCK_HOST_PORT);

    /* Handshake: REQUEST → RESPONSE → RW → SHUTDOWN. */
    if (vsock_send(VSOCK_OP_REQUEST, NULL, 0) < 0) {
        printk("[VSOCK] FAIL: could not send REQUEST\n");
        return;
    }
    if (vsock_wait_op(VSOCK_OP_RESPONSE) < 0) {
        printk("[VSOCK] no RESPONSE from host (no listener on port %u?)\n",
               (unsigned)VSOCK_HOST_PORT);
        return;
    }
    static const char msg[] = "hello from aegis\n";
    uint32_t n = (uint32_t)(sizeof(msg) - 1);
    if (vsock_send(VSOCK_OP_RW, msg, n) < 0) {
        printk("[VSOCK] FAIL: could not send RW payload\n");
        return;
    }
    (void)vsock_send(VSOCK_OP_SHUTDOWN, NULL, 0);
    printk("[VSOCK] OK: cid=%lu sent %u bytes to host\n",
           (unsigned long)s_cid, (unsigned)n);
}
