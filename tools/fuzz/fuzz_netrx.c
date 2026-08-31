/* Fuzz the Aegis kernel network RX path END TO END:
 *   eth_rx() -> arp_rx_pkt() / ip_rx() -> icmp_rx() / tcp_rx() / udp_rx()
 *
 * This is the pre-auth remote attack surface: any host on the LAN can put
 * arbitrary bytes into eth_rx with no capability and no authentication. Unlike
 * fuzz_ethrx.c this links the REAL tcp.c and udp.c, opens a listening TCP port
 * and a bound UDP port, and drives tcp_tick(), so the connection state machine,
 * the reassembly/ring code and the retransmit timer are all live.
 *
 * Honest scope:
 *   - Single-threaded. The REAL ticket spinlocks are used (uncontended), so
 *     this exercises genuine locking code but cannot find races.
 *   - The socket layer is stubbed (sock_get/sock_wake/epoll_notify): a
 *     connection is reachable from the wire but nothing drains its receive
 *     ring, so a filled ring is reached but the drain path is not.
 *   - g_in_isr_poll = 1, the context eth_rx really runs in.
 *
 * Each frame is copied into an exact-size heap block so ASan traps the first
 * byte read past what the NIC actually delivered.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "eth.h"
#include "ip.h"
#include "ipv6.h"
#include "netdev.h"
#include "tcp.h"
#include "udp.h"
#include "socket.h"

uint64_t g_fake_ticks = 0;
volatile int g_in_isr_poll = 1;

/* ---- stubs: socket layer, epoll, kva, rng ---------------------------- */

/* NULL here means an inbound datagram is parsed and then dropped at delivery,
 * so UDP's socket-enqueue path is NOT covered. TCP does not need it: tcp.c
 * keeps its own connection table and only uses the socket layer to wake a
 * blocked reader. */
sock_t *sock_get(uint32_t id)        { (void)id; return NULL; }
sock_t *sock_get_nolock(uint32_t id) { (void)id; return NULL; }
netdev_t *netdev_get(const char *n)  { (void)n; return NULL; }
void waitq_wake_all(waitq_t *q)      { (void)q; }
void  sock_wake(uint32_t id)     { (void)id; }
void  epoll_notify(uint32_t id, uint32_t ev) { (void)id; (void)ev; }
void ipv6_init(netdev_t *dev) { (void)dev; }
void ipv6_selftest(netdev_t *dev) { (void)dev; }
void ipv6_get_linklocal(ip6_addr_t *out) { if (out) memset(out, 0, sizeof(*out)); }
int ipv6_addr_equal(const ip6_addr_t *a, const ip6_addr_t *b)
{ return memcmp(a, b, sizeof(*a)) == 0; }
int ipv6_send(netdev_t *dev, const ip6_addr_t *dst, uint8_t next,
              const void *payload, uint16_t len)
{ (void)dev; (void)dst; (void)next; (void)payload; (void)len; return -1; }
void ipv6_rx(netdev_t *dev, const void *frame, const void *data, uint16_t len)
{ (void)dev; (void)frame; (void)data; (void)len; }
uint16_t ipv6_l4_checksum(const ip6_addr_t *src, const ip6_addr_t *dst,
                          uint8_t next, const void *payload, uint16_t len)
{ (void)src; (void)dst; (void)next; (void)payload; (void)len; return 1; }

/* Real backing memory — TCP rings are indexed with & (SIZE-1) and genuinely
 * written, so handing back a short buffer would fake a bug. */
void *kva_alloc_pages(uint64_t npages)
{
    void *p = NULL;
    if (npages == 0 || npages > (1u << 20))
        return NULL;
    if (posix_memalign(&p, 4096, npages * 4096) != 0)
        return NULL;
    memset(p, 0, npages * 4096);
    return p;
}

/* Deterministic "randomness": a fuzzer needs reproducible ISNs. */
int random_get_bytes(void *buf, size_t n)
{
    static uint64_t s = 0x9E3779B97F4A7C15ull;
    uint8_t *p = buf;
    size_t i;
    for (i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        p[i] = (uint8_t)s;
    }
    return 0;
}

/* ---- fake NIC --------------------------------------------------------- */

static unsigned long s_tx_frames;

static int fake_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    volatile uint8_t sink = 0;
    uint16_t i;
    (void)dev;
    assert(len >= 14   && "kernel emitted a runt Ethernet frame");
    assert(len <= 1514 && "kernel emitted an over-MTU Ethernet frame");
    for (i = 0; i < len; i++)
        sink = (uint8_t)(sink ^ ((const uint8_t *)pkt)[i]);
    (void)sink;
    s_tx_frames++;
    return 0;
}

static void fake_poll(netdev_t *dev) { (void)dev; }

static netdev_t s_dev = {
    .name = "eth0",
    .mac  = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 },
    .mtu  = 1500,
    .send = fake_send,
    .poll = fake_poll,
    .priv = NULL,
};

__attribute__((destructor)) static void report(void)
{
    if (getenv("FUZZ_NETRX_STATS"))
        fprintf(stderr, "[harness] kernel emitted %lu frames\n", s_tx_frames);
}

static int s_inited;

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    uint8_t *frame;
    uint16_t len;

    if (!s_inited) {
        eth_init();
        udp_init();
        tcp_init();
        net_set_config(0x3201A8C0u /* 192.168.1.50 */,
                       0x00FFFFFFu /* /24 */,
                       0x0101A8C0u /* 192.168.1.1 */);
        /* An open port, so inbound SYNs walk the state machine instead of
         * short-circuiting into the RST path. */
        tcp_listen(80, 1);
        udp_bind(68, 2);
        s_inited = 1;
    }

    if (n > 1514)
        n = 1514;
    len = (uint16_t)n;

    /* Advance the clock so retransmit/TIME_WAIT deadlines are actually
     * reached across a corpus run. */
    g_fake_ticks += 7;

    frame = malloc(len ? len : 1);
    if (!frame)
        return 0;
    memcpy(frame, d, len);

    eth_rx(&s_dev, frame, len);

    free(frame);

    /* Drive the retransmit timer roughly every 16 frames. */
    if ((g_fake_ticks & 0x7f) < 7)
        tcp_tick();

    return 0;
}
