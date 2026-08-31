/* Fuzz the Aegis kernel's Ethernet receive path: eth_rx() -> arp_rx_pkt() /
 * ip_rx() -> icmp_rx().
 *
 * This is the only entry point in the kernel an attacker reaches with NO
 * authentication and NO capability: any host on the LAN can put arbitrary bytes
 * here. Everything else audited so far needs at least a local process.
 *
 * Scope and honesty about it:
 *   - Locks are no-ops (single-threaded), so this finds PARSING bugs, not the
 *     concurrency bugs. The shim does trap on non-recursive-lock reentry.
 *   - tcp_rx/udp_rx are stubbed out here (they need the socket layer); this
 *     harness covers Ethernet framing, ARP, IPv4 and ICMP only.
 *   - g_in_isr_poll = 1 so arp_resolve takes the ISR path and never blocks —
 *     that is the context eth_rx actually runs in.
 *
 * The frame is placed at the END of a heap allocation of exactly `len` bytes so
 * ASan traps the first byte read past the frame the NIC actually delivered.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "eth.h"
#include "ip.h"
#include "ipv6.h"
#include "netdev.h"

uint64_t g_fake_ticks = 0;
volatile int g_in_isr_poll = 1;   /* eth_rx runs from the PIT poll */

/* ---- stubs for the layers this harness does not cover ---------------- */

void tcp_rx(netdev_t *dev, ip4_addr_t s, ip4_addr_t d,
            const void *seg, uint16_t len)
{
    /* Touch the whole segment so ASan proves ip_rx handed us a bounded one. */
    volatile uint8_t sink = 0;
    uint16_t i;
    (void)dev; (void)s; (void)d;
    for (i = 0; i < len; i++)
        sink = (uint8_t)(sink ^ ((const uint8_t *)seg)[i]);
    (void)sink;
}

void udp_rx(netdev_t *dev, ip4_addr_t s, ip4_addr_t d,
            const void *dgram, uint16_t len)
{
    volatile uint8_t sink = 0;
    uint16_t i;
    (void)dev; (void)s; (void)d;
    for (i = 0; i < len; i++)
        sink = (uint8_t)(sink ^ ((const uint8_t *)dgram)[i]);
    (void)sink;
}

void udp_init(void) {}
void tcp_init(void) {}
void ipv6_init(netdev_t *dev) { (void)dev; }
void ipv6_selftest(netdev_t *dev) { (void)dev; }
void ipv6_rx(netdev_t *dev, const void *frame, const void *data, uint16_t len)
{
    (void)dev; (void)frame; (void)data; (void)len;
}
netdev_t *netdev_get(const char *name) { (void)name; return NULL; }

/* ---- fake NIC --------------------------------------------------------- */

static unsigned long s_tx_frames;

static int fake_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    volatile uint8_t sink = 0;
    uint16_t i;
    (void)dev;
    /* A frame we emit must be a well-formed Ethernet frame, and must never
     * exceed the MTU + header. */
    assert(len >= 14 && "kernel emitted a runt Ethernet frame");
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

static int s_inited;

/* Coverage receipt: a clean fuzz run means nothing if the harness never
 * reached the code that emits packets. Set FUZZ_ETHRX_STATS=1 to see how many
 * frames the kernel actually transmitted in response to the corpus. */
__attribute__((destructor)) static void report(void)
{
    if (getenv("FUZZ_ETHRX_STATS"))
        fprintf(stderr, "[harness] kernel emitted %lu frames\n", s_tx_frames);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    uint8_t *frame;
    uint16_t len;

    if (!s_inited) {
        eth_init();
        /* A configured host: 192.168.1.50/24 via 192.168.1.1. Without an IP,
         * ip_rx's destination filter drops nearly everything and ARP never
         * replies, so most of the code would be unreachable. */
        net_set_config(0x3201A8C0u /* 192.168.1.50, net order on LE */,
                       0x00FFFFFFu /* 255.255.255.0 */,
                       0x0101A8C0u /* 192.168.1.1 */);
        s_inited = 1;
    }

    /* A real NIC delivers at most an MTU-sized frame. */
    if (n > 1514)
        n = 1514;
    len = (uint16_t)n;

    g_fake_ticks += 7;   /* keep the ARP LRU clock moving */

    frame = malloc(len ? len : 1);
    if (!frame)
        return 0;
    memcpy(frame, d, len);

    eth_rx(&s_dev, frame, len);

    free(frame);
    return 0;
}
