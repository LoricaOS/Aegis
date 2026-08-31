/* IPv6 link-local networking: EUI-64 address, NDP, ICMPv6 echo, and UDP. */
#include "ipv6.h"
#include "eth.h"
#include "udp.h"
#include "socket.h"
#include "printk.h"
#include "arch.h"
#include "spinlock.h"
#include "../lib/string.h"

#define NDP_SLOTS 16
#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY   129
#define ICMP6_NS           135
#define ICMP6_NA           136

typedef struct {
    ip6_addr_t ip;
    mac_addr_t mac;
    uint8_t valid;
    uint8_t resolved;
} ndp_entry_t;

static ip6_addr_t s_linklocal;
static ndp_entry_t s_ndp[NDP_SLOTS];
static spinlock_t ip6_lock = SPINLOCK_INIT;
extern volatile int g_in_isr_poll;

int
ipv6_addr_equal(const ip6_addr_t *a, const ip6_addr_t *b)
{
    return __builtin_memcmp(a->b, b->b, 16) == 0;
}

static int ip6_unspecified(const ip6_addr_t *a)
{
    static const ip6_addr_t zero;
    return ipv6_addr_equal(a, &zero);
}

static int ip6_linklocal(const ip6_addr_t *a)
{
    return a->b[0] == 0xfe && (a->b[1] & 0xc0) == 0x80;
}

static int ip6_multicast(const ip6_addr_t *a) { return a->b[0] == 0xff; }

void ipv6_get_linklocal(ip6_addr_t *out) { if (out) *out = s_linklocal; }

static uint32_t sum_be(uint32_t sum, const void *data, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    while (len >= 2) { sum += ((uint32_t)p[0] << 8) | p[1]; p += 2; len -= 2; }
    if (len) sum += (uint32_t)p[0] << 8;
    return sum;
}

uint16_t
ipv6_l4_checksum(const ip6_addr_t *src, const ip6_addr_t *dst,
                 uint8_t next_header, const void *payload, uint16_t len)
{
    uint32_t sum = sum_be(0, src, 16);
    sum = sum_be(sum, dst, 16);
    uint8_t tail[8] = {
        0, 0, (uint8_t)(len >> 8), (uint8_t)len,
        0, 0, 0, next_header
    };
    sum = sum_be(sum, tail, sizeof(tail));
    sum = sum_be(sum, payload, len);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

void
ipv6_init(netdev_t *dev)
{
    __builtin_memset(&s_linklocal, 0, sizeof(s_linklocal));
    __builtin_memset(s_ndp, 0, sizeof(s_ndp));
    if (!dev) return;
    s_linklocal.b[0] = 0xfe; s_linklocal.b[1] = 0x80;
    s_linklocal.b[8] = dev->mac[0] ^ 0x02;
    s_linklocal.b[9] = dev->mac[1]; s_linklocal.b[10] = dev->mac[2];
    s_linklocal.b[11] = 0xff; s_linklocal.b[12] = 0xfe;
    s_linklocal.b[13] = dev->mac[3]; s_linklocal.b[14] = dev->mac[4];
    s_linklocal.b[15] = dev->mac[5];
}

static void multicast_mac(const ip6_addr_t *ip, mac_addr_t *mac)
{
    mac->b[0] = 0x33; mac->b[1] = 0x33;
    for (int i = 0; i < 4; i++) mac->b[i + 2] = ip->b[i + 12];
}

static ndp_entry_t *ndp_find(const ip6_addr_t *ip)
{
    for (int i = 0; i < NDP_SLOTS; i++)
        if (s_ndp[i].valid && ipv6_addr_equal(&s_ndp[i].ip, ip)) return &s_ndp[i];
    return 0;
}

static ndp_entry_t *ndp_pending(const ip6_addr_t *ip)
{
    ndp_entry_t *e = ndp_find(ip);
    if (e) return e;
    for (int i = 0; i < NDP_SLOTS; i++) if (!s_ndp[i].valid) {
        s_ndp[i].ip = *ip; s_ndp[i].valid = 1; s_ndp[i].resolved = 0;
        return &s_ndp[i];
    }
    s_ndp[0].ip = *ip; s_ndp[0].valid = 1; s_ndp[0].resolved = 0;
    return &s_ndp[0];
}

static int ipv6_emit(netdev_t *dev, const ip6_addr_t *dst, uint8_t next,
                     const void *payload, uint16_t len, const mac_addr_t *mac)
{
    uint8_t pkt[1500];
    if (len > 1460) return -1;
    ip6_hdr_t *h = (ip6_hdr_t *)pkt;
    h->vtc_flow = htonl(6u << 28); h->payload_len = htons(len);
    h->next_header = next; h->hop_limit = next == IP6_PROTO_ICMPV6 ? 255 : 64;
    h->src = s_linklocal; h->dst = *dst;
    kmemcpy(pkt + sizeof(*h), payload, len);
    if (ipv6_addr_equal(dst, &s_linklocal)) {
        ipv6_rx(dev, 0, pkt, (uint16_t)(sizeof(*h) + len));
        return 0;
    }
    return eth_send(dev, mac, ETHERTYPE_IPV6, pkt, (uint16_t)(sizeof(*h) + len));
}

static void ndp_solicit(netdev_t *dev, const ip6_addr_t *target)
{
    uint8_t msg[32] = {0};
    msg[0] = ICMP6_NS;
    kmemcpy(msg + 8, target, 16);
    msg[24] = 1; msg[25] = 1;
    kmemcpy(msg + 26, dev->mac, 6);
    ip6_addr_t dst = { .b = {0xff,0x02,0,0,0,0,0,0,0,0,0,1,0xff,0,0,0} };
    dst.b[13] = target->b[13]; dst.b[14] = target->b[14]; dst.b[15] = target->b[15];
    uint16_t c = ipv6_l4_checksum(&s_linklocal, &dst, IP6_PROTO_ICMPV6, msg, sizeof(msg));
    msg[2] = (uint8_t)(c >> 8); msg[3] = (uint8_t)c;
    mac_addr_t mac; multicast_mac(&dst, &mac);
    ipv6_emit(dev, &dst, IP6_PROTO_ICMPV6, msg, sizeof(msg), &mac);
}

static int ndp_resolve(netdev_t *dev, const ip6_addr_t *ip, mac_addr_t *mac)
{
    irqflags_t fl = spin_lock_irqsave(&ip6_lock);
    ndp_entry_t *e = ndp_find(ip);
    if (e && e->resolved) { *mac = e->mac; spin_unlock_irqrestore(&ip6_lock, fl); return 0; }
    ndp_pending(ip);
    spin_unlock_irqrestore(&ip6_lock, fl);
    ndp_solicit(dev, ip);
    if (g_in_isr_poll) return -1;
    for (uint32_t i = 0; i < 500; i++) {
        arch_wait_for_irq();
        if (dev->poll) dev->poll(dev);
        fl = spin_lock_irqsave(&ip6_lock);
        e = ndp_find(ip);
        if (e && e->resolved) { *mac = e->mac; spin_unlock_irqrestore(&ip6_lock, fl); arch_enable_irq(); return 0; }
        spin_unlock_irqrestore(&ip6_lock, fl);
    }
    arch_enable_irq();
    return -1;
}

int
ipv6_send(netdev_t *dev, const ip6_addr_t *dst, uint8_t next,
          const void *payload, uint16_t len)
{
    if (!dev || ip6_unspecified(&s_linklocal) ||
        (!ip6_linklocal(dst) && !ip6_multicast(dst))) return -1;
    mac_addr_t mac;
    if (ip6_multicast(dst)) multicast_mac(dst, &mac);
    else if (ipv6_addr_equal(dst, &s_linklocal)) __builtin_memset(&mac, 0, sizeof(mac));
    else if (ndp_resolve(dev, dst, &mac) != 0) return -1;
    return ipv6_emit(dev, dst, next, payload, len, &mac);
}

static void icmp6_reply(netdev_t *dev, const ip6_hdr_t *ip,
                        const uint8_t *data, uint16_t len)
{
    uint8_t msg[1460];
    if (len > sizeof(msg)) return;
    kmemcpy(msg, data, len); msg[0] = ICMP6_ECHO_REPLY; msg[2] = msg[3] = 0;
    uint16_t c = ipv6_l4_checksum(&s_linklocal, &ip->src, IP6_PROTO_ICMPV6, msg, len);
    msg[2] = (uint8_t)(c >> 8); msg[3] = (uint8_t)c;
    ipv6_send(dev, &ip->src, IP6_PROTO_ICMPV6, msg, len);
}

static void icmp6_rx(netdev_t *dev, const ip6_hdr_t *ip,
                     const uint8_t *msg, uint16_t len)
{
    if (len < 4 || ipv6_l4_checksum(&ip->src, &ip->dst,
                                    IP6_PROTO_ICMPV6, msg, len) != 0) return;
    if (msg[0] == ICMP6_ECHO_REQUEST && msg[1] == 0 &&
        ipv6_addr_equal(&ip->dst, &s_linklocal) && !ip6_unspecified(&ip->src)) {
        icmp6_reply(dev, ip, msg, len);
        return;
    }
    if (msg[0] == ICMP6_NS && msg[1] == 0 && len >= 24 && ip->hop_limit == 255) {
        ip6_addr_t target; kmemcpy(&target, msg + 8, 16);
        if (!ipv6_addr_equal(&target, &s_linklocal)) return;
        if (!ip6_unspecified(&ip->src) && len >= 32 && msg[24] == 1 && msg[25] >= 1) {
            irqflags_t fl = spin_lock_irqsave(&ip6_lock);
            ndp_entry_t *e = ndp_pending(&ip->src);
            kmemcpy(&e->mac, msg + 26, 6); e->resolved = 1;
            spin_unlock_irqrestore(&ip6_lock, fl);
        }
        uint8_t out[32] = {0}; out[0] = ICMP6_NA; out[4] = 0x60;
        kmemcpy(out + 8, &s_linklocal, 16); out[24] = 2; out[25] = 1;
        kmemcpy(out + 26, dev->mac, 6);
        ip6_addr_t dst = ip->src;
        if (ip6_unspecified(&dst)) dst = (ip6_addr_t){ .b = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1} };
        uint16_t c = ipv6_l4_checksum(&s_linklocal, &dst, IP6_PROTO_ICMPV6, out, sizeof(out));
        out[2] = (uint8_t)(c >> 8); out[3] = (uint8_t)c;
        ipv6_send(dev, &dst, IP6_PROTO_ICMPV6, out, sizeof(out));
        return;
    }
    if (msg[0] == ICMP6_NA && msg[1] == 0 && len >= 32 && ip->hop_limit == 255 &&
        msg[24] == 2 && msg[25] >= 1) {
        ip6_addr_t target; kmemcpy(&target, msg + 8, 16);
        irqflags_t fl = spin_lock_irqsave(&ip6_lock);
        ndp_entry_t *e = ndp_find(&target);
        if (e && !e->resolved) { kmemcpy(&e->mac, msg + 26, 6); e->resolved = 1; }
        spin_unlock_irqrestore(&ip6_lock, fl);
    }
}

void
ipv6_rx(netdev_t *dev, const void *frame, const void *payload, uint16_t len)
{
    (void)frame;
    if (len < sizeof(ip6_hdr_t)) return;
    const ip6_hdr_t *h = (const ip6_hdr_t *)payload;
    if ((ntohl(h->vtc_flow) >> 28) != 6) return;
    uint16_t plen = ntohs(h->payload_len);
    if (plen > len - sizeof(*h)) return;
    if (!ipv6_addr_equal(&h->dst, &s_linklocal) && !ip6_multicast(&h->dst)) return;
    const uint8_t *data = (const uint8_t *)payload + sizeof(*h);
    if (h->next_header == IP6_PROTO_ICMPV6) icmp6_rx(dev, h, data, plen);
    else if (h->next_header == IP6_PROTO_UDP) udp6_rx(dev, &h->src, &h->dst, data, plen);
}

void
ipv6_selftest(netdev_t *dev)
{
    int tx = sock_alloc(SOCK_TYPE_DGRAM), rx = sock_alloc(SOCK_TYPE_DGRAM);
    int ok = tx >= 0 && rx >= 0;
    if (ok) {
        sock_t *ts = sock_get((uint32_t)tx), *rs = sock_get((uint32_t)rx);
        ts->domain = rs->domain = AF_INET6;
        ts->local_port = 49150; rs->local_port = 49151;
        rs->local_ip6 = s_linklocal;
        ok = udp_bind(rs->local_port, (uint32_t)rx) == 0;
        uint8_t byte = 0xa6;
        if (ok) ok = udp6_send(dev, ts->local_port, &s_linklocal,
                               rs->local_port, &byte, 1) == 0;
        if (ok) {
            udp_rx_slot_t *slot = &rs->udp_rx[0];
            ok = rs->udp_rx_tail == 1 && slot->len == 1 &&
                 slot->data[0] == byte && slot->family == AF_INET6 &&
                 ipv6_addr_equal(&slot->src_ip6, &s_linklocal);
        }
        udp_unbind(rs->local_port);
    }
    if (tx >= 0) sock_free((uint32_t)tx);
    if (rx >= 0) sock_free((uint32_t)rx);
    printk(ok ? "[NET6] OK: link-local NDP/ICMPv6 + UDP loopback\n" :
                "[NET6] FAIL: UDP loopback self-test\n");
}
