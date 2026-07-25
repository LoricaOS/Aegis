/* kernel/net/ip.c — IPv4 send/receive, ICMP echo, net_init */
#include "ip.h"
#include "../lib/string.h"
#include "eth.h"
#include "udp.h"
#include "tcp.h"
#include "printk.h"
#include "spinlock.h"
#include "arch.h"   /* arch_get_ticks() */

/* Local memory helpers (kernel has no libc). */


/* ---- Checksum implementation ------------------------------------------ */

uint32_t net_checksum(const void *data, uint32_t len)
{
    const uint16_t *p   = (const uint16_t *)data;
    uint32_t        sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)p;
    return sum;
}

uint16_t net_checksum_finish(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ---- IP configuration -------------------------------------------------- */

static ip4_addr_t s_my_ip;
static ip4_addr_t s_netmask;
static ip4_addr_t s_gateway;
static spinlock_t ip_lock = SPINLOCK_INIT;

void net_set_config(ip4_addr_t ip, ip4_addr_t mask, ip4_addr_t gw)
{
    irqflags_t fl = spin_lock_irqsave(&ip_lock);
    s_my_ip   = ip;
    s_netmask = mask;
    s_gateway = gw;

    /* Print human-readable form: derive prefix length from mask. */
    uint32_t m  = ntohl(mask);
    int      pl = 0;
    while (m & 0x80000000u) { pl++; m <<= 1; }

    uint32_t a = ntohl(ip);
    uint32_t g = ntohl(gw);
    printk("[NET] configured: %u.%u.%u.%u/%u gw %u.%u.%u.%u\n",
           (a>>24)&0xff, (a>>16)&0xff, (a>>8)&0xff, a&0xff, pl,
           (g>>24)&0xff, (g>>16)&0xff, (g>>8)&0xff, g&0xff);
    spin_unlock_irqrestore(&ip_lock, fl);
}

void net_get_config(ip4_addr_t *ip, ip4_addr_t *mask, ip4_addr_t *gw)
{
    irqflags_t fl = spin_lock_irqsave(&ip_lock);
    if (ip)   *ip   = s_my_ip;
    if (mask) *mask = s_netmask;
    if (gw)   *gw   = s_gateway;
    spin_unlock_irqrestore(&ip_lock, fl);
}

/* ---- IP send ----------------------------------------------------------- */

/* s_ip_id — IP identification counter. Shared, so it is bumped under ip_lock.
 * (The 1500-byte static assembly buffer that used to live here is gone: the
 * packet was built in it under ip_lock and then memcpy'd to a stack buffer
 * before the lock was dropped, so it was pure indirection — one static and one
 * copy. Build straight into the stack buffer instead.) */
static uint16_t s_ip_id;

/* ── Loopback queue ──────────────────────────────────────────────────────
 * Loopback packets are queued here and drained by ip_loopback_poll()
 * (called from PIT at 100Hz). Synchronous delivery would cause re-entry:
 *   ip_send(SYN) → ip_rx → tcp_rx → ip_send(SYN-ACK) → ip_rx → ...
 * clobbering static buffers. Deferred delivery breaks the recursion. */
#define LO_RING_SIZE 8
#define LO_PKT_MAX  1500
static uint8_t  s_lo_ring[LO_RING_SIZE][LO_PKT_MAX];
static uint16_t s_lo_len[LO_RING_SIZE];
static uint32_t s_lo_head;   /* next write slot */
static uint32_t s_lo_tail;   /* next read slot */
static netdev_t *s_lo_dev;   /* device context for ip_rx callback */

/* Single-flight guard for the drain below. netdev_poll_all is serialised by
 * netdev_lock; loopback never was, and poll sources run on EVERY core (the
 * arm64 timer PPI is per-core). Two cores in the loop below raced the
 * non-atomic s_lo_tail++: the same slot got delivered twice, or tail moved
 * BACKWARDS and replayed up to 8 stale packets into ip_rx. */
static volatile uint32_t s_lo_draining;

void ip_loopback_poll(void)
{
    /* Claim the drain. A CPU that loses just returns — the winner is already
     * draining the ring, including anything queued since. This is a flag and
     * not ip_lock because ip_rx re-enters the stack (ip_rx -> tcp_rx ->
     * ip_send) and would deadlock on the non-recursive ip_lock. */
    if (__atomic_exchange_n(&s_lo_draining, 1u, __ATOMIC_ACQUIRE))
        return;

    /* Only this CPU touches s_lo_tail while the claim is held, so the
     * increment needs no atomic; the store is RELEASE-ordered so ip_send's
     * ring-full test (under ip_lock) sees the slot freed. Producers only ever
     * advance s_lo_head, so re-reading it each pass picks up new work.
     * The slot stays counted as occupied across ip_rx — tail advances only
     * after delivery — so a producer cannot overwrite what we are reading. */
    while (__atomic_load_n(&s_lo_tail, __ATOMIC_RELAXED) !=
           __atomic_load_n(&s_lo_head, __ATOMIC_ACQUIRE)) {
        uint32_t tail = __atomic_load_n(&s_lo_tail, __ATOMIC_RELAXED);
        uint32_t idx  = tail & (LO_RING_SIZE - 1);
        ip_rx(s_lo_dev, (void *)0, s_lo_ring[idx], s_lo_len[idx]);
        __atomic_store_n(&s_lo_tail, tail + 1, __ATOMIC_RELEASE);
    }

    __atomic_store_n(&s_lo_draining, 0u, __ATOMIC_RELEASE);
}

int ip_send(netdev_t *dev, ip4_addr_t dst_ip, uint8_t proto,
            const void *payload, uint16_t len)
{
    if (len > 1480)  return -1; /* EMSGSIZE — no fragmentation in v1 */
    irqflags_t ip_fl = spin_lock_irqsave(&ip_lock);

    /* Loopback: if destination is ourselves or 127.0.0.0/8, queue the
     * packet for deferred delivery instead of sending it to the NIC.
     * Loopback works without a NIC (dev may be NULL). */
    if ((s_my_ip != 0 && dst_ip == s_my_ip) ||
        (ntohl(dst_ip) >> 24) == 127) {
        if (s_lo_head - s_lo_tail >= LO_RING_SIZE) {
            spin_unlock_irqrestore(&ip_lock, ip_fl);
            return -1;  /* loopback queue full — drop */
        }
        uint32_t idx = s_lo_head & (LO_RING_SIZE - 1);
        uint16_t total = (uint16_t)(sizeof(ip_hdr_t) + len);
        ip_hdr_t *hdr  = (ip_hdr_t *)s_lo_ring[idx];
        hdr->ver_ihl    = 0x45;
        hdr->dscp_ecn   = 0;
        hdr->total_len  = htons(total);
        hdr->id         = htons(s_ip_id++);
        hdr->flags_frag = 0;
        hdr->ttl        = 64;
        hdr->proto      = proto;
        hdr->checksum   = 0;
        hdr->src        = s_my_ip ? s_my_ip : dst_ip;
        hdr->dst        = dst_ip;
        hdr->checksum   = net_checksum_finish(net_checksum(hdr, sizeof(ip_hdr_t)));
        kmemcpy(s_lo_ring[idx] + sizeof(ip_hdr_t), payload, len);
        s_lo_len[idx] = total;
        s_lo_dev = dev;
        s_lo_head++;
        spin_unlock_irqrestore(&ip_lock, ip_fl);
        return 0;
    }

    /* Non-loopback path requires a real NIC. */
    if (!dev) {
        spin_unlock_irqrestore(&ip_lock, ip_fl);
        return -1;
    }

    /* Build the packet directly in the stack buffer, under ip_lock (s_ip_id
     * and the address config are shared). The lock must be dropped before
     * arp_resolve/eth_send, which take arp_lock: the order is arp_lock >
     * ip_lock, so holding ip_lock into them would invert it. */
    uint8_t   local_pkt[1500];
    ip_hdr_t *hdr   = (ip_hdr_t *)local_pkt;
    uint16_t  total = (uint16_t)(sizeof(ip_hdr_t) + len);

    hdr->ver_ihl    = 0x45;
    hdr->dscp_ecn   = 0;
    hdr->total_len  = htons(total);
    hdr->id         = htons(s_ip_id++);
    hdr->flags_frag = 0;
    hdr->ttl        = 64;
    hdr->proto      = proto;
    hdr->checksum   = 0;
    hdr->src        = s_my_ip;  /* may be 0.0.0.0 during DHCP bootstrap */
    hdr->dst        = dst_ip;
    hdr->checksum   = net_checksum_finish(net_checksum(hdr, sizeof(ip_hdr_t)));

    kmemcpy(local_pkt + sizeof(ip_hdr_t), payload, len);

    /* Snapshot the config we need after the unlock. */
    ip4_addr_t my_ip   = s_my_ip;
    ip4_addr_t netmask = s_netmask;
    ip4_addr_t gateway = s_gateway;
    spin_unlock_irqrestore(&ip_lock, ip_fl);

    /* Determine next-hop MAC (outside ip_lock). */
    mac_addr_t next_hop_mac;

    if (dst_ip == htonl(0xFFFFFFFFu)) {
        /* Limited broadcast — no ARP needed. */
        kmemset(&next_hop_mac, 0xff, sizeof(next_hop_mac));
    } else {
        /* Same subnet? */
        ip4_addr_t via;
        if (my_ip == 0 || (dst_ip & netmask) == (my_ip & netmask))
            via = dst_ip;
        else
            via = gateway;

        if (arp_resolve(dev, via, &next_hop_mac) != 0)
            return -1; /* ARP timeout */
    }

    return eth_send(dev, &next_hop_mac, ETHERTYPE_IP, local_pkt, total);
}

/* ---- ICMP -------------------------------------------------------------- */

/* ICMP echo replies are built on the caller's stack, not in a shared static:
 * icmp_rx runs from ip_rx on every core, so a shared buffer let two concurrent
 * pings assemble into each other. 1480 B == the IP payload ceiling. */
#define ICMP_REPLY_MAX 1480

static void icmp_rx(netdev_t *dev, ip4_addr_t src_ip,
                    const icmp_hdr_t *icmp, uint16_t len)
{
    if (icmp->type == 0) {
        /* Echo reply — silently drop (no self-test in net_init any more). */
        return;
    }

    if (icmp->type == 8) {
        /* Echo request — build reply: swap src/dst, type=0, recompute checksum.
         * Guard the source first: the reply is sent TO src_ip, so an attacker
         * who spoofs the source as a broadcast / multicast / 0.0.0.0 address
         * would make Aegis emit attacker-chosen traffic (a reflection /
         * amplification vector, e.g. smurf).  A legitimate echo request always
         * carries a real unicast source, so dropping these never affects real
         * ping.  src_ip is network byte order. */
        {
            uint32_t s = ntohl(src_ip);
            if (s == 0 || s == 0xFFFFFFFFu) return;  /* 0.0.0.0 / limited bcast */
            if ((s >> 28) == 0xE) return;            /* 224.0.0.0/4 multicast   */
        }
        uint8_t icmp_buf[ICMP_REPLY_MAX];
        if (len > (uint16_t)sizeof(icmp_buf)) return;
        kmemcpy(icmp_buf, icmp, len);
        icmp_hdr_t *reply = (icmp_hdr_t *)icmp_buf;
        reply->type     = 0;
        reply->checksum = 0;
        reply->checksum = net_checksum_finish(net_checksum(icmp_buf, len));
        ip_send(dev, src_ip, IP_PROTO_ICMP, icmp_buf, len);
    }
    /* All other ICMP types: drop silently. */
}

/* ---- IP receive -------------------------------------------------------- */

void ip_rx(netdev_t *dev, const void *frame,
           const void *ip_payload, uint16_t ip_payload_len)
{
    if (ip_payload_len < (uint16_t)sizeof(ip_hdr_t)) return;

    const ip_hdr_t *hdr = (const ip_hdr_t *)ip_payload;

    /* Validate version and header length. */
    if ((hdr->ver_ihl >> 4) != 4)   return;
    if ((hdr->ver_ihl & 0xf) != 5)  return; /* no IP options in v1 */

    /* Validate header checksum. */
    if (net_checksum_finish(net_checksum(hdr, sizeof(ip_hdr_t))) != 0) return;

    /* Drop IP fragments.  Aegis has no reassembly, so a fragment is processed
     * as if it were a whole datagram: a fragment whose first 20 bytes happen to
     * look like a valid TCP/UDP/ICMP header would be used to build a reflected
     * reply (and later fragments, which carry no L4 header, are garbage).  Drop
     * anything with the More-Fragments bit (0x2000) set or a nonzero fragment
     * offset (low 13 bits) — i.e. flags_frag & 0x3FFF != 0.  The Don't-Fragment
     * bit (0x4000) is left alone (a normal unfragmented packet may set it). */
    if (ntohs(hdr->flags_frag) & 0x3FFF) return;

    /* rpfilter (anti-spoof) — applies ONLY to wire-received packets. Loopback
     * is delivered via ip_loopback_poll with frame == NULL (and legitimately
     * carries 127/8 or our-own-IP src/dst), so it is exempt; a non-NULL frame
     * means a real NIC delivered it, where a 127/8 source or destination, or a
     * source spoofing our own IP, is always attacker-controlled. Without this a
     * LAN attacker could inject packets that local services trust as 127.0.0.1
     * peers, or that bypass src-based filtering. Recovered from the April audit
     * (57e713f), lost in refactoring. */
    if (frame != (const void *)0) {
        if ((ntohl(hdr->src) >> 24) == 127)        return;
        if ((ntohl(hdr->dst) >> 24) == 127)        return;
        if (s_my_ip != 0 && hdr->src == s_my_ip)   return;
    }

    /* Destination filtering. */
    ip4_addr_t dst = hdr->dst;
    int accept = 0;
    if (dst == s_my_ip && s_my_ip != 0)                              accept = 1;
    if ((ntohl(dst) >> 24) == 127)                                   accept = 1; /* loopback 127.0.0.0/8 */
    if (dst == htonl(0xFFFFFFFFu))                                   accept = 1;
    if (s_my_ip == 0 && dst == htonl(0xFFFFFFFFu))                   accept = 1;
    if (s_my_ip != 0 && s_netmask != 0 &&
        dst == (s_my_ip | ~s_netmask))                               accept = 1;
    if (!accept) return;

    uint16_t hdr_len    = (uint16_t)sizeof(ip_hdr_t);
    uint16_t ip_tot_len = ntohs(hdr->total_len);
    if (ip_tot_len < hdr_len) return;               /* underflow guard */
    uint16_t data_len   = (uint16_t)(ip_tot_len - hdr_len);
    if (data_len > ip_payload_len - hdr_len) return;

    const void *proto_data = (const uint8_t *)ip_payload + hdr_len;

    switch (hdr->proto) {
    case IP_PROTO_ICMP:
        if (data_len >= (uint16_t)sizeof(icmp_hdr_t))
            icmp_rx(dev, hdr->src, (const icmp_hdr_t *)proto_data, data_len);
        break;
    case IP_PROTO_TCP:
        if (data_len >= 20u)   /* minimum TCP header is 20 bytes */
            tcp_rx(dev, hdr->src, hdr->dst, proto_data, data_len);
        break;
    case IP_PROTO_UDP:
        udp_rx(dev, hdr->src, hdr->dst, proto_data, data_len);
        break;
    default:
        break;
    }
}

/* ---- net_init ---------------------------------------------------------- */

void net_init(void)
{
    netdev_t *dev = netdev_get("eth0");
    if (!dev) {
        /* No NIC registered (e.g. make test with -machine pc): silent return.
         * boot.txt must NOT contain any [NET] lines. */
        return;
    }
    eth_init();
    udp_init();
    tcp_init();
}
