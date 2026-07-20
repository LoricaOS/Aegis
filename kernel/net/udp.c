/* kernel/net/udp.c — UDP send/receive, port demultiplexing */
#include "udp.h"
#include "../lib/string.h"
#include "ip.h"
#include "socket.h"
#include "epoll.h"
#include "spinlock.h"

/* Local memory helpers. */


/* ---- Binding table ----------------------------------------------------- */

typedef struct {
    uint16_t port;      /* host byte order; 0 = free */
    uint32_t sock_id;   /* index into socket table (Phase 26) */
} udp_binding_t;

static udp_binding_t s_udp[UDP_BINDINGS_MAX];
static spinlock_t udp_lock = SPINLOCK_INIT;

void udp_init(void)
{
    kmemset(s_udp, 0, sizeof(s_udp));
}

/* Maximum UDP datagram we can assemble: 1500 MTU - 20 IP hdr = 1480.
 * (ip_send rejects payloads > 1480 — no fragmentation in v1.) */
#define UDP_TX_MAX 1480

int udp_send(netdev_t *dev, uint16_t src_port, ip4_addr_t dst_ip,
             uint16_t dst_port, const void *payload, uint16_t len)
{
    if (!dev) return -1;
    /* Guard the 8-byte-header addition against uint16_t overflow first
     * (len near 0xFFFF would wrap udp_len to a tiny value), then bound. */
    if (len > UDP_TX_MAX - (uint16_t)sizeof(udp_hdr_t)) return -1;  /* EMSGSIZE */
    uint16_t udp_len = (uint16_t)(sizeof(udp_hdr_t) + len);

    /* Assemble on the stack — no shared static buffer, so concurrent
     * senders on different CPUs can't corrupt each other's datagram.
     * ip_send copies into its own local before releasing ip_lock. */
    uint8_t pkt[UDP_TX_MAX];
    udp_hdr_t *hdr = (udp_hdr_t *)pkt;
    hdr->src_port = htons(src_port);
    hdr->dst_port = htons(dst_port);
    hdr->length   = htons(udp_len);
    /* checksum = 0: legal for IPv4 (RFC 768 makes it optional).  We don't
     * compute an outbound checksum; receivers that require one will reject,
     * but every mainstream stack accepts checksum-0 IPv4 UDP.  If outbound
     * checksums become necessary, compute over the pseudo-header here and
     * store 0xFFFF when the result is 0 (0 means "no checksum" on the wire). */
    hdr->checksum = 0;
    if (len)
        kmemcpy(pkt + sizeof(udp_hdr_t), payload, len);

    return ip_send(dev, dst_ip, IP_PROTO_UDP, pkt, udp_len);
}

/* S4: UDP pseudo-header checksum validation.
 * Computes one's-complement sum over pseudo-header + UDP header + payload.
 * Returns 0 if valid, non-zero if corrupted. */
static uint16_t
udp_checksum_verify(uint32_t src_ip, uint32_t dst_ip,
                    const uint8_t *udp_pkt, uint16_t udp_len)
{
    uint32_t sum = 0;
    /* pseudo-header */
    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;
    sum += htons(17);            /* protocol = UDP */
    sum += htons(udp_len);
    /* UDP header + payload */
    const uint16_t *p = (const uint16_t *)udp_pkt;
    uint16_t i;
    for (i = 0; i < udp_len / 2; i++)
        sum += p[i];
    if (udp_len & 1)
        sum += udp_pkt[udp_len - 1];  /* odd byte, zero-padded */
    /* fold carries */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

void udp_rx(netdev_t *dev, ip4_addr_t src_ip, ip4_addr_t dst_ip,
            const void *udp_data, uint16_t len)
{
    (void)dev;
    if (len < (uint16_t)sizeof(udp_hdr_t)) return;
    irqflags_t fl = spin_lock_irqsave(&udp_lock);

    /* Deferred socket wake/notify — avoids udp_lock → sock_lock inversion. */
    uint32_t wake_sid = SOCK_NONE;

    const udp_hdr_t *hdr      = (const udp_hdr_t *)udp_data;
    uint16_t udp_claimed = ntohs(hdr->length);
    if (udp_claimed < (uint16_t)sizeof(udp_hdr_t)) goto udp_out;  /* malformed */
    if (udp_claimed > len) goto udp_out;                           /* truncated */

    /* S4: Validate UDP checksum (skip if checksum field is 0 per RFC 768). */
    if (hdr->checksum != 0) {
        if (udp_checksum_verify(src_ip, dst_ip,
                                (const uint8_t *)hdr, udp_claimed) != 0)
            goto udp_out;  /* drop corrupted packet */
    }

    {
    uint16_t dst_port  = ntohs(hdr->dst_port);
    uint16_t src_port  = ntohs(hdr->src_port);
    uint16_t payload_len = (uint16_t)(udp_claimed - (uint16_t)sizeof(udp_hdr_t));
    const uint8_t *payload = (const uint8_t *)udp_data + sizeof(udp_hdr_t);
    int i;

    for (i = 0; i < UDP_BINDINGS_MAX; i++) {
        if (s_udp[i].port != dst_port || s_udp[i].port == 0)
            continue;
        uint32_t sid = s_udp[i].sock_id;
        if (sid == SOCK_NONE)
            continue;                 /* stale entry — keep scanning */
        sock_t *s = sock_get_nolock(sid);
        if (!s)
            continue;                 /* slot freed under us — keep scanning */

        /* Local-IP demux: a socket bound to a specific local address
         * (not INADDR_ANY) only receives datagrams whose IP destination
         * matches that address. local_ip/dst_ip are both network byte
         * order; INADDR_ANY (0) is the wildcard and matches everything.
         * Matches Linux: a bind to 10.0.0.5 won't see traffic to a
         * different local address (or limited broadcast). */
        if (s->local_ip != INADDR_ANY && s->local_ip != dst_ip)
            continue;

        /* Connected-UDP peer filter: a UDP socket that has called
         * connect() only receives datagrams from its connected peer
         * (RFC / Linux semantics).  remote_ip/remote_port are network/
         * host order respectively to match what connect() stored.
         * An unconnected socket (state != SOCK_CONNECTED) accepts any
         * source.  This both fixes the conformance gap and closes an
         * off-path injection vector against connected sockets. */
        if (s->state == SOCK_CONNECTED) {
            if (s->remote_ip != src_ip || s->remote_port != src_port)
                continue;
        }

        /* Ring is lazily allocated for DGRAM sockets; a matched bound socket
         * always has one, but drop rather than deref if somehow absent. */
        if (!s->udp_rx) goto udp_out;
        /* Find a free UDP RX slot (SPSC ring: producer owns tail,
         * consumer owns head). */
        uint8_t next = (uint8_t)((s->udp_rx_tail + 1) & (UDP_RX_SLOTS - 1));
        if (next == s->udp_rx_head) goto udp_out;  /* ring full, drop */
        udp_rx_slot_t *slot = &s->udp_rx[s->udp_rx_tail & (UDP_RX_SLOTS - 1)];
        if (payload_len > UDP_RX_MAXBUF) payload_len = UDP_RX_MAXBUF;
        uint32_t j;
        for (j = 0; j < payload_len; j++)
            slot->data[j] = payload[j];
        slot->len      = payload_len;
        slot->src_ip   = src_ip;
        slot->src_port = src_port;
        slot->in_use   = 1;
        /* Publish the filled slot last.  On x86 stores are ordered, so a
         * consumer that observes the new tail also observes the slot
         * contents above; __atomic release makes that explicit and is
         * correct on ARM64 too (the consumer side in sys_recvfrom reads
         * head/tail without udp_lock — this is the only synchronisation). */
        __atomic_store_n(&s->udp_rx_tail, next, __ATOMIC_RELEASE);
        wake_sid = sid;
        goto udp_out;
    }
    }
    /* No binding: drop silently. */
udp_out:
    spin_unlock_irqrestore(&udp_lock, fl);

    /* Wake + epoll notify outside udp_lock (sock_lock > udp_lock). */
    if (wake_sid != SOCK_NONE) {
        sock_wake(wake_sid);
        epoll_notify(wake_sid, EPOLLIN);
        /* Wake any sys_poll / sys_epoll_wait waiter on this socket. */
        {
            sock_t *s_wake = sock_get(wake_sid);
            if (s_wake) waitq_wake_all(&s_wake->poll_waiters);
        }
    }
}

/* udp_bind: register a sock_id for the given port. Returns 0 or -1.
 * port 0 is rejected: it is the "free slot" sentinel in the binding
 * table, so registering it would corrupt demux (a port-0 entry is
 * skipped by udp_rx and treated as free by the next bind).  Callers
 * that want an auto-assigned port resolve a concrete ephemeral port
 * first (udp_ensure_local_port) and never pass 0 here. */
int
udp_bind(uint16_t port, uint32_t sock_id)
{
    if (port == 0) return -1;
    if (sock_id == SOCK_NONE) return -1;
    irqflags_t fl = spin_lock_irqsave(&udp_lock);
    uint32_t i;
    for (i = 0; i < UDP_BINDINGS_MAX; i++) {
        if (s_udp[i].port == port) {
            spin_unlock_irqrestore(&udp_lock, fl);
            return -1; /* EADDRINUSE */
        }
    }
    for (i = 0; i < UDP_BINDINGS_MAX; i++) {
        if (s_udp[i].port == 0) {
            s_udp[i].port    = port;
            s_udp[i].sock_id = sock_id;
            spin_unlock_irqrestore(&udp_lock, fl);
            return 0;
        }
    }
    spin_unlock_irqrestore(&udp_lock, fl);
    return -1;
}

/* udp_unbind: release the binding table entry for `port`.
 * Called from sock_vfs_close so a subsequent bind() to the same port
 * doesn't fail with EADDRINUSE. Without this, every UDP socket that
 * gets closed leaks its port binding (DHCP retry was the symptom that
 * exposed it: second bind to port 68 failed). */
void
udp_unbind(uint16_t port)
{
    if (port == 0) return;
    irqflags_t fl = spin_lock_irqsave(&udp_lock);
    uint32_t i;
    /* udp_bind enforces port uniqueness, so at most one entry matches. */
    for (i = 0; i < UDP_BINDINGS_MAX; i++) {
        if (s_udp[i].port == port) {
            s_udp[i].port    = 0;
            s_udp[i].sock_id = SOCK_NONE;
            break;
        }
    }
    spin_unlock_irqrestore(&udp_lock, fl);
}
