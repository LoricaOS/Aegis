/* kernel/net/tcp.c — TCP state machine (RFC 793), retransmit, TIME_WAIT */
#include "tcp.h"
#include "../lib/string.h"
#include "ip.h"
#include "socket.h"
#include "epoll.h"
#include "arch.h"   /* arch_get_ticks() */
#include "printk.h"
#include "spinlock.h"
#include "random.h" /* random_get_bytes() — unpredictable ISN */
#include "kva.h"    /* kva_alloc_pages — per-connection ring buffers */
#include <stddef.h>                 /* NULL */

/* tcp_isn — draw a 32-bit initial sequence number from the kernel CSPRNG.
 * Replaces the old (uint32_t)arch_get_ticks() seed, which was low-entropy
 * and externally predictable (RFC 6528 / blind-injection hardening). */
static uint32_t tcp_isn(void)
{
    uint32_t isn = 0;
    random_get_bytes(&isn, sizeof(isn));
    return isn;
}

/* S2: RFC 793 serial number arithmetic for TCP sequence numbers.
 * 32-bit sequence numbers wrap; plain < / > gives wrong results near 2^31.
 * a < b iff the signed difference (a - b) is negative. */
static inline int seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline int seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static inline int seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }
static inline int seq_ge(uint32_t a, uint32_t b) { return (int32_t)(a - b) >= 0; }

/* Local memory helpers. */


/* TCP header (20 bytes, no options). */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_hdr_t;

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

typedef struct __attribute__((packed)) {
    ip4_addr_t src;
    ip4_addr_t dst;
    uint8_t    zero;
    uint8_t    proto;
    uint16_t   tcp_len;
} tcp_pseudo_hdr_t;

static tcp_conn_t s_tcp[TCP_MAX_CONNS];

/* SYN-flood guard: cap concurrent half-open (SYN_RCVD) connections so a flood
 * of unfinished handshakes can't exhaust the shared s_tcp[] table, which is
 * also used by every established connection and every outbound connect().
 * Leaves the majority of the table for completed/outbound use. */
#define TCP_SYN_BACKLOG_MAX 32

static uint8_t s_tcp_buf[1480];
/* RST template — used by tcp_rx to send RST|ACK for unknown ports.
 * File-static to avoid placing a 16KB tcp_conn_t on the ISR stack. */
static tcp_conn_t s_rst_conn;
static spinlock_t tcp_lock = SPINLOCK_INIT;

/* tcp_claim_slot: zero slot i for reuse while preserving the kva-allocated ring
 * pointers (rbuf/sbuf are allocated once at boot and never freed — see
 * tcp_init). A raw memset of the slot would NULL them and the next data op
 * would dereference NULL. Every claim site (tcp_alloc, tcp_listen, tcp_connect)
 * must go through this, never a bare kmemset(&s_tcp[i], ...). */
static void tcp_claim_slot(uint32_t i)
{
    uint8_t *rb = s_tcp[i].rbuf;
    uint8_t *sb = s_tcp[i].sbuf;
    kmemset(&s_tcp[i], 0, sizeof(s_tcp[i]));
    s_tcp[i].rbuf = rb;
    s_tcp[i].sbuf = sb;
}

void tcp_init(void)
{
    /* Zero the table FIRST, then attach the kva rings — the alloc loop must run
     * after the memset so the pointers survive. */
    kmemset(s_tcp, 0, sizeof(s_tcp));
    for (uint32_t i = 0; i < TCP_MAX_CONNS; i++) {
        s_tcp[i].rbuf = kva_alloc_pages(TCP_RBUF_SIZE / 4096); /* 64 pages, panics on OOM */
        s_tcp[i].sbuf = kva_alloc_pages(TCP_SBUF_SIZE / 4096); /* 16 pages, panics on OOM */
    }
}

/* tcp_adv_window — compute the (network-order) 16-bit window field to advertise.
 * The ring reserves one byte (max usable = TCP_RBUF_SIZE - 1) so an exactly-full
 * ring never aliases to empty under the free-running-counter mask
 * `used = (tail - head) & (SIZE - 1)`; the window is capped at SIZE-1-used so we
 * never advertise bytes the rx path would drop.  For a non-SYN segment the value
 * is right-shifted by rcv_wscale (RFC 7323 window scaling); a SYN's window field
 * is NEVER scaled (RFC 7323 §2.2), so is_syn passes the raw value.  Either way
 * the result is clamped to 0xFFFF. */
static uint16_t tcp_adv_window(const tcp_conn_t *conn, int is_syn)
{
    uint32_t used  = (conn->rbuf_tail - conn->rbuf_head) & (TCP_RBUF_SIZE - 1);
    uint32_t avail = (TCP_RBUF_SIZE - 1) - used;
    if (!is_syn) avail >>= conn->rcv_wscale;
    if (avail > 0xFFFFu) avail = 0xFFFFu;
    return htons((uint16_t)avail);
}

/* tcp_parse_wscale — scan a SYN segment's TCP options for the Window Scale
 * option (RFC 7323, kind 3, len 3).  `opts` points just past the fixed 20-byte
 * header; `optlen` = hdr_bytes - 20.  Returns 1 and writes *shift (clamped to
 * the RFC 7323 §2.3 max of 14) if found, else 0. */
static int tcp_parse_wscale(const uint8_t *opts, uint32_t optlen, uint8_t *shift)
{
    uint32_t i = 0;
    while (i < optlen) {
        uint8_t kind = opts[i];
        if (kind == 0) break;              /* End of option list */
        if (kind == 1) { i++; continue; }  /* NOP */
        if (i + 1 >= optlen) break;        /* truncated length byte */
        uint8_t olen = opts[i + 1];
        if (olen < 2 || i + olen > optlen) break;  /* malformed */
        if (kind == 3 && olen == 3) {
            uint8_t s = opts[i + 2];
            if (s > 14) s = 14;
            *shift = s;
            return 1;
        }
        i += olen;
    }
    return 0;
}

/* TCP send-side fallback MSS: the conservative IPv4 default (576-byte MTU →
 * 536-byte MSS, RFC 879/1122), used only when the peer's SYN carried no MSS
 * option.  Normally sends chunk to conn->snd_mss (peer MSS, ≤ TCP_ADVMSS;
 * s_tcp_buf is 1480 so a full 1460 segment fits). */
#define TCP_DEFAULT_MSS  536

/* tcp_snd_mss — the segment size to use for conn's outbound data. */
static inline uint16_t tcp_snd_mss(const tcp_conn_t *c)
{
    return c->snd_mss ? c->snd_mss : TCP_DEFAULT_MSS;
}

/* tcp_parse_mss — same option walk, for the MSS option (RFC 793, kind 2,
 * len 4).  Returns the peer's MSS clamped to TCP_ADVMSS (s_tcp_buf holds one
 * full-size segment), or TCP_DEFAULT_MSS if absent/malformed. */
static uint16_t tcp_parse_mss(const uint8_t *opts, uint32_t optlen)
{
    uint32_t i = 0;
    while (i < optlen) {
        uint8_t kind = opts[i];
        if (kind == 0) break;
        if (kind == 1) { i++; continue; }
        if (i + 1 >= optlen) break;
        uint8_t olen = opts[i + 1];
        if (olen < 2 || i + olen > optlen) break;
        if (kind == 2 && olen == 4) {
            uint16_t mss = (uint16_t)((opts[i + 2] << 8) | opts[i + 3]);
            if (mss > TCP_ADVMSS) mss = TCP_ADVMSS;
            if (mss < 64) break;   /* nonsense value → default */
            return mss;
        }
        i += olen;
    }
    return TCP_DEFAULT_MSS;
}

/* tcp_send_syn — emit a SYN or SYN-ACK carrying TCP options: an MSS option
 * (TCP_ADVMSS) always, plus a Window Scale option (conn->rcv_wscale) when this
 * connection is offering scaling (rcv_wscale != 0).  Option layout mirrors Linux
 * for a clean 4-byte-aligned header: 02 04 <mss hi> <mss lo> [01 03 03 <shift>]
 * → 4 or 8 option bytes, data offset 6 or 7 words.  The window field in a SYN is
 * never scaled (is_syn=1).  Used for connect()'s SYN, the listener's SYN-ACK,
 * and their retransmits — all other (non-SYN) segments go through
 * tcp_send_segment / tcp_send_at_seq. */
static int tcp_send_syn(netdev_t *dev, tcp_conn_t *conn, uint8_t flags)
{
    uint8_t opts[8];
    uint32_t olen = 0;
    opts[olen++] = 2;  opts[olen++] = 4;                  /* MSS, len 4 */
    opts[olen++] = (uint8_t)(TCP_ADVMSS >> 8);
    opts[olen++] = (uint8_t)(TCP_ADVMSS & 0xFF);
    if (conn->rcv_wscale != 0) {
        opts[olen++] = 1;                                 /* NOP (align) */
        opts[olen++] = 3;  opts[olen++] = 3;              /* WScale, len 3 */
        opts[olen++] = conn->rcv_wscale;
    }

    uint16_t tcp_len = (uint16_t)(sizeof(tcp_hdr_t) + olen);
    if (tcp_len > (uint16_t)sizeof(s_tcp_buf)) return -1;

    tcp_hdr_t *hdr = (tcp_hdr_t *)s_tcp_buf;
    hdr->src_port = htons(conn->local_port);
    hdr->dst_port = htons(conn->remote_port);
    hdr->seq      = htonl(conn->snd_nxt);
    hdr->ack      = (flags & TCP_ACK) ? htonl(conn->rcv_nxt) : 0;
    hdr->data_off = (uint8_t)((tcp_len / 4) << 4);
    hdr->flags    = flags;
    hdr->window   = tcp_adv_window(conn, 1 /* is_syn */);
    hdr->checksum = 0;
    hdr->urgent   = 0;
    kmemcpy(s_tcp_buf + sizeof(tcp_hdr_t), opts, olen);

    tcp_pseudo_hdr_t ph;
    ph.src     = conn->local_ip;
    ph.dst     = conn->remote_ip;
    ph.zero    = 0;
    ph.proto   = IP_PROTO_TCP;
    ph.tcp_len = htons(tcp_len);
    uint32_t sum = 0;
    sum += net_checksum(&ph, sizeof(ph));
    sum += net_checksum(s_tcp_buf, tcp_len);
    hdr->checksum = net_checksum_finish(sum);

    return ip_send(dev, conn->remote_ip, IP_PROTO_TCP, s_tcp_buf, tcp_len);
}

int tcp_send_segment(netdev_t *dev, tcp_conn_t *conn,
                     uint8_t flags, const void *payload, uint16_t len)
{
    /* dev may be NULL for loopback — ip_send handles it */
    uint16_t tcp_len = (uint16_t)(sizeof(tcp_hdr_t) + len);
    if (tcp_len > (uint16_t)sizeof(s_tcp_buf)) return -1;

    tcp_hdr_t *hdr = (tcp_hdr_t *)s_tcp_buf;
    hdr->src_port = htons(conn->local_port);
    hdr->dst_port = htons(conn->remote_port);
    hdr->seq      = htonl(conn->snd_nxt);
    hdr->ack      = (flags & TCP_ACK) ? htonl(conn->rcv_nxt) : 0;
    hdr->data_off = (uint8_t)((sizeof(tcp_hdr_t) / 4) << 4);
    hdr->flags    = flags;
    hdr->window   = tcp_adv_window(conn, (flags & TCP_SYN) ? 1 : 0);
    hdr->checksum = 0;
    hdr->urgent   = 0;
    if (payload && len > 0)
        __builtin_memcpy(s_tcp_buf + sizeof(tcp_hdr_t), payload, len);

    tcp_pseudo_hdr_t ph;
    ph.src      = conn->local_ip;
    ph.dst      = conn->remote_ip;
    ph.zero     = 0;
    ph.proto    = IP_PROTO_TCP;
    ph.tcp_len  = htons(tcp_len);
    uint32_t sum = 0;
    sum += net_checksum(&ph, sizeof(ph));
    sum += net_checksum(s_tcp_buf, tcp_len);
    hdr->checksum = net_checksum_finish(sum);

    return ip_send(dev, conn->remote_ip, IP_PROTO_TCP, s_tcp_buf, tcp_len);
}

/* tcp_send_at_seq — like tcp_send_segment but stamps an explicit sequence
 * number instead of conn->snd_nxt.  Used for DATA (re)transmission, where the
 * segment must carry SND.UNA + offset, not SND.NXT.  tcp_send_segment is left
 * untouched for SYN/FIN/pure-ACK callers, which correctly use snd_nxt.
 * Identical header/checksum/window construction otherwise. */
static int tcp_send_at_seq(netdev_t *dev, tcp_conn_t *conn, uint8_t flags,
                           uint32_t seq, const void *payload, uint16_t len)
{
    uint16_t tcp_len = (uint16_t)(sizeof(tcp_hdr_t) + len);
    if (tcp_len > (uint16_t)sizeof(s_tcp_buf)) return -1;

    tcp_hdr_t *hdr = (tcp_hdr_t *)s_tcp_buf;
    hdr->src_port = htons(conn->local_port);
    hdr->dst_port = htons(conn->remote_port);
    hdr->seq      = htonl(seq);
    hdr->ack      = (flags & TCP_ACK) ? htonl(conn->rcv_nxt) : 0;
    hdr->data_off = (uint8_t)((sizeof(tcp_hdr_t) / 4) << 4);
    hdr->flags    = flags;
    hdr->window   = tcp_adv_window(conn, (flags & TCP_SYN) ? 1 : 0);
    hdr->checksum = 0;
    hdr->urgent   = 0;
    if (payload && len > 0)
        __builtin_memcpy(s_tcp_buf + sizeof(tcp_hdr_t), payload, len);

    tcp_pseudo_hdr_t ph;
    ph.src     = conn->local_ip;
    ph.dst     = conn->remote_ip;
    ph.zero    = 0;
    ph.proto   = IP_PROTO_TCP;
    ph.tcp_len = htons(tcp_len);
    uint32_t sum = 0;
    sum += net_checksum(&ph, sizeof(ph));
    sum += net_checksum(s_tcp_buf, tcp_len);
    hdr->checksum = net_checksum_finish(sum);

    return ip_send(dev, conn->remote_ip, IP_PROTO_TCP, s_tcp_buf, tcp_len);
}

/* tcp_unacked — bytes in sbuf awaiting ACK == SND.NXT - SND.UNA. */
static inline uint32_t tcp_unacked(const tcp_conn_t *c)
{
    return (c->sbuf_tail - c->sbuf_head) & (TCP_SBUF_SIZE - 1);
}

/* tcp_sbuf_space — free bytes in the retransmit buffer (reserve one byte so a
 * full ring never aliases to empty under the free-running-counter mask). */
static inline uint32_t tcp_sbuf_space(const tcp_conn_t *c)
{
    return (TCP_SBUF_SIZE - 1) - tcp_unacked(c);
}

/* tcp_retransmit_unacked — resend the oldest unacked segment (up to one MSS)
 * from sbuf at SND.UNA.  Called only from tcp_tick (PIT ISR context), which
 * holds tcp_lock: that is safe because arp_resolve does not block in ISR
 * context, so ip_send cannot park the CPU while the lock is held.  c points
 * into the static s_tcp[] table and is not freed on a single core. */
static void tcp_retransmit_unacked(netdev_t *dev, tcp_conn_t *c)
{
    uint32_t unacked = tcp_unacked(c);
    if (unacked == 0) return;
    uint16_t mss = tcp_snd_mss(c);
    uint32_t n = unacked < mss ? unacked : mss;
    uint8_t  seg[TCP_ADVMSS];
    /* Two-segment memcpy out of the power-of-two sbuf ring (was a byte loop). */
    uint32_t hoff  = c->sbuf_head & (TCP_SBUF_SIZE - 1);
    uint32_t first = TCP_SBUF_SIZE - hoff;
    if (first > n) first = n;
    __builtin_memcpy(seg, &c->sbuf[hoff], first);
    if (first < n)
        __builtin_memcpy(seg + first, &c->sbuf[0], n - first);
    tcp_send_at_seq(dev, c, TCP_PSH | TCP_ACK, c->snd_una, seg, (uint16_t)n);
}

static tcp_conn_t *tcp_find(ip4_addr_t remote_ip, uint16_t remote_port,
                             ip4_addr_t local_ip,  uint16_t local_port)
{
    int i;
    for (i = 0; i < TCP_MAX_CONNS; i++) {
        tcp_conn_t *c = &s_tcp[i];
        if (c->state       != TCP_CLOSED  &&
            c->remote_ip   == remote_ip   &&
            c->remote_port == remote_port &&
            c->local_ip    == local_ip    &&
            c->local_port  == local_port)
            return c;
    }
    return NULL;
}

static tcp_conn_t *tcp_find_listener(ip4_addr_t local_ip, uint16_t local_port)
{
    int i;
    for (i = 0; i < TCP_MAX_CONNS; i++) {
        tcp_conn_t *c = &s_tcp[i];
        if (c->state == TCP_LISTEN &&
            c->local_port == local_port &&
            (c->local_ip == 0 || c->local_ip == local_ip))
            return c;
    }
    return NULL;
}

static tcp_conn_t *tcp_alloc(void)
{
    int i;
    for (i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_tcp[i].state == TCP_CLOSED) {
            tcp_claim_slot((uint32_t)i);
            return &s_tcp[i];
        }
    }
    return NULL;
}

/* tcp_conn_abort — RST the peer and free the conn slot. Used when a handshake
 * has completed but the connection can never be delivered to accept() (the
 * listener's backlog is full or the listener vanished). Leaving such a conn
 * ESTABLISHED leaks its s_tcp[] slot forever: an ESTABLISHED conn with no
 * queued data arms no retransmit timer, so nothing ever reaps it, and the table
 * is shared with every outbound connect() — a peer completing many handshakes
 * to a slow/non-accepting listener would exhaust it (remote DoS). Acquires
 * tcp_lock; must be called OUTSIDE it (respects sock_lock > tcp_lock: callers
 * invoke it after sock_get has released sock_lock). */
static void tcp_conn_abort(uint32_t conn_id)
{
    irqflags_t fl = spin_lock_irqsave(&tcp_lock);
    if (conn_id < TCP_MAX_CONNS) {
        tcp_conn_t *c = &s_tcp[conn_id];
        if (c->state != TCP_CLOSED) {
            if (c->dev)
                tcp_send_segment(c->dev, c, TCP_RST | TCP_ACK, NULL, 0);
            c->state = TCP_CLOSED;   /* slot reclaimable by tcp_alloc */
        }
    }
    spin_unlock_irqrestore(&tcp_lock, fl);
}

/* wake_poll_waiters — wake any sys_poll / sys_epoll_wait registered on
 * sock_id's embedded poll_waiters waitq. Safe to call with NONE / freed
 * sids; sock_get returns NULL.  Must be called OUTSIDE tcp_lock to
 * respect the sock_lock > tcp_lock ordering. */
static void wake_poll_waiters(uint32_t sock_id)
{
    sock_t *s = sock_get(sock_id);
    if (s) waitq_wake_all(&s->poll_waiters);
}

void tcp_rx(netdev_t *dev, ip4_addr_t src_ip, ip4_addr_t dst_ip,
            const void *tcp_data, uint16_t len)
{
    if (len < (uint16_t)sizeof(tcp_hdr_t)) return;
    irqflags_t fl = spin_lock_irqsave(&tcp_lock);
    const tcp_hdr_t *seg = (const tcp_hdr_t *)tcp_data;

    /* Deferred socket wake/notify — collected under tcp_lock, executed after
     * release.  Avoids tcp_lock → sock_lock ordering inversion.  Sized to
     * TCP_MAX_CONNS so a worst-case packet that touches every conn can
     * still queue every wake without dropping. */
    #define TCP_RX_WAKE_MAX TCP_MAX_CONNS
    uint32_t wake_ids[TCP_RX_WAKE_MAX];
    uint32_t wake_epoll_events[TCP_RX_WAKE_MAX];
    uint32_t wake_count = 0;
    /* Deferred sock state transition (SYN_SENT → CONNECTED). */
    uint32_t connect_sock_id = SOCK_NONE;
    /* Deferred sock state transition for a FAILED connect (SYN_SENT → CLOSED):
     * a RST-refused while connecting leaves the sock in SOCK_CONNECTING unless
     * we mark it SOCK_CLOSED, so getsockopt(SO_ERROR)/poll can detect the
     * failure.  Done in the post-unlock section (sock_lock > tcp_lock). */
    uint32_t connect_fail_sock_id = SOCK_NONE;
    /* Deferred accept queue push (SYN_RCVD → ESTABLISHED). */
    uint32_t accept_listener_id = SOCK_NONE;
    uint32_t accept_conn_id = 0;

    tcp_pseudo_hdr_t ph;
    ph.src     = src_ip;
    ph.dst     = dst_ip;
    ph.zero    = 0;
    ph.proto   = IP_PROTO_TCP;
    ph.tcp_len = htons(len);
    uint32_t sum = 0;
    sum += net_checksum(&ph, sizeof(ph));
    sum += net_checksum(tcp_data, len);
    if (net_checksum_finish(sum) != 0) goto out;

    uint16_t remote_port = ntohs(seg->src_port);
    uint16_t local_port  = ntohs(seg->dst_port);
    uint8_t  hdr_bytes   = (uint8_t)((seg->data_off >> 4) * 4);
    if (hdr_bytes < sizeof(tcp_hdr_t) || hdr_bytes > len) goto out;
    uint16_t payload_len = (uint16_t)(len - hdr_bytes);
    const uint8_t *payload = (const uint8_t *)tcp_data + hdr_bytes;
    uint32_t seq = ntohl(seg->seq);
    uint32_t ack = ntohl(seg->ack);
    uint8_t  flags = seg->flags;

    tcp_conn_t *conn = tcp_find(src_ip, remote_port, dst_ip, local_port);

    if (!conn) {
        if (flags & TCP_SYN) {
            tcp_conn_t *listener = tcp_find_listener(dst_ip, local_port);
            if (!listener) {
                kmemset(&s_rst_conn, 0, sizeof(s_rst_conn));
                s_rst_conn.local_ip    = dst_ip;
                s_rst_conn.local_port  = local_port;
                s_rst_conn.remote_ip   = src_ip;
                s_rst_conn.remote_port = remote_port;
                s_rst_conn.snd_nxt     = 0;
                s_rst_conn.rcv_nxt     = seq + 1;
                tcp_send_segment(dev, &s_rst_conn, TCP_RST | TCP_ACK, NULL, 0);
                goto out;
            }
            /* Drop the SYN if this LISTENER already has too many half-open
             * connections pending (SYN-flood guard). Counting per-listener, not
             * globally: a global count let an off-box attacker starve every
             * service (incl. :22) with 32 half-opens to any one port. The peer's
             * SYN retransmit recovers once the backlog drains. tcp_lock is held
             * here, so the count is stable. */
            {
                uint32_t half_open = 0;
                for (uint32_t hi = 0; hi < TCP_MAX_CONNS; hi++)
                    if (s_tcp[hi].state == TCP_SYN_RCVD &&
                        s_tcp[hi].listener_id == listener->sock_id) half_open++;
                if (half_open >= TCP_SYN_BACKLOG_MAX) goto out;
            }
            conn = tcp_alloc();
            if (!conn) goto out;
            conn->state       = TCP_SYN_RCVD;
            conn->dev         = dev;
            conn->local_ip    = dst_ip;
            conn->local_port  = local_port;
            conn->remote_ip   = src_ip;
            conn->remote_port = remote_port;
            conn->rcv_nxt     = seq + 1;
            conn->snd_nxt     = tcp_isn();
            conn->snd_una     = conn->snd_nxt;
            conn->snd_wnd     = ntohs(seg->window);   /* SYN window: unscaled */
            conn->listener_id = listener->sock_id;
            /* Not accepted yet: no socket owns this half-open conn. Leave it
             * SOCK_NONE (not the 0 that tcp_claim_slot zeroes it to) so the
             * `sock_id != SOCK_NONE` wake guards don't fire a spurious
             * sock_wake(0)/epoll_notify(0) on slot 0. accept() assigns the
             * real id via tcp_conn_set_sock. */
            conn->sock_id     = SOCK_NONE;
            /* RFC 7323: enable window scaling on this connection only if the
             * incoming SYN carried a Window Scale option.  If so, record the
             * peer's shift (applied to its future windows) and arm our own
             * advertised shift so the SYN-ACK echoes a WScale option back.
             * Absent the option both shifts stay 0 (no scaling, <= 64 KiB). */
            {
                uint8_t psh = 0;
                const uint8_t *opts = (const uint8_t *)tcp_data + sizeof(tcp_hdr_t);
                uint32_t optlen = (uint32_t)hdr_bytes - sizeof(tcp_hdr_t);
                if (tcp_parse_wscale(opts, optlen, &psh)) {
                    conn->snd_wscale = psh;
                    conn->rcv_wscale = TCP_RCV_WSCALE;
                }
                conn->snd_mss = tcp_parse_mss(opts, optlen);
            }
            tcp_send_syn(dev, conn, TCP_SYN | TCP_ACK);
            conn->snd_nxt++;
            conn->retransmit_at    = (uint32_t)arch_get_ticks() + TCP_RTO_INITIAL;
            conn->retransmit_count = 0;
        }
        goto out;
    }

    /* Apply the negotiated window scale to the peer's advertised window.  For a
     * SYN_SENT conn this runs BEFORE the SYN-ACK is parsed below, so snd_wscale
     * is still 0 — correct, because a SYN-ACK's own window field is unscaled.
     * From the first post-handshake segment onward snd_wscale is set and the
     * peer's windows are left-shifted into the real 32-bit value. */
    conn->snd_wnd = ((uint32_t)ntohs(seg->window)) << conn->snd_wscale;

    switch (conn->state) {
    case TCP_SYN_RCVD:
        if (flags & TCP_RST) {
            /* RFC 793: a RST in SYN_RCVD aborts the half-open connection.
             * Validate the sequence number is the one we expect (== rcv_nxt,
             * the ack of the SYN-ACK we sent) so a blind off-path RST can't
             * tear down a connection it didn't help create.  Free the slot so
             * the connection table doesn't leak a half-open entry until the
             * SYN-ACK retransmit timeout. */
            if (seq == conn->rcv_nxt) {
                conn->state         = TCP_CLOSED;
                conn->retransmit_at = 0;
            }
            break;
        }
        if ((flags & TCP_ACK) && !(flags & TCP_SYN)) {
            if (ack == conn->snd_nxt) {
                conn->snd_una  = ack;
                conn->state    = TCP_ESTABLISHED;
                printk("[TCP] ESTABLISHED port=%u\n", (uint32_t)conn->local_port);
                conn->retransmit_at = 0;
                /* Defer accept() queue push + wake to after tcp_lock release */
                if (conn->listener_id != SOCK_NONE) {
                    accept_listener_id = conn->listener_id;
                    accept_conn_id = (uint32_t)(conn - s_tcp);
                    if (wake_count < TCP_RX_WAKE_MAX) {
                        wake_ids[wake_count] = conn->listener_id;
                        wake_epoll_events[wake_count] = EPOLLIN;
                        wake_count++;
                    }
                }
            }
        }
        break;

    case TCP_SYN_SENT:
        if (flags & TCP_RST) {
            /* RFC 793 p.66 / RFC 5961: in SYN_SENT, a RST is only acceptable
             * if it carries an ACK that acknowledges our SYN (ack == snd_nxt,
             * i.e. ISN+1).  Otherwise a blind off-path RST could abort the
             * connect().  A legitimate "connection refused" RST|ACK from the
             * peer always sets ack = our ISN+1, so this still works. */
            if ((flags & TCP_ACK) && ack == conn->snd_nxt) {
                /* Connection refused — close and wake connect() caller */
                conn->state = TCP_CLOSED;
                conn->retransmit_at = 0;
                if (conn->sock_id != SOCK_NONE) {
                    /* Mark the owning sock CLOSED after the lock drops so the
                     * failed connect is observable (it would otherwise stay
                     * SOCK_CONNECTING forever). */
                    connect_fail_sock_id = conn->sock_id;
                    if (wake_count < TCP_RX_WAKE_MAX) {
                        wake_ids[wake_count] = conn->sock_id;
                        wake_epoll_events[wake_count] = EPOLLERR;
                        wake_count++;
                    }
                }
            }
            break;
        }
        if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
            if (ack == conn->snd_nxt) {
                conn->snd_una  = ack;
                conn->rcv_nxt  = seq + 1;
                conn->state    = TCP_ESTABLISHED;
                /* RFC 7323: we offered window scaling in our SYN (rcv_wscale was
                 * set in tcp_connect).  Scaling is enabled in BOTH directions
                 * only if the SYN-ACK also carries a WScale option: record the
                 * peer's shift and keep ours.  If the peer omitted it, disable
                 * scaling entirely (both shifts 0) so we never advertise a scaled
                 * window the peer won't unscale.  snd_wnd was already stored
                 * unscaled above (snd_wscale was still 0); only the shift used
                 * for FUTURE segments is recorded here — the SYN-ACK's own window
                 * field is never scaled (RFC 7323 §2.2), so we must NOT re-shift
                 * the value we just stored. */
                {
                    uint8_t psh = 0;
                    const uint8_t *opts = (const uint8_t *)tcp_data + sizeof(tcp_hdr_t);
                    uint32_t optlen = (uint32_t)hdr_bytes - sizeof(tcp_hdr_t);
                    if (tcp_parse_wscale(opts, optlen, &psh)) {
                        conn->snd_wscale = psh;
                    } else {
                        conn->rcv_wscale = 0;   /* peer can't scale → neither do we */
                        conn->snd_wscale = 0;
                    }
                    conn->snd_mss = tcp_parse_mss(opts, optlen);
                }
                tcp_send_segment(dev, conn, TCP_ACK, NULL, 0);
                conn->retransmit_at = 0;
                /* Defer connect() wake + state transition */
                if (conn->sock_id != SOCK_NONE) {
                    connect_sock_id = conn->sock_id;
                    if (wake_count < TCP_RX_WAKE_MAX) {
                        wake_ids[wake_count] = conn->sock_id;
                        wake_epoll_events[wake_count] = EPOLLOUT;
                        wake_count++;
                    }
                }
            }
        }
        break;

    case TCP_ESTABLISHED:
        if (flags & TCP_ACK) {
            /* RFC 793 §3.9 / RFC 5961 §5: a valid ACK acks data we actually
             * sent — SND.UNA < SEG.ACK <= SND.NXT. An ACK above SND.NXT
             * acknowledges bytes we never transmitted (a confused peer or a
             * blind off-path injection); per RFC 793 the segment is
             * unacceptable, so send a current ACK to resynchronise the sender
             * and drop the rest of it (no data/RST/FIN processing). An ACK at
             * or below SND.UNA is an old/duplicate cumulative ACK: ignore the
             * ack field but keep processing the segment (it may carry data or a
             * FIN). Only an in-range ACK advances SND.UNA. */
            if (seq_gt(ack, conn->snd_nxt)) {
                tcp_send_segment(dev, conn, TCP_ACK, NULL, 0);
                break;
            }
            if (seq_gt(ack, conn->snd_una)) {
                /* Free newly-acked bytes from the retransmit buffer and slide
                 * SND.UNA forward.  sbuf_head tracks SND.UNA, so advancing it
                 * by the same delta keeps tcp_unacked() == SND.NXT - SND.UNA.
                 * Cap the slide at the bytes actually buffered so a peer acking
                 * our FIN (which is +1 beyond the last data byte and is NOT in
                 * sbuf) can't over-advance sbuf_head past sbuf_tail. */
                uint32_t acked   = ack - conn->snd_una;
                uint32_t buffered = tcp_unacked(conn);
                uint32_t slide   = acked < buffered ? acked : buffered;
                conn->sbuf_head += slide;
                conn->snd_una    = ack;
                /* Re-arm or stop the retransmit timer based on whether any
                 * data remains unacked.  Without this, the timer kept firing
                 * on a fully-acked idle connection and escalated to a RST that
                 * tore down healthy long-lived connections after ~7 s. */
                if (tcp_unacked(conn) == 0) {
                    conn->retransmit_at    = 0;
                    conn->retransmit_count = 0;
                } else {
                    /* Forward progress: reset backoff and re-arm. */
                    conn->retransmit_at    = (uint32_t)arch_get_ticks()
                                             + TCP_RTO_INITIAL;
                    conn->retransmit_count = 0;
                }
                /* The ACK drained the send ring: wake a sender blocked on
                 * send-space (a write > TCP_SBUF_SIZE) and any POLLOUT poller. */
                if (slide > 0 && conn->sock_id != SOCK_NONE &&
                    wake_count < TCP_RX_WAKE_MAX) {
                    wake_ids[wake_count] = conn->sock_id;
                    wake_epoll_events[wake_count] = EPOLLOUT;
                    wake_count++;
                }
            }
        }
        if (payload_len > 0) {
            if (seq == conn->rcv_nxt) {
                /* In-order data. Reserve one byte: max usable ring capacity is
                 * TCP_RBUF_SIZE - 1. Without this, a segment that fills the ring
                 * to EXACTLY TCP_RBUF_SIZE bytes makes used mask to 0 (aliases
                 * empty), and subsequent writes overwrite unread data while
                 * rcv_nxt advances (silent stream corruption). Matches the
                 * advertised-window calc in tcp_send_segment and the AF_UNIX
                 * reserve-one-byte scheme. */
                uint32_t used  = (conn->rbuf_tail - conn->rbuf_head) & (TCP_RBUF_SIZE - 1);
                uint32_t space = (TCP_RBUF_SIZE - 1) - used;
                if (payload_len <= space) {
                    /* Two-segment memcpy into the power-of-two ring (was a byte
                     * loop). rbuf_tail stays free-running; only the physical
                     * index wraps. payload is a kernel buffer (RX frame copy). */
                    uint32_t toff  = conn->rbuf_tail & (TCP_RBUF_SIZE - 1);
                    uint32_t first = TCP_RBUF_SIZE - toff;
                    if (first > payload_len) first = payload_len;
                    __builtin_memcpy(&conn->rbuf[toff], payload, first);
                    if (first < payload_len)
                        __builtin_memcpy(&conn->rbuf[0], payload + first,
                                         payload_len - first);
                    conn->rbuf_tail += payload_len;
                    conn->rcv_nxt += payload_len;
                    /* Defer recv() wake */
                    if (conn->sock_id != SOCK_NONE &&
                        wake_count < TCP_RX_WAKE_MAX) {
                        wake_ids[wake_count] = conn->sock_id;
                        wake_epoll_events[wake_count] = EPOLLIN;
                        wake_count++;
                    }
                }
            }
            /* ACK every data segment. In-order data advances the cumulative ACK;
             * an out-of-order (gap) or already-received (retransmitted) segment
             * yields a duplicate ACK at rcv_nxt, which drives the sender's
             * fast-retransmit instead of forcing it to wait out an RTO. We keep
             * no reassembly queue, so out-of-order payload is dropped and later
             * retransmitted — the dup-ACK just makes that prompt. Previously the
             * ACK was nested under the in-order test, so a lost/reordered
             * segment was met with silence. */
            tcp_send_segment(dev, conn, TCP_ACK, NULL, 0);
        }
        if (flags & TCP_RST) {
            /* RFC 5961 §3.2: in ESTABLISHED only honor a RST whose sequence
             * number falls inside the current receive window; otherwise an
             * off-path attacker with the right 4-tuple could tear down the
             * connection with a blind RST.  recv_window is the same value we
             * advertise (free rbuf space, reserve-one-byte), so a legitimate
             * peer's RST (seq == rcv_nxt) is always in-window and still resets.
             * Out-of-window RSTs are dropped (minimal safe variant — no
             * challenge ACK). */
            uint32_t rused = (conn->rbuf_tail - conn->rbuf_head) & (TCP_RBUF_SIZE - 1);
            uint32_t recv_window = (TCP_RBUF_SIZE - 1) - rused;
            if (seq_ge(seq, conn->rcv_nxt) &&
                seq_lt(seq, conn->rcv_nxt + recv_window)) {
                conn->state = TCP_CLOSED;
                if (conn->sock_id != SOCK_NONE &&
                    wake_count < TCP_RX_WAKE_MAX) {
                    wake_ids[wake_count] = conn->sock_id;
                    wake_epoll_events[wake_count] = 0; /* wake only, no epoll */
                    wake_count++;
                }
            }
            break;
        }
        if (flags & TCP_FIN) {
            conn->rcv_nxt++;
            conn->state = TCP_CLOSE_WAIT;
            tcp_send_segment(dev, conn, TCP_ACK, NULL, 0);
            /* Defer recv() EOF/hangup wake */
            if (conn->sock_id != SOCK_NONE &&
                wake_count < TCP_RX_WAKE_MAX) {
                wake_ids[wake_count] = conn->sock_id;
                wake_epoll_events[wake_count] = EPOLLHUP;
                wake_count++;
            }
        }
        break;

    case TCP_CLOSE_WAIT:
        /* Half-closed: the peer FIN'd its send side but we may still be
         * sending.  Process ACKs so our outstanding data is freed from sbuf and
         * the retransmit timer is released/re-armed — otherwise a connection
         * that sent data and then saw the peer's FIN would retransmit the
         * already-acked data forever and eventually RST.  A RST here aborts. */
        if (flags & TCP_RST) {
            uint32_t rused = (conn->rbuf_tail - conn->rbuf_head) & (TCP_RBUF_SIZE - 1);
            uint32_t recv_window = (TCP_RBUF_SIZE - 1) - rused;
            if (seq_ge(seq, conn->rcv_nxt) &&
                seq_lt(seq, conn->rcv_nxt + recv_window)) {
                conn->state            = TCP_CLOSED;
                conn->retransmit_at    = 0;
                conn->retransmit_count = 0;
                if (conn->sock_id != SOCK_NONE &&
                    wake_count < TCP_RX_WAKE_MAX) {
                    wake_ids[wake_count] = conn->sock_id;
                    wake_epoll_events[wake_count] = 0;
                    wake_count++;
                }
            }
            break;
        }
        if (flags & TCP_ACK) {
            if (seq_gt(ack, conn->snd_nxt)) {
                tcp_send_segment(dev, conn, TCP_ACK, NULL, 0);
                break;
            }
            if (seq_gt(ack, conn->snd_una)) {
                uint32_t acked    = ack - conn->snd_una;
                uint32_t buffered = tcp_unacked(conn);
                uint32_t slide    = acked < buffered ? acked : buffered;
                conn->sbuf_head  += slide;
                conn->snd_una     = ack;
                if (tcp_unacked(conn) == 0) {
                    conn->retransmit_at    = 0;
                    conn->retransmit_count = 0;
                } else {
                    conn->retransmit_at    = (uint32_t)arch_get_ticks()
                                             + TCP_RTO_INITIAL;
                    conn->retransmit_count = 0;
                }
            }
        }
        break;

    case TCP_FIN_WAIT_1:
        if (flags & TCP_ACK) {
            /* Free any acked data and slide SND.UNA forward.  snd_nxt here is
             * one past our FIN, so our FIN is fully acked only when
             * ack == snd_nxt.  A peer may ack our remaining data first
             * (ack == snd_nxt-1) and the FIN in a later segment — the previous
             * exact-match-only test got stuck retransmitting data in that case.
             * Cap the sbuf slide at buffered bytes so acking the FIN (which is
             * not in sbuf) can't over-advance sbuf_head. */
            if (seq_gt(ack, conn->snd_una) && !seq_gt(ack, conn->snd_nxt)) {
                uint32_t acked    = ack - conn->snd_una;
                uint32_t buffered = tcp_unacked(conn);
                uint32_t slide    = acked < buffered ? acked : buffered;
                conn->sbuf_head  += slide;
                conn->snd_una     = ack;
            }
            if (ack == conn->snd_nxt) {
                /* Our FIN is acknowledged. */
                conn->retransmit_at    = 0;
                conn->retransmit_count = 0;
                if (flags & TCP_FIN) {
                    /* This segment both ACKs our FIN and carries the peer's
                     * FIN → straight to TIME_WAIT (not CLOSING; CLOSING is only
                     * for when our FIN is still unacked).  Ack the peer's FIN
                     * and start the 2MSL timer. */
                    conn->rcv_nxt++;
                    conn->state       = TCP_TIME_WAIT;
                    conn->timewait_at = (uint32_t)arch_get_ticks()
                                        + TCP_TIMEWAIT_TICKS;
                    tcp_send_segment(dev, conn, TCP_ACK, NULL, 0);
                    if (conn->sock_id != SOCK_NONE &&
                        wake_count < TCP_RX_WAKE_MAX) {
                        wake_ids[wake_count] = conn->sock_id;
                        wake_epoll_events[wake_count] = EPOLLHUP;
                        wake_count++;
                    }
                } else {
                    conn->state = TCP_FIN_WAIT_2;
                }
                break;
            }
        }
        if (flags & TCP_FIN) {
            /* Peer's FIN arrived but our FIN is NOT yet acked (simultaneous
             * close) → CLOSING.  We remain responsible for retransmitting our
             * unacked FIN until it is acked, at which point CLOSING →
             * TIME_WAIT. */
            conn->rcv_nxt++;
            conn->state = TCP_CLOSING;
            tcp_send_segment(dev, conn, TCP_ACK, NULL, 0);
        }
        break;

    case TCP_FIN_WAIT_2:
        if (flags & TCP_FIN) {
            conn->rcv_nxt++;
            conn->state       = TCP_TIME_WAIT;
            conn->timewait_at = (uint32_t)arch_get_ticks() + TCP_TIMEWAIT_TICKS;
            tcp_send_segment(dev, conn, TCP_ACK, NULL, 0);
            if (conn->sock_id != SOCK_NONE &&
                wake_count < TCP_RX_WAKE_MAX) {
                wake_ids[wake_count] = conn->sock_id;
                wake_epoll_events[wake_count] = EPOLLHUP;
                wake_count++;
            }
        }
        break;

    case TCP_CLOSING:
        /* RFC 793: CLOSING → TIME_WAIT only when our FIN is acknowledged
         * (ack == snd_nxt, one past the FIN).  A bare data/dup ACK that does
         * not cover our FIN must not advance the state, or we'd stop
         * retransmitting an unacked FIN. */
        if ((flags & TCP_ACK) && ack == conn->snd_nxt) {
            conn->state            = TCP_TIME_WAIT;
            conn->timewait_at      = (uint32_t)arch_get_ticks() + TCP_TIMEWAIT_TICKS;
            conn->retransmit_at    = 0;
            conn->retransmit_count = 0;
            /* Wake any sys_poll / sys_epoll_wait watcher (POLLHUP). */
            if (conn->sock_id != SOCK_NONE &&
                wake_count < TCP_RX_WAKE_MAX) {
                wake_ids[wake_count] = conn->sock_id;
                wake_epoll_events[wake_count] = EPOLLHUP;
                wake_count++;
            }
        }
        break;

    case TCP_LAST_ACK:
        /* RFC 793: LAST_ACK → CLOSED only when our FIN is acknowledged. */
        if ((flags & TCP_ACK) && ack == conn->snd_nxt) {
            conn->state            = TCP_CLOSED;
            conn->retransmit_at    = 0;
            conn->retransmit_count = 0;
            /* Wake any sys_poll / sys_epoll_wait watcher (POLLHUP). */
            if (conn->sock_id != SOCK_NONE &&
                wake_count < TCP_RX_WAKE_MAX) {
                wake_ids[wake_count] = conn->sock_id;
                wake_epoll_events[wake_count] = EPOLLHUP;
                wake_count++;
            }
        }
        break;

    default:
        break;
    }
out:
    spin_unlock_irqrestore(&tcp_lock, fl);

    /* ── Deferred socket operations (outside tcp_lock) ───────────────────
     * sock_get/sock_wake acquire sock_lock.  Calling them under tcp_lock
     * would violate the lock ordering (sock_lock > tcp_lock). */

    /* SYN_SENT → CONNECTED: update sock state before waking. */
    if (connect_sock_id != SOCK_NONE) {
        sock_t *sk = sock_get(connect_sock_id);
        if (sk) sk->state = SOCK_CONNECTED;
    }

    /* SYN_SENT → CLOSED (connect refused by RST): mark the sock CLOSED so
     * getsockopt(SO_ERROR)/poll can observe the failure.  The guard
     * (state == SOCK_CONNECTING) avoids clobbering a sock that has since
     * been reused or closed for another purpose. */
    if (connect_fail_sock_id != SOCK_NONE) {
        sock_t *sk = sock_get(connect_fail_sock_id);
        if (sk && sk->state == SOCK_CONNECTING) sk->state = SOCK_CLOSED;
    }

    /* Accept queue push for SYN_RCVD → ESTABLISHED. */
    if (accept_listener_id != SOCK_NONE) {
        sock_t *ls = sock_get(accept_listener_id);
        int queued = 0;
        if (ls) {
            uint8_t next_tail = (uint8_t)((ls->accept_tail + 1) & 7);
            if (next_tail != ls->accept_head) {
                ls->accept_queue[ls->accept_tail] = accept_conn_id;
                ls->accept_tail = next_tail;
                queued = 1;
            }
        }
        /* Backlog full or listener gone: abort instead of leaking an ESTABLISHED
         * slot nobody will ever accept (see tcp_conn_abort). sock_get has already
         * released sock_lock, so taking tcp_lock here honors sock_lock > tcp_lock. */
        if (!queued)
            tcp_conn_abort(accept_conn_id);
    }

    {
        uint32_t w;
        for (w = 0; w < wake_count; w++) {
            sock_wake(wake_ids[w]);
            if (wake_epoll_events[w] != 0)
                epoll_notify(wake_ids[w], wake_epoll_events[w]);
            /* Wake any sys_poll / sys_epoll_wait waiters registered on
             * this socket via its embedded poll_waiters waitq. Every
             * wake_ids entry above corresponds to a pollable state
             * change (rx data, accept ready, connect complete, RST,
             * FIN/CLOSE_WAIT, FIN_WAIT_2/CLOSING/LAST_ACK). */
            wake_poll_waiters(wake_ids[w]);
        }
    }
    #undef TCP_RX_WAKE_MAX
}

void tcp_tick(void)
{
    irqflags_t fl = spin_lock_irqsave(&tcp_lock);
    uint32_t now = (uint32_t)arch_get_ticks();
    /* Deferred poll_waiters wakes — collected under tcp_lock, fired after
     * release to avoid the tcp_lock → sock_lock ordering inversion.
     * Sized to TCP_MAX_CONNS so a worst-case tick where every conn
     * expires TIME_WAIT in the same 10ms can still queue every wake. */
    #define TCP_TICK_WAKE_MAX TCP_MAX_CONNS
    uint32_t tick_wake_ids[TCP_TICK_WAKE_MAX];
    uint32_t tick_wake_count = 0;
    int i;
    for (i = 0; i < TCP_MAX_CONNS; i++) {
        tcp_conn_t *c = &s_tcp[i];
        if (c->state == TCP_CLOSED) continue;

        if (c->state == TCP_TIME_WAIT) {
            if ((int32_t)(now - c->timewait_at) >= 0) {
                c->state = TCP_CLOSED;
                /* Wake any sys_poll / sys_epoll_wait watcher. */
                if (c->sock_id != SOCK_NONE &&
                    tick_wake_count < TCP_TICK_WAKE_MAX) {
                    tick_wake_ids[tick_wake_count++] = c->sock_id;
                }
            }
            continue;
        }

        if (c->retransmit_at == 0) continue;
        if ((int32_t)(now - c->retransmit_at) < 0) continue;

        /* Zero-window persist: if we have unacked data but the peer has
         * advertised a zero window, our "retransmits" are really zero-window
         * probes (RFC 1122 §4.2.2.17).  These must NOT count toward the
         * connection-abort limit — a receiver that is merely slow to drain its
         * buffer must not have its connection torn down.  Keep probing
         * indefinitely with a capped interval and do not escalate to RST. */
        if (c->snd_wnd == 0 && tcp_unacked(c) > 0 &&
            (c->state == TCP_ESTABLISHED || c->state == TCP_CLOSE_WAIT)) {
            c->retransmit_at = now + TCP_RTO_MAX;
            tcp_retransmit_unacked(c->dev, c);   /* probe — elicits a window update */
            continue;
        }

        if (c->retransmit_count >= TCP_RETRANSMIT_MAX) {
            /* Maximum retransmits — RST best-effort and close.
             * Wake any blocked connect/send caller so it gets an error. */
            tcp_send_segment(c->dev, c, TCP_RST, NULL, 0);
            uint32_t timeout_sid = c->sock_id;
            c->state = TCP_CLOSED;
            if (timeout_sid != SOCK_NONE) {
                spin_unlock_irqrestore(&tcp_lock, fl);
                /* Mark the owning sock CLOSED so a connect() that timed out
                 * (unreachable host: retransmit limit hit with no reply) is
                 * observable via getsockopt(SO_ERROR)/poll instead of being
                 * stuck in SOCK_CONNECTING forever.  sock_get acquires
                 * sock_lock, so this is correctly done after dropping tcp_lock
                 * (sock_lock > tcp_lock).  The guard avoids clobbering a sock
                 * that has since been reused/closed. */
                {
                    sock_t *sk = sock_get(timeout_sid);
                    if (sk && sk->state == SOCK_CONNECTING)
                        sk->state = SOCK_CLOSED;
                }
                sock_wake(timeout_sid);
                /* Wake poll_waiters — connection died, plus any
                 * pending TIME_WAIT-expiry wakes queued earlier. */
                wake_poll_waiters(timeout_sid);
                {
                    uint32_t w;
                    for (w = 0; w < tick_wake_count; w++)
                        wake_poll_waiters(tick_wake_ids[w]);
                }
                return;  /* bail — we released the lock */
            }
            continue;
        }

        c->retransmit_count++;
        uint32_t rto = TCP_RTO_INITIAL << c->retransmit_count;
        if (rto > TCP_RTO_MAX) rto = TCP_RTO_MAX;
        c->retransmit_at = now + rto;

        /* Retransmit per state.  tcp_tick runs in the PIT ISR with interrupts
         * disabled; arp_resolve returns immediately (no blocking) from ISR
         * context, so tcp_send_*  is safe to call under tcp_lock here (unlike
         * the syscall-context senders).  Data retransmit reads from sbuf and
         * re-sends the oldest unacked MSS-worth at SND.UNA; SYN/FIN states
         * resend their control segment.  Previously only SYN/SYN-ACK were
         * retransmitted, so lost DATA was never resent (silent truncation) and
         * the climbing retransmit_count eventually RST'd a healthy connection. */
        if (c->state == TCP_SYN_RCVD)
            tcp_send_syn(c->dev, c, TCP_SYN | TCP_ACK);   /* re-carry MSS/WScale */
        else if (c->state == TCP_SYN_SENT)
            tcp_send_syn(c->dev, c, TCP_SYN);             /* re-carry MSS/WScale */
        else if (tcp_unacked(c) > 0)
            tcp_retransmit_unacked(c->dev, c);
        else if (c->state == TCP_FIN_WAIT_1 || c->state == TCP_LAST_ACK ||
                 c->state == TCP_CLOSING)
            /* Our FIN is unacked (it consumes one sequence number but lives in
             * no buffer).  Resend it. snd_nxt was already advanced past the
             * FIN, so stamp it at snd_nxt-1. */
            tcp_send_at_seq(c->dev, c, TCP_FIN | TCP_ACK, c->snd_nxt - 1,
                            NULL, 0);
    }
    spin_unlock_irqrestore(&tcp_lock, fl);

    /* Fire deferred poll_waiters wakes outside tcp_lock. */
    {
        uint32_t w;
        for (w = 0; w < tick_wake_count; w++)
            wake_poll_waiters(tick_wake_ids[w]);
    }
    #undef TCP_TICK_WAKE_MAX
}

/* ── Socket-layer helpers (Phase 26) ─────────────────────────────────────── */

/* tcp_listen: register a listening socket at port. */
int
tcp_listen(uint16_t port, uint32_t sock_id)
{
    irqflags_t fl = spin_lock_irqsave(&tcp_lock);
    uint32_t i;
    for (i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_tcp[i].state == TCP_CLOSED) {
            tcp_claim_slot(i);
            s_tcp[i].state      = TCP_LISTEN;
            s_tcp[i].local_port = port;
            s_tcp[i].sock_id    = sock_id;
            spin_unlock_irqrestore(&tcp_lock, fl);
            return 0;
        }
    }
    spin_unlock_irqrestore(&tcp_lock, fl);
    return -1;
}

/* tcp_connect: send SYN, allocate conn. Returns 0 on success. */
int
tcp_connect(uint32_t sock_id, ip4_addr_t dst_ip, uint16_t dst_port,
            uint32_t *conn_id_out)
{
    extern netdev_t *netdev_get(const char *name);
    irqflags_t fl = spin_lock_irqsave(&tcp_lock);
    uint32_t i;
    for (i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_tcp[i].state == TCP_CLOSED) {
            tcp_claim_slot(i);
            s_tcp[i].state       = TCP_SYN_SENT;
            net_get_config(&s_tcp[i].local_ip, (ip4_addr_t *)0, (ip4_addr_t *)0);
            /* Loopback: use 127.0.0.1 as local IP (net_get_config returns
             * 0.0.0.0 when no NIC is configured). */
            if ((ntohl(dst_ip) >> 24) == 127)
                s_tcp[i].local_ip = dst_ip;  /* 127.0.0.1 */
            else if (s_tcp[i].local_ip == 0 && dst_ip == s_tcp[i].local_ip)
                s_tcp[i].local_ip = dst_ip;  /* self-connect */
            s_tcp[i].local_port  = (uint16_t)(49152u + (arch_get_ticks() & 0x3FFFu));
            s_tcp[i].remote_ip   = dst_ip;
            s_tcp[i].remote_port = dst_port;
            s_tcp[i].sock_id     = sock_id;
            s_tcp[i].snd_nxt     = tcp_isn();
            s_tcp[i].snd_una     = s_tcp[i].snd_nxt;
            /* RFC 7323: offer window scaling on our SYN.  rcv_wscale set now so
             * tcp_send_syn emits the WScale option; the SYN-ACK handler keeps it
             * if the peer reciprocates, else resets it to 0 (no scaling). */
            s_tcp[i].rcv_wscale  = TCP_RCV_WSCALE;
            *conn_id_out = i;
            netdev_t *dev = netdev_get("eth0");
            s_tcp[i].dev = dev;
            /* Set retransmit far enough in the future that tcp_tick won't
             * fire before we send the SYN.  We must release tcp_lock before
             * tcp_send_segment because ip_send → arp_resolve may block. */
            s_tcp[i].retransmit_at = (uint32_t)arch_get_ticks() + TCP_RTO_INITIAL + 200;
            spin_unlock_irqrestore(&tcp_lock, fl);
            tcp_send_syn(dev, &s_tcp[i], TCP_SYN);
            /* Increment snd_nxt AFTER sending the SYN — the SYN must go out
             * with seq=ISN (our initial snd_nxt), and snd_nxt then advances to
             * ISN+1 so the SYN_SENT handler matches ack=ISN+1 from the remote.
             * Bug: this was before tcp_send_segment, causing SYN seq=ISN+1 and
             * the remote's ack=ISN+2 to never match snd_nxt=ISN+1. */
            s_tcp[i].snd_nxt++;
            s_tcp[i].retransmit_at = (uint32_t)arch_get_ticks() + TCP_RTO_INITIAL;
            return 0;
        }
    }
    spin_unlock_irqrestore(&tcp_lock, fl);
    return -1;
}

/* tcp_conn_recv: read up to max_len bytes from rbuf. max_len=0 returns available count. */
int
tcp_conn_recv(uint32_t conn_id, void *dst, uint16_t max_len)
{
    irqflags_t fl = spin_lock_irqsave(&tcp_lock);
    if (conn_id >= TCP_MAX_CONNS) {
        spin_unlock_irqrestore(&tcp_lock, fl);
        return -1;
    }
    tcp_conn_t *c = &s_tcp[conn_id];
    /* TCP_RBUF_SIZE is a power of two, so the free-running rbuf_tail/rbuf_head
     * counters mask to the live byte count — identical form to the `used`
     * computations in tcp_rx and the window-update math below. */
    uint32_t avail = (c->rbuf_tail - c->rbuf_head) & (TCP_RBUF_SIZE - 1);
    if (avail == 0) {
        int ret;
        if (c->state == TCP_CLOSE_WAIT || c->state == TCP_CLOSED
            || c->state == TCP_TIME_WAIT)
            ret = 0;  /* EOF — FIN received, no more data */
        else
            ret = -11;  /* EAGAIN — buffer empty, connection alive */
        spin_unlock_irqrestore(&tcp_lock, fl);
        return ret;
    }
    if (max_len == 0) {
        spin_unlock_irqrestore(&tcp_lock, fl);
        return (int)avail;  /* peek: report available bytes */
    }
    uint32_t n = avail < max_len ? avail : max_len;
    /* Two-segment memcpy out of the power-of-two ring (was a byte loop).
     * rbuf_head stays free-running; only the physical index wraps. dst is a
     * kernel bounce buffer (sys_socket copies it to user afterwards). */
    uint8_t *d = (uint8_t *)dst;
    uint32_t hoff  = c->rbuf_head & (TCP_RBUF_SIZE - 1);
    uint32_t first = TCP_RBUF_SIZE - hoff;
    if (first > n) first = n;
    __builtin_memcpy(d, &c->rbuf[hoff], first);
    if (first < n)
        __builtin_memcpy(d + first, &c->rbuf[0], n - first);
    c->rbuf_head += n;
    /* SWS-avoidance window update (see TCP_RX_WUPDATE_THRESH): draining n bytes
     * reopened the receive window by n. If that crossed from below one MSS to at
     * least one MSS, the sender may be parked on a closed/tiny window with
     * nothing to wake it (we only ACK from the inbound-segment path). Send a
     * bare window-update ACK so it resumes immediately instead of waiting out a
     * zero-window probe / RTO — the fix for large downloads truncating when the
     * app (curl → ext2) lags the wire. tcp_send_segment must run WITHOUT
     * tcp_lock (its ip_send → arp path can block with interrupts enabled;
     * holding the lock there deadlocks tcp_tick — see tcp_conn_send), so decide
     * under the lock, then send after unlocking. c points into static s_tcp[]
     * and is not freed under us on a single core. */
    uint32_t used_after = (c->rbuf_tail - c->rbuf_head) & (TCP_RBUF_SIZE - 1);
    uint32_t win_after  = (TCP_RBUF_SIZE - 1) - used_after;
    uint32_t win_before = win_after - n;   /* draining n freed exactly n bytes */
    netdev_t *wu_dev = NULL;
    if (c->state == TCP_ESTABLISHED &&
        win_before < TCP_RX_WUPDATE_THRESH && win_after >= TCP_RX_WUPDATE_THRESH)
        wu_dev = c->dev;
    spin_unlock_irqrestore(&tcp_lock, fl);
    if (wu_dev)
        tcp_send_segment(wu_dev, c, TCP_ACK, NULL, 0);
    return (int)n;
}

/* tcp_conn_send: buffer up to `len` bytes into the retransmit ring and send
 * them (segmented to one MSS each).  Returns the number of bytes accepted
 * (>0), 0 if no buffer/window space is currently available (caller treats as
 * EAGAIN / would-block), or a negative errno.
 *
 * Bytes are copied into sbuf BEFORE transmission so tcp_tick can retransmit
 * them if they are lost — previously the data was sent once and never kept, so
 * any loss silently truncated the stream (no retransmit) and the armed timer
 * eventually RST'd the connection.  The caller (sys_sendto) loops on partial
 * counts, so a short write here is correct POSIX behaviour. */
/* tcp_conn_send_ready: classify the send side for a blocking writer.
 *   1  = send-buffer space available (a tcp_conn_send will accept data)
 *   0  = no space right now — caller should block until an ACK drains the ring
 *  -1  = connection not in a sendable state — caller should error (EPIPE)
 * Used by the socket layer's blocking send so a write larger than
 * TCP_SBUF_SIZE waits for ACKs instead of truncating. */
int
tcp_conn_send_ready(uint32_t conn_id)
{
    irqflags_t fl = spin_lock_irqsave(&tcp_lock);
    if (conn_id >= TCP_MAX_CONNS) {
        spin_unlock_irqrestore(&tcp_lock, fl);
        return -1;
    }
    tcp_conn_t *c = &s_tcp[conn_id];
    if (c->state != TCP_ESTABLISHED && c->state != TCP_CLOSE_WAIT) {
        spin_unlock_irqrestore(&tcp_lock, fl);
        return -1;
    }
    int ready = tcp_sbuf_space(c) > 0 ? 1 : 0;
    spin_unlock_irqrestore(&tcp_lock, fl);
    return ready;
}

int
tcp_conn_send(uint32_t conn_id, const void *data, uint16_t len)
{
    irqflags_t fl = spin_lock_irqsave(&tcp_lock);
    if (conn_id >= TCP_MAX_CONNS) {
        spin_unlock_irqrestore(&tcp_lock, fl);
        return -1;
    }
    tcp_conn_t *c = &s_tcp[conn_id];
    /* ESTABLISHED and CLOSE_WAIT both permit sending: in CLOSE_WAIT the peer
     * has closed its send side (we got its FIN) but our send side is still
     * open until we close() — POSIX half-close.  All other states (closing,
     * closed, listen, syn-*) reject with EPIPE. */
    if (c->state != TCP_ESTABLISHED && c->state != TCP_CLOSE_WAIT) {
        spin_unlock_irqrestore(&tcp_lock, fl);
        return -32;  /* EPIPE */
    }
    if (len == 0) {
        spin_unlock_irqrestore(&tcp_lock, fl);
        return 0;
    }

    /* Acceptance is gated only by retransmit-ring space — NOT by the peer's
     * window.  Gating acceptance on a transiently-closed window would make this
     * return 0, which sys_sendto turns into EPIPE on the first chunk (it has no
     * blocking/retry path for us).  Instead we buffer what the ring can hold and
     * let the peer window throttle what goes on the WIRE; anything held back is
     * flushed by the retransmit timer once the window reopens (the ESTABLISHED
     * ACK handler re-arms the timer as snd_una advances on a window update).
     * accept is also clamped to the snapshot size; sys_sendto already chunks at
     * 1460, and it loops on partial returns, so a short write here is correct
     * POSIX behaviour. */
    const uint8_t *src = (const uint8_t *)data;
    uint8_t  snap[1460];
    uint32_t accept = len;
    uint32_t space  = tcp_sbuf_space(c);
    if (accept > space)         accept = space;
    if (accept > sizeof(snap))  accept = sizeof(snap);
    if (accept == 0) {
        /* Ring momentarily full (peer not acking).  Report 0; the caller
         * returns a short count if it already sent some, otherwise EPIPE —
         * acceptable for this degenerate backpressure case without a blocking
         * path we cannot add from here. */
        spin_unlock_irqrestore(&tcp_lock, fl);
        return 0;
    }

    /* Copy accepted bytes into sbuf at the tail (== SND.NXT) and advance both
     * the ring tail and SND.NXT by the same amount, preserving
     * tcp_unacked() == SND.NXT - SND.UNA.  Stage them in a local snapshot so the
     * transmit below can run after we drop the lock without racing a concurrent
     * ACK that advances sbuf_head past these bytes. */
    uint32_t send_seq = c->snd_nxt;
    /* Two-segment memcpy into the power-of-two sbuf ring (was a byte loop), plus
     * a contiguous copy into the local snapshot. src is kernel-staged (sndbuf in
     * sock_stream_send); sbuf_tail stays free-running, only the index wraps. */
    uint32_t toff  = c->sbuf_tail & (TCP_SBUF_SIZE - 1);
    uint32_t first = TCP_SBUF_SIZE - toff;
    if (first > accept) first = accept;
    __builtin_memcpy(&c->sbuf[toff], src, first);
    if (first < accept)
        __builtin_memcpy(&c->sbuf[0], src + first, accept - first);
    __builtin_memcpy(snap, src, accept);
    c->sbuf_tail += accept;
    c->snd_nxt += accept;

    /* Decide how many of the just-accepted bytes may go on the wire NOW,
     * bounded by the peer's advertised window minus what was already in flight
     * before this call.  The remainder stays in sbuf and is sent by the
     * retransmit timer when the window opens. */
    uint32_t prev_inflight = (send_seq - c->snd_una);  /* in flight before us */
    uint32_t wnd = c->snd_wnd;
    uint32_t sendable;
    if (wnd > prev_inflight) {
        sendable = wnd - prev_inflight;
        if (sendable > accept) sendable = accept;
    } else {
        sendable = 0;  /* window already full — timer will flush */
    }
    netdev_t *dev = c->dev;
    /* Arm the retransmit timer for the now-outstanding data. */
    c->retransmit_at    = (uint32_t)arch_get_ticks() + TCP_RTO_INITIAL;
    c->retransmit_count = 0;

    /* Release tcp_lock before transmitting: ip_send → arp_resolve may block
     * with `sti; hlt; cli` in syscall context; holding tcp_lock across that
     * re-enables interrupts inside the irqsave critical section and the PIT ISR
     * → tcp_tick → spin_lock_irqsave(&tcp_lock) then spins forever on the lock
     * whose owner is parked in hlt.  The data is already in sbuf, so even if a
     * transmit drops (or is withheld by the window), tcp_tick will (re)send it.
     * c lives in static s_tcp[] and is not freed under us on a single core. */
    spin_unlock_irqrestore(&tcp_lock, fl);

    /* Transmit the window-permitted prefix from the lock-free snapshot,
     * segmented to one MSS per packet. */
    uint32_t off = 0;
    uint16_t mss = tcp_snd_mss(c);
    while (off < sendable) {
        uint32_t chunk = sendable - off;
        if (chunk > mss) chunk = mss;
        tcp_send_at_seq(dev, c, TCP_PSH | TCP_ACK, send_seq + off,
                        snap + off, (uint16_t)chunk);
        off += chunk;
    }
    return (int)accept;
}

/* tcp_conn_close: send FIN (active close from ESTABLISHED, or passive close
 * from CLOSE_WAIT).  No-op in any other state. */
int
tcp_conn_close(uint32_t conn_id)
{
    irqflags_t fl = spin_lock_irqsave(&tcp_lock);
    if (conn_id >= TCP_MAX_CONNS) {
        spin_unlock_irqrestore(&tcp_lock, fl);
        return -1;
    }
    tcp_conn_t *c = &s_tcp[conn_id];
    /* Active close (ESTABLISHED → FIN_WAIT_1) and passive close
     * (CLOSE_WAIT → LAST_ACK) both send a FIN at SND.NXT and bump it by one.
     * The old code handled only ESTABLISHED, so a server that closes after the
     * client's FIN sat in CLOSE_WAIT forever (half-open leak) and never sent
     * its own FIN.  We stamp the FIN explicitly at snd_nxt so the +1 we apply
     * here matches what the FIN-retransmit path (snd_nxt-1) and the peer's ACK
     * accounting expect.  tcp_send_* must run WITHOUT tcp_lock in syscall
     * context (ip_send → arp may block; holding the lock there deadlocks
     * tcp_tick — see tcp_conn_send), so decide and mutate state under the lock,
     * then send after unlocking.  c lives in static s_tcp[]. */
    netdev_t *dev    = NULL;
    uint32_t  finseq = 0;
    if (c->state == TCP_ESTABLISHED || c->state == TCP_CLOSE_WAIT) {
        dev    = c->dev;
        finseq = c->snd_nxt;
        c->snd_nxt++;
        c->state = (c->state == TCP_ESTABLISHED) ? TCP_FIN_WAIT_1 : TCP_LAST_ACK;
        /* Arm the FIN retransmit timer (it is otherwise unbuffered). */
        c->retransmit_at    = (uint32_t)arch_get_ticks() + TCP_RTO_INITIAL;
        c->retransmit_count = 0;
        spin_unlock_irqrestore(&tcp_lock, fl);
        tcp_send_at_seq(dev, c, TCP_FIN | TCP_ACK, finseq, NULL, 0);
        return 0;
    }
    spin_unlock_irqrestore(&tcp_lock, fl);
    return 0;
}

/* tcp_conn_get_addr: fill remote/local address. */
void
tcp_conn_get_addr(uint32_t conn_id, ip4_addr_t *rip, uint16_t *rport,
                  ip4_addr_t *lip, uint16_t *lport)
{
    if (conn_id >= TCP_MAX_CONNS) return;
    tcp_conn_t *c = &s_tcp[conn_id];
    if (rip)   *rip   = c->remote_ip;
    if (rport) *rport = c->remote_port;
    if (lip)   *lip   = c->local_ip;
    if (lport) *lport = c->local_port;
}

/* tcp_conn_set_sock: update sock_id back-reference after accept. */
void
tcp_conn_set_sock(uint32_t conn_id, uint32_t sock_id)
{
    if (conn_id >= TCP_MAX_CONNS) return;
    s_tcp[conn_id].sock_id = sock_id;
}

/* tcp_conn_get: return pointer to tcp_conn_t for conn_id, or NULL if invalid. */
tcp_conn_t *
tcp_conn_get(uint32_t conn_id)
{
    if (conn_id >= TCP_MAX_CONNS) return (tcp_conn_t *)0;
    return &s_tcp[conn_id];
}
