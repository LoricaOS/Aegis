/* kernel/net/tcp.h — TCP connection table, state machine, retransmit */
#ifndef TCP_H
#define TCP_H

#include "net.h"
#include "netdev.h"
#include "../limits.h"

#define TCP_MAX_CONNS  AEGIS_TCP_MAX_CONNS
/* Receive/send ring sizes. Both MUST stay powers of two (the rings index with
 * `& (SIZE-1)`).  TCP_RBUF_SIZE doubles as the advertised receive window.  The
 * window rides a 16-bit field, so for a buffer > 64 KiB we negotiate RFC 7323
 * window scaling: we advertise `avail >> TCP_RCV_WSCALE` and the peer left-
 * shifts it back.  Throughput = window / effective-RTT; Aegis services the NIC
 * rx ring + ACKs at the 100 Hz device-poll cadence (effective RTT ~10 ms poll-
 * bound), so a 64 KiB window capped bulk downloads at ~6 MB/s.  A 256 KiB scaled
 * window lifts that ~4x (toward ~25 MB/s) — and we also advertise an MSS option
 * (TCP_ADVMSS) so the peer sends full-size 1460-byte segments instead of the
 * RFC-879 default 536 (otherwise the 256-entry RX ring × 536 B/poll re-caps us
 * ~13 MB/s).  Rings are kva_alloc_pages-backed (kernel/net/tcp.c tcp_init), not
 * embedded, so enlarging them only costs heap pages, not BSS. */
#define TCP_RBUF_SIZE  262144
#define TCP_SBUF_SIZE  65536

/* TCP_RCV_WSCALE — the window-scale shift we advertise (RFC 7323).  Chosen so
 * the whole receive buffer fits the 16-bit window field: (TCP_RBUF_SIZE-1) >>
 * TCP_RCV_WSCALE must be <= 0xFFFF.  Shift 3 (×8) covers buffers up to 512 KiB.
 * Scaling is only ENABLED if the peer also offers a Window Scale option in its
 * SYN; otherwise both shifts fall back to 0 (<= 64 KiB, unscaled). */
#define TCP_RCV_WSCALE 3
_Static_assert(((TCP_RBUF_SIZE - 1) >> TCP_RCV_WSCALE) <= 0xFFFF,
               "TCP_RCV_WSCALE too small: scaled window overflows 16-bit field");

/* TCP_ADVMSS — Maximum Segment Size we advertise in our SYN/SYN-ACK so the peer
 * sends full 1460-byte segments.  1460 = 1500 (Ethernet MTU) - 20 (IP) - 20
 * (TCP); a 1460-byte payload fits the 1536-byte virtio RX buffer (14 eth + 20 +
 * 20 + 1460 = 1514).  Our OWN send path uses the peer's MSS from its SYN
 * (conn->snd_mss, clamped to TCP_ADVMSS), falling back to the RFC-879 536
 * default only when the peer offered no MSS option. */
#define TCP_ADVMSS 1460

/* Receive-window update threshold (Silly Window Syndrome avoidance, RFC 1122
 * §4.2.3.3). We only emit ACKs from the inbound-segment path, so when the app
 * drains the ring after the window had closed, the sender has nothing to prod
 * it back to life except a slow zero-window probe / RTO — which, on a large
 * download where the app (e.g. curl writing to ext2) lags the wire, stalls and
 * then drops the connection. tcp_conn_recv sends a window-update ACK when a
 * drain reopens the window from below one MSS to at least one MSS. */
#define TCP_RX_WUPDATE_THRESH  1460

/* TIME_WAIT duration: 4 seconds (shortened 2MSL; non-production acceptable). */
#define TCP_TIMEWAIT_TICKS  400   /* 4 s at 100 Hz */
/* Retransmit timeout: 1 s initial, doubles to 8 s (3 retransmits then RST). */
#define TCP_RTO_INITIAL     100   /* 1 s at 100 Hz */
#define TCP_RTO_MAX         800   /* 8 s at 100 Hz */
#define TCP_RETRANSMIT_MAX  3

typedef enum {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_RCVD,
    TCP_SYN_SENT,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSING,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

typedef struct {
    tcp_state_t state;
    ip4_addr_t  local_ip,  remote_ip;
    uint16_t    local_port, remote_port;
    netdev_t   *dev;           /* NIC this connection arrived on */
    uint32_t    snd_nxt, snd_una;
    uint32_t    rcv_nxt;
    uint32_t    snd_wnd;       /* peer's advertised window, already left-shifted
                               * by snd_wscale (so this can exceed 65535) */
    uint8_t     snd_wscale;    /* RFC 7323 shift for the peer's window (incoming);
                               * 0 = peer offered no scaling */
    uint8_t     rcv_wscale;    /* RFC 7323 shift we advertise (outgoing); 0 until
                               * we decide to offer scaling on this conn */
    uint16_t    snd_mss;       /* peer's MSS from its SYN (clamped to TCP_ADVMSS);
                               * 0 (zeroed slot) → treat as 536 default */
    uint8_t    *rbuf;          /* kva-allocated at boot, never freed */
    uint32_t    rbuf_head, rbuf_tail;
    uint8_t    *sbuf;          /* kva-allocated at boot, never freed */
    uint32_t    sbuf_head, sbuf_tail;
    uint32_t    retransmit_at;
    uint8_t     retransmit_count;
    uint32_t    timewait_at;
    uint32_t    sock_id;
    uint32_t    listener_id;
} tcp_conn_t;

/* tcp_init: zero the connection table. Called from net_init(). */
void tcp_init(void);

/* tcp_rx: process an inbound TCP segment. Called by ip_rx for IP_PROTO_TCP. */
void tcp_rx(netdev_t *dev, ip4_addr_t src_ip, ip4_addr_t dst_ip,
            const void *tcp_data, uint16_t len);

/* tcp_tick: retransmit timer tick. Called from the PIT handler at 100 Hz. */
void tcp_tick(void);

/* tcp_send_segment: build a 20-byte TCP header + optional payload and call ip_send. */
int tcp_send_segment(netdev_t *dev, tcp_conn_t *conn,
                     uint8_t flags, const void *payload, uint16_t len);

/* ── Socket-layer helpers (Phase 26) ─────────────────────────────────────── */
int  tcp_listen(uint16_t port, uint32_t sock_id);
int  tcp_connect(uint32_t sock_id, ip4_addr_t dst_ip, uint16_t dst_port,
                 uint32_t *conn_id_out);
int  tcp_conn_recv(uint32_t conn_id, void *dst, uint16_t max_len);
int  tcp_conn_send(uint32_t conn_id, const void *data, uint16_t len);
/* tcp_conn_send_ready: 1=send space available, 0=block (ring full), -1=not
 * sendable (EPIPE).  For the socket layer's blocking send. */
int  tcp_conn_send_ready(uint32_t conn_id);
int  tcp_conn_close(uint32_t conn_id);
void tcp_conn_get_addr(uint32_t conn_id, ip4_addr_t *rip, uint16_t *rport,
                       ip4_addr_t *lip, uint16_t *lport);
void tcp_conn_set_sock(uint32_t conn_id, uint32_t sock_id);
/* tcp_conn_get: return pointer to tcp_conn_t for conn_id, or NULL if invalid. */
tcp_conn_t *tcp_conn_get(uint32_t conn_id);

#endif /* TCP_H */
