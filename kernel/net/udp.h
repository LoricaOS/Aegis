/* kernel/net/udp.h — UDP send/receive, port binding table */
#ifndef UDP_H
#define UDP_H

#include "net.h"
#include "netdev.h"

#define UDP_BINDINGS_MAX 16

/* UDP header (8 bytes). */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;     /* header + data in bytes */
    uint16_t checksum;   /* 0 = not computed (optional for IPv4) */
} udp_hdr_t;

/* udp_init: zero the binding table. Called from net_init(). */
void udp_init(void);

/* udp_send: build an 8-byte UDP header and hand off to ip_send.
 * Ports in host byte order. Returns 0 on success, -1 on error. */
int udp_send(netdev_t *dev, uint16_t src_port, ip4_addr_t dst_ip,
             uint16_t dst_port, const void *payload, uint16_t len);

/* udp_rx: called by ip_rx for IP_PROTO_UDP (17).
 * src_ip/dst_ip in network byte order (for socket layer delivery). */
void udp_rx(netdev_t *dev, ip4_addr_t src_ip, ip4_addr_t dst_ip,
            const void *udp_data, uint16_t len);

/* udp_bind: register sock_id for dst_port. Returns 0 on success, -1 if already bound. */
int udp_bind(uint16_t port, uint32_t sock_id);

/* udp_unbind: free the binding table entry for port. Called from socket
 * close path so that the next bind() to the same port doesn't fail with
 * EADDRINUSE. No-op if port == 0 or no entry exists. */
void udp_unbind(uint16_t port);

#endif /* UDP_H */
