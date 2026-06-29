/* kernel/net/ip.h — IPv4 send/receive, routing, ICMP echo, net_set_config */
#ifndef IP_H
#define IP_H

#include "net.h"
#include "netdev.h"

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

/* IPv4 header (20 bytes, no options). */
typedef struct __attribute__((packed)) {
    uint8_t    ver_ihl;     /* version (4) | IHL (5) */
    uint8_t    dscp_ecn;
    uint16_t   total_len;   /* network byte order */
    uint16_t   id;
    uint16_t   flags_frag;
    uint8_t    ttl;
    uint8_t    proto;
    uint16_t   checksum;
    ip4_addr_t src;
    ip4_addr_t dst;
} ip_hdr_t;

/* ICMP header (8 bytes for echo request/reply). */
typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} icmp_hdr_t;

/* net_set_config: store static IP configuration.
 * All addresses in network byte order.
 * Prints: [NET] configured: A.B.C.D/prefix gw W.X.Y.Z */
void net_set_config(ip4_addr_t ip, ip4_addr_t mask, ip4_addr_t gw);

/* net_get_config: retrieve current IP configuration (may be 0.0.0.0). */
void net_get_config(ip4_addr_t *ip, ip4_addr_t *mask, ip4_addr_t *gw);

/* ip_send: route and transmit a raw IP payload.
 * proto: IP_PROTO_ICMP / TCP / UDP.
 * src_ip may be 0.0.0.0 (DHCP bootstrap path — do not reject).
 * Returns 0 on success, -1 on ARP timeout or EMSGSIZE. */
int ip_send(netdev_t *dev, ip4_addr_t dst_ip, uint8_t proto,
            const void *payload, uint16_t len);

/* ip_rx: called by eth_rx for ethertype 0x0800.
 * frame: full Ethernet frame (for src MAC extraction for gratuitous ARP).
 * ip_payload: pointer to start of IPv4 header.
 * ip_payload_len: bytes from IPv4 header to end of Ethernet payload. */
void ip_rx(netdev_t *dev, const void *frame,
           const void *ip_payload, uint16_t ip_payload_len);

/* net_init: called from main.c after virtio_net_init().
 * If no netdev is registered: returns immediately (no printk — make test safe).
 * If a netdev is registered:
 *   1. Sets static IP 10.0.2.15/24, gw 10.0.2.2 (QEMU SLIRP).
 *   2. Sends ICMP echo request to 10.0.2.2.
 *   3. Polls for ICMP echo reply (up to 1000 ticks).
 *   4. Prints [NET] ICMP: echo reply from 10.0.2.2 on success. */
void net_init(void);

/* ip_loopback_poll — drain the loopback queue. Called from the PIT handler
 * at 100Hz alongside netdev_poll_all and tcp_tick. Delivers queued loopback
 * packets (127.0.0.0/8 and self-addressed) to ip_rx for processing. */
void ip_loopback_poll(void);

#endif /* IP_H */
