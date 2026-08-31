/* kernel/net/ipv6.h — IPv6 link-local, NDP, ICMPv6, and UDP transport */
#ifndef IPV6_H
#define IPV6_H

#include "net.h"
#include "netdev.h"

#define IP6_PROTO_ICMPV6 58
#define IP6_PROTO_UDP    17

typedef struct __attribute__((packed)) {
    uint32_t vtc_flow;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    ip6_addr_t src;
    ip6_addr_t dst;
} ip6_hdr_t;

void ipv6_init(netdev_t *dev);
void ipv6_selftest(netdev_t *dev);
void ipv6_get_linklocal(ip6_addr_t *out);
int  ipv6_addr_equal(const ip6_addr_t *a, const ip6_addr_t *b);
int  ipv6_send(netdev_t *dev, const ip6_addr_t *dst, uint8_t next_header,
               const void *payload, uint16_t len);
void ipv6_rx(netdev_t *dev, const void *frame,
             const void *payload, uint16_t len);
uint16_t ipv6_l4_checksum(const ip6_addr_t *src, const ip6_addr_t *dst,
                          uint8_t next_header, const void *payload, uint16_t len);

#endif
