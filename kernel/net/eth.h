/* kernel/net/eth.h — Ethernet layer: framing, ARP table, ARP resolution */
#ifndef ETH_H
#define ETH_H

#include "net.h"
#include "netdev.h"

#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806

/* Ethernet frame header (14 bytes, no VLAN tag). */
typedef struct __attribute__((packed)) {
    mac_addr_t  dst;
    mac_addr_t  src;
    uint16_t    ethertype;   /* network byte order */
} eth_hdr_t;

/* ARP packet (28 bytes for IPv4/Ethernet). */
typedef struct __attribute__((packed)) {
    uint16_t   htype;        /* hardware type: 1 = Ethernet */
    uint16_t   ptype;        /* protocol type: 0x0800 = IPv4 */
    uint8_t    hlen;         /* hardware address length: 6 */
    uint8_t    plen;         /* protocol address length: 4 */
    uint16_t   oper;         /* operation: 1 = REQUEST, 2 = REPLY */
    mac_addr_t sha;          /* sender hardware address */
    ip4_addr_t spa;          /* sender protocol address */
    mac_addr_t tha;          /* target hardware address */
    ip4_addr_t tpa;          /* target protocol address */
} arp_pkt_t;

/* Initialize the ARP table (zero all entries).
 * Called from eth_init() which is called from net_init(). */
void eth_init(void);

/* eth_send: build a 14-byte Ethernet header + payload and transmit via dev->send.
 * Uses a file-scope static 1514-byte TX buffer — callers are sequential.
 * Returns 0 on success, -1 if dev is NULL or len > 1500. */
int eth_send(netdev_t *dev, const mac_addr_t *dst_mac,
             uint16_t ethertype, const void *payload, uint16_t len);

/* eth_rx: dispatch an inbound Ethernet frame.
 * Called by netdev_rx_deliver(). Dispatches on ethertype:
 *   0x0800 → ip_rx()
 *   0x0806 → arp_rx()
 *   other  → drop */
void eth_rx(netdev_t *dev, const void *frame, uint16_t len);

/* arp_resolve: look up ip in the ARP cache; if missing, send an ARP REQUEST
 * and busy-poll the NIC for up to 1000 PIT ticks (~100 ms) with interrupts
 * disabled to prevent concurrent virtio_net_poll() advancement of rx_last_used.
 * Writes the resolved MAC into *mac_out on success.
 * Returns 0 on success, -1 on timeout (EHOSTUNREACH). */
int arp_resolve(netdev_t *dev, ip4_addr_t ip, mac_addr_t *mac_out);

#endif /* ETH_H */
