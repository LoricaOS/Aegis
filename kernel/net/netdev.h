/* netdev.h — Network device abstraction layer
 *
 * Mirrors the blkdev_t pattern. Provides a uniform send/poll interface
 * for network devices. virtio-net, RTL8125, etc. register here.
 *
 * netdev_rx_deliver() is called by drivers from PIT ISR context —
 * it must not block and must not call sched_block().
 *
 * Phase 24: netdev_rx_deliver() is a stub that silently discards frames.
 * Phase 25 replaces it with eth_rx() dispatch.
 */
#ifndef NETDEV_H
#define NETDEV_H

#include <stdint.h>

#define NETDEV_MAX 4

typedef struct netdev {
    char     name[16];      /* "eth0", "eth1", ... */
    uint8_t  mac[6];        /* hardware MAC address */
    uint16_t mtu;           /* maximum transmission unit (1500 for Ethernet) */
    /* send: transmit one Ethernet frame (including 14-byte header).
     * Returns 0 on success, -1 on error (e.g. link down, TX timeout).
     * Called from process context (syscall path). Must not block. */
    int    (*send)(struct netdev *dev, const void *pkt, uint16_t len);
    /* poll: check for received frames. Called from PIT tick ISR at 100 Hz.
     * Must not block. Delivers received frames via netdev_rx_deliver(). */
    void   (*poll)(struct netdev *dev);
    void    *priv;          /* driver-private data */
} netdev_t;

/* Register a network device. Returns 0 on success, -1 if table full. */
int       netdev_register(netdev_t *dev);

/* Look up a network device by name. Returns NULL if not found. */
netdev_t *netdev_get(const char *name);

/* Poll all registered network devices. Called from pit_handler() at 100 Hz.
 * Calls dev->poll(dev) for each registered device. ISR-safe. */
void      netdev_poll_all(void);

/* Called by drivers when a frame is received. Dispatches to upper layer.
 * frame points to the raw Ethernet frame (including 14-byte header).
 * len is the number of bytes in the frame (excluding virtio_net_hdr).
 * Safe to call from ISR context. Must not block.
 * Phase 24: silently discards (no printk). */
void netdev_rx_deliver(netdev_t *dev, const void *frame, uint16_t len);

#endif /* NETDEV_H */
