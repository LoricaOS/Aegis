/* virtio_net.h — virtio-net specifics over the shared virtio core
 *
 * The PCI transport + virtqueue types now live in virtio.h (shared by every
 * virtio device). This header carries only what is specific to the network
 * device: the per-frame header and the net feature/device ids.
 *
 * References: VIRTIO v1.0 §5.1 Network Device.
 */
#ifndef VIRTIO_NET_H
#define VIRTIO_NET_H

#include <stdint.h>
#include "virtio.h"

/* ── PCI device ids ───────────────────────────────────────────────────────── */
#define VIRTIO_NET_DEVICE_MODERN  0x1041u   /* virtio 1.0 network device */
#define VIRTIO_NET_DEVICE_LEGACY  0x1000u   /* transitional (also modern-capable) */

/* ── Feature bits (§5.1.3) ───────────────────────────────────────────────── */
#define VIRTIO_NET_F_MAC           (1u << 5)   /* device has a MAC address */

/* ── virtio_net_hdr (§5.1.6, modern path) ─────────────────────────────────── */
/* 12 bytes prepended to every TX frame; 12 bytes at the start of every RX
 * buffer. Virtio 1.0 (VIRTIO_F_VERSION_1) always uses the 12-byte header with
 * num_buffers even without MRG_RXBUF; skipping only 10 on RX would read 2 header
 * bytes as frame data and silently corrupt every received frame. */
#define VIRTIO_NET_HDR_SIZE 12u
typedef struct __attribute__((packed)) {
    uint8_t  flags;
    uint8_t  gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
    uint16_t num_buffers;  /* always 1 without VIRTIO_NET_F_MRG_RXBUF */
} virtio_net_hdr_t;

/* virtio_net_init — scan PCIe for a virtio-net device, bring it up via the
 * virtio core, and register it as "eth0". Silent (no printk) if none found.
 * Declared in virtio.h too; kept here for source compatibility. */
void virtio_net_init(void);

#endif /* VIRTIO_NET_H */
