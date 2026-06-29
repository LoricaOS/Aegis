/* virtio.h — shared virtio 1.0 (modern) PCI transport + virtqueue core
 *
 * One transport for every virtio device (net, blk, rng, gpu, console, …).
 * Modern transport only (PCI capability-list MMIO, §4.1). No legacy port I/O,
 * no MSI-X. Each device driver (virtio_net.c, virtio_blk.c, virtio_rng.c) is a
 * thin layer over this core: probe → negotiate → set up queues → driver_ok,
 * then submit/poll descriptor chains.
 *
 * References: Virtual I/O Device (VIRTIO) v1.0, OASIS Standard 2016-01-11
 *   §2.6 Virtqueues, §3.1 Device Initialization, §4.1 Virtio Over PCI.
 */
#ifndef VIRTIO_H
#define VIRTIO_H

#include <stdint.h>
#include "pcie.h"
#include "spinlock.h"

/* ── PCI identity ─────────────────────────────────────────────────────────── */
#define VIRTIO_VENDOR_ID           0x1AF4u

/* PCI vendor-specific capability sub-types (§4.1.4) */
#define VIRTIO_PCI_CAP_COMMON_CFG  1u
#define VIRTIO_PCI_CAP_NOTIFY_CFG  2u
#define VIRTIO_PCI_CAP_DEVICE_CFG  4u

/* Device status bits (§2.1) */
#define VIRTIO_STATUS_RESET        0x00u
#define VIRTIO_STATUS_ACKNOWLEDGE  0x01u
#define VIRTIO_STATUS_DRIVER       0x02u
#define VIRTIO_STATUS_DRIVER_OK    0x04u
#define VIRTIO_STATUS_FEATURES_OK  0x08u
#define VIRTIO_STATUS_FAILED       0x80u

/* Transport feature bit 32 = VIRTIO_F_VERSION_1 (bit 0 of the high feature word).
 * Non-transitional modern devices REQUIRE this to be negotiated or FEATURES_OK
 * is rejected. */
#define VIRTIO_F_VERSION_1_BIT     0u   /* within the high (select=1) word */

/* ── Common configuration structure (§4.1.4.3) ────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint32_t device_feature_select;
    uint32_t device_feature;
    uint32_t driver_feature_select;
    uint32_t driver_feature;
    uint16_t msix_config;
    uint16_t num_queues;
    uint8_t  device_status;
    uint8_t  config_generation;
    uint16_t queue_select;
    uint16_t queue_size;
    uint16_t queue_msix_vector;
    uint16_t queue_enable;
    uint16_t queue_notify_off;
    uint64_t queue_desc;    /* phys addr of descriptor table */
    uint64_t queue_driver;  /* phys addr of available ring */
    uint64_t queue_device;  /* phys addr of used ring */
} virtio_pci_common_cfg_t;

/* ── Virtqueue layout (§2.6). Fixed 256 entries: each ring fits one 4K page. ── */
#define VIRTQ_SIZE  256u

typedef struct __attribute__((packed)) {
    uint64_t addr;   /* phys address of buffer */
    uint32_t len;    /* length in bytes */
    uint16_t flags;  /* VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE */
    uint16_t next;   /* next descriptor index when NEXT set */
} virtq_desc_t;

#define VIRTQ_DESC_F_NEXT   1u
#define VIRTQ_DESC_F_WRITE  2u   /* device writes into this buffer (device-IN) */

typedef struct __attribute__((packed)) {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[VIRTQ_SIZE];
    uint16_t used_event;
} virtq_avail_t;

typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t len;
} virtq_used_elem_t;

typedef struct __attribute__((packed)) {
    uint16_t flags;
    uint16_t idx;
    virtq_used_elem_t ring[VIRTQ_SIZE];
    uint16_t avail_event;
} virtq_used_t;

/* ── Device handle ────────────────────────────────────────────────────────── */
typedef struct virtio_dev {
    pcie_device_t pci;                          /* copy of the PCI device */
    volatile virtio_pci_common_cfg_t *common;   /* COMMON_CFG MMIO */
    volatile uint32_t *notify_base;             /* NOTIFY_CFG MMIO base */
    uint32_t           notify_off_mult;         /* notify_off_multiplier */
    volatile uint8_t  *devcfg;                  /* DEVICE_CFG MMIO (device-specific) */
    uint64_t           features;                /* negotiated features (low|high<<32) */
} virtio_dev_t;

/* ── A configured virtqueue ───────────────────────────────────────────────── */
typedef struct virtq {
    virtio_dev_t *dev;
    uint16_t      index;        /* queue index (== value written to notify) */
    uint16_t      size;         /* negotiated queue size (≤ VIRTQ_SIZE) */
    volatile virtq_desc_t  *desc;
    volatile virtq_avail_t *avail;
    volatile virtq_used_t  *used;
    uint16_t      notify_off;   /* queue_notify_off for the doorbell */
    uint16_t      last_used;    /* used-ring entries consumed so far */
    uint16_t      free[VIRTQ_SIZE]; /* free-descriptor stack (submit/poll API) */
    uint16_t      nfree;
    spinlock_t    lock;         /* driver-held when using the submit/poll API */
} virtq_t;

/* One scatter-gather segment of a descriptor chain. */
typedef struct virtq_buf {
    uint64_t phys;
    uint32_t len;
    int      write;   /* 1 = device writes into it (IN), 0 = device reads (OUT) */
} virtq_buf_t;

/* ── Transport core (virtio_pci.c) ────────────────────────────────────────── */

/* Scan the PCI device list for a virtio device of modern_id (or legacy_id),
 * walk its capability list, map COMMON/NOTIFY/DEVICE cfg BARs into KVA, and fill
 * *out. Returns 0 on success, -1 if not found / un-mappable. Leaves the device
 * in RESET; caller drives negotiate → setup_queue → driver_ok. */
int  virtio_pci_find(uint16_t modern_id, uint16_t legacy_id, virtio_dev_t *out);

/* RESET → ACKNOWLEDGE → DRIVER. */
void virtio_reset(virtio_dev_t *d);

/* Offer want_features (low 32 bits) + VIRTIO_F_VERSION_1, then set FEATURES_OK
 * and verify it stuck. Stores the negotiated set in d->features. Returns 0 on
 * success, -1 if the device rejected FEATURES_OK (device left FAILED). */
int  virtio_negotiate(virtio_dev_t *d, uint32_t want_features);

/* Set DRIVER_OK — device becomes live. */
void virtio_driver_ok(virtio_dev_t *d);

/* Allocate + map queue qidx's desc/avail/used rings (from <4GB DMA pages),
 * program the common-cfg queue registers, enable the queue, and initialise *vq
 * (free stack full, last_used 0). Returns 0 on success, -1 on no-such-queue or
 * DMA exhaustion. */
int  virtio_setup_queue(virtio_dev_t *d, uint16_t qidx, virtq_t *vq);

/* Allocate one zeroed <4GB DMA page; return its phys + KVA. 0 on success, -1 if
 * the low pool is exhausted. Shared by every virtio driver for buffers. */
int  virtio_alloc_dma_page(uint64_t *phys_out, uintptr_t *virt_out);

/* ── Virtqueue ops (virtqueue.c). Caller serialises via vq->lock. ─────────── */

/* Pop one free descriptor id, or -1 if the queue is full. */
int  virtq_alloc_desc(virtq_t *vq);

/* Fill descriptor `id` with a single segment and publish it to the avail ring
 * (no NEXT). Does NOT kick. Used for RX-style fixed buffer recycling. */
void virtq_publish_single(virtq_t *vq, uint16_t id,
                          uint64_t pa, uint32_t len, int write);

/* Allocate n descriptors, chain them over segs[], publish the head to the avail
 * ring. *head receives the head descriptor id. Does NOT kick. Returns 0, or -1
 * if fewer than n descriptors are free. */
int  virtq_publish_chain(virtq_t *vq, const virtq_buf_t *segs, int n,
                         uint16_t *head);

/* Ring the device's doorbell for this queue (sfence + MMIO write of the index). */
void virtq_notify(virtq_t *vq);

/* If a completion is pending, set *id (head desc id) + *len (bytes the device
 * wrote) and advance last_used; return 1. Else return 0. */
int  virtq_poll_used(virtq_t *vq, uint16_t *id, uint32_t *len);

/* Return every descriptor in the chain starting at `head` to the free stack. */
void virtq_free_chain(virtq_t *vq, uint16_t head);

/* ── Per-device init entry points (called from kernel_main) ──────────────── */
void virtio_net_init(void);   /* virtio_net.c */
void virtio_blk_init(void);   /* virtio_blk.c */
void virtio_rng_init(void);   /* virtio_rng.c */
void virtio_scsi_init(void);  /* virtio_scsi.c */
void virtio_balloon_init(void); /* virtio_balloon.c */
void virtio_balloon_poll(void); /* virtio_balloon.c — from PIT 100 Hz */
void virtio_input_init(void);   /* virtio_input.c */
void virtio_input_poll(void);   /* virtio_input.c — from PIT 100 Hz */
void virtio_pmem_init(void);    /* virtio_pmem.c */
void virtio_console_init(void); /* virtio_console.c */
void virtio_9p_init(void);      /* virtio_9p.c */
void virtio_vsock_init(void);   /* virtio_vsock.c */

#endif /* VIRTIO_H */
