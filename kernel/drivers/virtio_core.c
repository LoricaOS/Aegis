/* virtio_core.c — transport-neutral virtio 1.0 core.
 *
 * The device-agnostic half of the virtio stack, independent of how the device
 * is discovered or reached (PCI capability MMIO vs. virtio-mmio register block).
 * It owns:
 *   - virtio_find[_nth]: unified discovery — try PCI, then virtio-mmio.
 *   - the RESET→ACK→DRIVER→FEATURES_OK→DRIVER_OK handshake + queue setup,
 *     dispatched to the right register layout by dev->is_mmio.
 *   - the shared <4GB DMA-page allocator and the uncached-MMIO mapper.
 *
 * Splitting this out of virtio_pci.c is what lets a microVM build drop PCI
 * entirely (CONFIG_PCI off, virtio-mmio only) while every device driver stays
 * byte-identical — they call virtio_find + virtio_reset/negotiate/… and never
 * name a transport.
 */
#include "virtio.h"
#include "arch.h"
#include "kva.h"
#include "vmm.h"
#include "printk.h"
#include <stddef.h>

/* Arch-neutral VMM flags for uncached MMIO mapping. */
#define VIRTIO_MAP_FLAGS (VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS)

/* ── uncached-MMIO mapper (shared by both transports) ───────────────────────
 * Map n_pages at physical base pa into KVA as uncached device memory. */
uintptr_t
virtio_map_mmio(uint64_t pa, uint32_t n_pages)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(n_pages);
    if (!va)
        return 0;
    for (uint32_t i = 0; i < n_pages; i++) {
        uintptr_t page_va = va + (uint64_t)i * 4096;
        /* kva_alloc_pages already mapped each page to a PMM frame; unmap before
         * remapping to the device PA so vmm_map_page doesn't panic on a
         * double-map. */
        vmm_unmap_page(page_va);
        vmm_map_page(page_va, pa + (uint64_t)i * 4096, VIRTIO_MAP_FLAGS);
    }
    return va;
}

/* ── <4GB DMA-page allocator (shared) ───────────────────────────────────────
 * One PMM page from the guaranteed-below-4GB pool, KVA-mapped + zeroed. */
int
virtio_alloc_dma_page(uint64_t *phys_out, uintptr_t *virt_out)
{
    void *p = kva_alloc_pages_low(1);
    if (!p)
        return -1;
    uintptr_t va = (uintptr_t)p;
    uint64_t  pa = kva_page_phys(p);
    uint8_t  *z  = (uint8_t *)va;
    for (uint32_t i = 0; i < 4096; i++)   /* comes zeroed; be explicit */
        z[i] = 0;
    *phys_out = pa;
    *virt_out = va;
    return 0;
}

/* ── unified discovery ──────────────────────────────────────────────────────
 * PCI first (the id is a PCI device id, 0x1040+type), then virtio-mmio (whose
 * DeviceID register holds the bare device type = modern_id - 0x1040). */
int
virtio_find_nth(uint16_t modern_id, uint16_t legacy_id, int skip,
                virtio_dev_t *out)
{
#ifdef CONFIG_PCI
    if (virtio_pci_find_nth(modern_id, legacy_id, skip, out) == 0)
        return 0;
#else
    (void)legacy_id;
#endif
#ifdef CONFIG_VIRTIO_MMIO
    if (virtio_mmio_find_nth((uint16_t)(modern_id - 0x1040u), skip, out) == 0)
        return 0;
#endif
    return -1;
}

int
virtio_find(uint16_t modern_id, uint16_t legacy_id, virtio_dev_t *out)
{
    return virtio_find_nth(modern_id, legacy_id, 0, out);
}

/* ── mmio register helpers ──────────────────────────────────────────────────
 * 32-bit little-endian accessors over the flat mmio register block. */
#ifdef CONFIG_VIRTIO_MMIO
static inline uint32_t mmio_rd(virtio_dev_t *d, uint32_t off)
{
    return *(volatile uint32_t *)(d->mmio + off);
}
static inline void mmio_wr(virtio_dev_t *d, uint32_t off, uint32_t v)
{
    *(volatile uint32_t *)(d->mmio + off) = v;
}
#endif

/* ── status handshake (dispatched) ──────────────────────────────────────────*/
void
virtio_reset(virtio_dev_t *d)
{
#ifdef CONFIG_VIRTIO_MMIO
    if (d->is_mmio) {
        mmio_wr(d, VMMIO_STATUS, VIRTIO_STATUS_RESET);
        mmio_wr(d, VMMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        mmio_wr(d, VMMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        return;
    }
#endif
    volatile virtio_pci_common_cfg_t *c = d->common;
    c->device_status = VIRTIO_STATUS_RESET;
    c->device_status = VIRTIO_STATUS_ACKNOWLEDGE;
    c->device_status = (uint8_t)(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
}

int
virtio_negotiate(virtio_dev_t *d, uint32_t want_features)
{
#ifdef CONFIG_VIRTIO_MMIO
    if (d->is_mmio) {
        /* Offer the low-word subset we support + VIRTIO_F_VERSION_1 (high word). */
        mmio_wr(d, VMMIO_DEVICE_FEATURES_SEL, 0);
        (void)mmio_rd(d, VMMIO_DEVICE_FEATURES);
        mmio_wr(d, VMMIO_DRIVER_FEATURES_SEL, 0);
        mmio_wr(d, VMMIO_DRIVER_FEATURES, want_features);
        mmio_wr(d, VMMIO_DRIVER_FEATURES_SEL, 1);
        mmio_wr(d, VMMIO_DRIVER_FEATURES, (1u << VIRTIO_F_VERSION_1_BIT));

        mmio_wr(d, VMMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
                                 VIRTIO_STATUS_FEATURES_OK);
        if (!(mmio_rd(d, VMMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK)) {
            mmio_wr(d, VMMIO_STATUS, VIRTIO_STATUS_FAILED);
            return -1;
        }
        d->features = (uint64_t)want_features |
                      ((uint64_t)(1u << VIRTIO_F_VERSION_1_BIT) << 32);
        return 0;
    }
#endif
    volatile virtio_pci_common_cfg_t *c = d->common;
    c->device_feature_select = 0;
    (void)c->device_feature;

    c->driver_feature_select = 0;
    c->driver_feature        = want_features;
    c->driver_feature_select = 1;
    c->driver_feature        = (1u << VIRTIO_F_VERSION_1_BIT);

    c->device_status = (uint8_t)(VIRTIO_STATUS_ACKNOWLEDGE |
                                 VIRTIO_STATUS_DRIVER |
                                 VIRTIO_STATUS_FEATURES_OK);
    if (!(c->device_status & VIRTIO_STATUS_FEATURES_OK)) {
        c->device_status = VIRTIO_STATUS_FAILED;
        return -1;
    }
    d->features = (uint64_t)want_features |
                  ((uint64_t)(1u << VIRTIO_F_VERSION_1_BIT) << 32);
    return 0;
}

void
virtio_driver_ok(virtio_dev_t *d)
{
#ifdef CONFIG_VIRTIO_MMIO
    if (d->is_mmio) {
        mmio_wr(d, VMMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
                                 VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);
        return;
    }
#endif
    d->common->device_status = (uint8_t)(VIRTIO_STATUS_ACKNOWLEDGE |
                                         VIRTIO_STATUS_DRIVER |
                                         VIRTIO_STATUS_FEATURES_OK |
                                         VIRTIO_STATUS_DRIVER_OK);
}

/* ── virtqueue allocation (dispatched) ──────────────────────────────────────*/
int
virtio_setup_queue(virtio_dev_t *d, uint16_t qidx, virtq_t *vq)
{
    uint16_t  qsz;
    uint64_t  desc_pa, avail_pa, used_pa;
    uintptr_t desc_va, avail_va, used_va;

#ifdef CONFIG_VIRTIO_MMIO
    if (d->is_mmio) {
        mmio_wr(d, VMMIO_QUEUE_SEL, qidx);
        uint16_t dev_max = (uint16_t)mmio_rd(d, VMMIO_QUEUE_NUM_MAX);
        if (dev_max == 0)
            return -1;
        qsz = (dev_max < VIRTQ_SIZE) ? dev_max : (uint16_t)VIRTQ_SIZE;

        if (virtio_alloc_dma_page(&desc_pa,  &desc_va)  < 0 ||
            virtio_alloc_dma_page(&avail_pa, &avail_va) < 0 ||
            virtio_alloc_dma_page(&used_pa,  &used_va)  < 0)
            return -1;

        mmio_wr(d, VMMIO_QUEUE_NUM, qsz);
        mmio_wr(d, VMMIO_QUEUE_DESC_LOW,    (uint32_t)desc_pa);
        mmio_wr(d, VMMIO_QUEUE_DESC_HIGH,   (uint32_t)(desc_pa >> 32));
        mmio_wr(d, VMMIO_QUEUE_DRIVER_LOW,  (uint32_t)avail_pa);
        mmio_wr(d, VMMIO_QUEUE_DRIVER_HIGH, (uint32_t)(avail_pa >> 32));
        mmio_wr(d, VMMIO_QUEUE_DEVICE_LOW,  (uint32_t)used_pa);
        mmio_wr(d, VMMIO_QUEUE_DEVICE_HIGH, (uint32_t)(used_pa >> 32));
        mmio_wr(d, VMMIO_QUEUE_READY, 1);
        vq->notify_off = 0;   /* mmio doorbell is a fixed register; index only */
        goto common;
    }
#endif
    {
    volatile virtio_pci_common_cfg_t *c = d->common;
    c->queue_select = qidx;
    uint16_t dev_max = c->queue_size;
    if (dev_max == 0)
        return -1;
    qsz = (dev_max < VIRTQ_SIZE) ? dev_max : (uint16_t)VIRTQ_SIZE;
    c->queue_size = qsz;

    if (virtio_alloc_dma_page(&desc_pa,  &desc_va)  < 0 ||
        virtio_alloc_dma_page(&avail_pa, &avail_va) < 0 ||
        virtio_alloc_dma_page(&used_pa,  &used_va)  < 0)
        return -1;

    c->queue_desc   = desc_pa;
    c->queue_driver = avail_pa;
    c->queue_device = used_pa;
    vq->notify_off  = c->queue_notify_off;
    c->queue_enable = 1;
    }

#ifdef CONFIG_VIRTIO_MMIO
common:
#endif
    vq->dev       = d;
    vq->index     = qidx;
    vq->size      = qsz;
    vq->desc      = (volatile virtq_desc_t  *)desc_va;
    vq->avail     = (volatile virtq_avail_t *)avail_va;
    vq->used      = (volatile virtq_used_t  *)used_va;
    vq->last_used = 0;
    for (uint16_t i = 0; i < qsz; i++)
        vq->free[i] = i;
    vq->nfree = qsz;
    vq->lock  = (spinlock_t)SPINLOCK_INIT;
    return 0;
}
