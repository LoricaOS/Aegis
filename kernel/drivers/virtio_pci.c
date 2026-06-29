/* virtio_pci.c — shared virtio 1.0 modern PCI transport
 *
 * Device-agnostic bring-up lifted from the original virtio_net.c so every virtio
 * driver shares it: capability-list walk, BAR mapping, the
 * RESET→ACK→DRIVER→FEATURES_OK→DRIVER_OK status handshake, virtqueue allocation,
 * and the <4GB DMA-page allocator.
 *
 * Memory model (unchanged from the net driver this came from):
 *   - PCI config space: PCIe ECAM (pcie.h)
 *   - BAR MMIO: kva_alloc_pages + vmm_map_page, PWT|PCD (no-cache)
 *   - DMA pages: kva_alloc_pages_low() — guaranteed <4GB physical, KVA-mapped;
 *     physical address via kva_page_phys(). Every address handed to the device
 *     (ring bases, descriptor .addr) must come from this <4GB pool.
 */
#include "virtio.h"
#include "arch.h"
#include "kva.h"
#include "vmm.h"
#include "printk.h"
#include <stddef.h>

/* Arch-neutral VMM flags for uncached MMIO mapping (same as the net driver). */
#define VIRTIO_MAP_FLAGS (VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS)

/* ── BAR mapping helper ─────────────────────────────────────────────────────
 * Map n_pages of a BAR region (physical base pa) into KVA as uncached MMIO. */
static uintptr_t
map_bar_region(uint64_t pa, uint32_t n_pages)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(n_pages);
    if (!va)
        return 0;
    uint32_t i;
    for (i = 0; i < n_pages; i++) {
        uintptr_t page_va = va + (uint64_t)i * 4096;
        /* kva_alloc_pages already mapped each page to a PMM frame; unmap before
         * remapping to the BAR PA so vmm_map_page does not panic on a double-map.
         * SAFETY: page_va is present (kva_alloc_pages guarantees it); unmap then
         * map installs the BAR PA. */
        vmm_unmap_page(page_va);
        vmm_map_page(page_va, pa + (uint64_t)i * 4096, VIRTIO_MAP_FLAGS);
    }
    return va;
}

/* ── <4GB DMA-page allocator (shared) ───────────────────────────────────────
 * One PMM page from the guaranteed-below-4GB pool, KVA-mapped + zeroed. Returns
 * both phys and virt. 0 on success, -1 if the low pool is exhausted. */
int
virtio_alloc_dma_page(uint64_t *phys_out, uintptr_t *virt_out)
{
    void *p = kva_alloc_pages_low(1);
    if (!p)
        return -1;
    uintptr_t va = (uintptr_t)p;
    uint64_t  pa = kva_page_phys(p);
    /* Page comes zeroed by kva_alloc_pages_low. */
    uint8_t *z = (uint8_t *)va;
    uint32_t i;
    for (i = 0; i < 4096; i++)
        z[i] = 0;
    *phys_out = pa;
    *virt_out = va;
    return 0;
}

/* ── PCI capability walker ──────────────────────────────────────────────────
 * Walk the device's PCI capability list for virtio vendor caps (id 0x09) and
 * record the COMMON/NOTIFY/DEVICE cfg BAR + offset (+ notify multiplier).
 * Layout (§4.1.4): +0 cap_id, +1 cap_next, +3 cfg_type, +4 bar, +8 offset,
 * +12 length; NOTIFY adds +16 notify_off_multiplier. */
static void
walk_caps(const pcie_device_t *d,
          uint8_t *common_bar, uint32_t *common_off,
          uint8_t *notify_bar, uint32_t *notify_off, uint32_t *notify_mult,
          uint8_t *device_bar, uint32_t *device_off)
{
    uint8_t cap_ptr = (uint8_t)pcie_read8(d->bus, d->dev, d->fn, 0x34) & 0xFCu;

    while (cap_ptr != 0) {
        uint8_t cap_id   = pcie_read8(d->bus, d->dev, d->fn, cap_ptr + 0);
        uint8_t cap_next = pcie_read8(d->bus, d->dev, d->fn, cap_ptr + 1);

        if (cap_id == 0x09u) {  /* PCI vendor-specific capability */
            uint8_t  cfg_type = pcie_read8 (d->bus, d->dev, d->fn, cap_ptr + 3);
            uint8_t  bar      = pcie_read8 (d->bus, d->dev, d->fn, cap_ptr + 4);
            uint32_t off      = pcie_read32(d->bus, d->dev, d->fn, cap_ptr + 8);

            switch (cfg_type) {
            case VIRTIO_PCI_CAP_COMMON_CFG:
                *common_bar = bar; *common_off = off;
                break;
            case VIRTIO_PCI_CAP_NOTIFY_CFG:
                *notify_bar = bar; *notify_off = off;
                *notify_mult = pcie_read32(d->bus, d->dev, d->fn, cap_ptr + 16);
                break;
            case VIRTIO_PCI_CAP_DEVICE_CFG:
                *device_bar = bar; *device_off = off;
                break;
            default:
                break;
            }
        }
        cap_ptr = cap_next & 0xFCu;
    }
}

/* ── virtio_pci_find ─────────────────────────────────────────────────────── */
int
virtio_pci_find(uint16_t modern_id, uint16_t legacy_id, virtio_dev_t *out)
{
    const pcie_device_t *found = NULL;
    int count = pcie_device_count();
    int i;
    for (i = 0; i < count; i++) {
        const pcie_device_t *d = &pcie_get_devices()[i];
        if (d->vendor_id == VIRTIO_VENDOR_ID &&
            (d->device_id == modern_id ||
             (legacy_id != 0 && d->device_id == legacy_id))) {
            found = d;
            break;
        }
    }
    if (!found)
        return -1;

    /* Enable PCI memory space + bus mastering — virtio devices DMA. Harmless if
     * firmware already set them (QEMU does); required on stricter backends. */
    uint32_t cmd = pcie_read32(found->bus, found->dev, found->fn, 0x04);
    pcie_write32(found->bus, found->dev, found->fn, 0x04,
                 cmd | (1u << 1) | (1u << 2));

    uint8_t  common_bar = 0, notify_bar = 0, device_bar = 0;
    uint32_t common_off = 0, notify_off = 0, notify_mult = 0, device_off = 0;
    walk_caps(found,
              &common_bar, &common_off,
              &notify_bar, &notify_off, &notify_mult,
              &device_bar, &device_off);

    uint64_t common_pa = found->bar[common_bar] + common_off;
    uint64_t notify_pa = found->bar[notify_bar] + notify_off;
    uint64_t device_pa = found->bar[device_bar] + device_off;

    uintptr_t common_va = map_bar_region(common_pa & ~0xFFFULL, 1);
    uintptr_t notify_va = map_bar_region(notify_pa & ~0xFFFULL, 1);
    uintptr_t device_va = map_bar_region(device_pa & ~0xFFFULL, 1);
    if (!common_va || !notify_va || !device_va)
        return -1;
    common_va += (common_pa & 0xFFFULL);
    notify_va += (notify_pa & 0xFFFULL);
    device_va += (device_pa & 0xFFFULL);

    out->pci             = *found;
    out->common          = (volatile virtio_pci_common_cfg_t *)common_va;
    out->notify_base     = (volatile uint32_t *)notify_va;
    out->notify_off_mult = notify_mult;
    out->devcfg          = (volatile uint8_t *)device_va;
    out->features        = 0;
    return 0;
}

/* ── status handshake ────────────────────────────────────────────────────── */
void
virtio_reset(virtio_dev_t *d)
{
    volatile virtio_pci_common_cfg_t *c = d->common;
    c->device_status = VIRTIO_STATUS_RESET;
    c->device_status = VIRTIO_STATUS_ACKNOWLEDGE;
    c->device_status = (uint8_t)(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
}

int
virtio_negotiate(virtio_dev_t *d, uint32_t want_features)
{
    volatile virtio_pci_common_cfg_t *c = d->common;

    /* Read device features (low word) — informational; we only ever request the
     * subset we actively support. */
    c->device_feature_select = 0;
    uint32_t dev_lo = c->device_feature;
    (void)dev_lo;

    /* Offer low-word features. */
    c->driver_feature_select = 0;
    c->driver_feature        = want_features;

    /* Offer VIRTIO_F_VERSION_1 in the high word — mandatory on the modern path
     * (QEMU rejects FEATURES_OK without it for non-transitional devices). */
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
    d->common->device_status = (uint8_t)(VIRTIO_STATUS_ACKNOWLEDGE |
                                         VIRTIO_STATUS_DRIVER |
                                         VIRTIO_STATUS_FEATURES_OK |
                                         VIRTIO_STATUS_DRIVER_OK);
}

/* ── virtqueue allocation ────────────────────────────────────────────────── */
int
virtio_setup_queue(virtio_dev_t *d, uint16_t qidx, virtq_t *vq)
{
    volatile virtio_pci_common_cfg_t *c = d->common;

    c->queue_select = qidx;
    uint16_t dev_max = c->queue_size;     /* device's maximum for this queue */
    if (dev_max == 0)
        return -1;                        /* queue not available */
    uint16_t qsz = (dev_max < VIRTQ_SIZE) ? dev_max : (uint16_t)VIRTQ_SIZE;
    c->queue_size = qsz;

    uint64_t  desc_pa, avail_pa, used_pa;
    uintptr_t desc_va, avail_va, used_va;
    if (virtio_alloc_dma_page(&desc_pa,  &desc_va)  < 0 ||
        virtio_alloc_dma_page(&avail_pa, &avail_va) < 0 ||
        virtio_alloc_dma_page(&used_pa,  &used_va)  < 0)
        return -1;

    c->queue_desc   = desc_pa;
    c->queue_driver = avail_pa;
    c->queue_device = used_pa;

    vq->dev        = d;
    vq->index      = qidx;
    vq->size       = qsz;
    vq->desc       = (volatile virtq_desc_t  *)desc_va;
    vq->avail      = (volatile virtq_avail_t *)avail_va;
    vq->used       = (volatile virtq_used_t  *)used_va;
    vq->notify_off = c->queue_notify_off;
    vq->last_used  = 0;

    uint16_t i;
    for (i = 0; i < qsz; i++)
        vq->free[i] = i;
    vq->nfree = qsz;
    vq->lock = (spinlock_t)SPINLOCK_INIT;

    c->queue_enable = 1;
    return 0;
}
