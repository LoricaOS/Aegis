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

/* ── virtio_pci_find[_nth] ───────────────────────────────────────────────── */
/* Find the (skip+1)-th matching virtio device — skip=0 is the first, as
 * virtio_pci_find. Lets a driver claim several identical devices (e.g. the
 * separate virtio-keyboard + virtio-mouse input devices QEMU exposes). */
int
virtio_pci_find_nth(uint16_t modern_id, uint16_t legacy_id, int skip,
                    virtio_dev_t *out)
{
    const pcie_device_t *found = NULL;
    int count = pcie_device_count();
    int seen = 0;
    int i;
    for (i = 0; i < count; i++) {
        const pcie_device_t *d = &pcie_get_devices()[i];
        if (d->vendor_id == VIRTIO_VENDOR_ID &&
            (d->device_id == modern_id ||
             (legacy_id != 0 && d->device_id == legacy_id))) {
            if (seen++ < skip)
                continue;
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

    uintptr_t common_va = virtio_map_mmio(common_pa & ~0xFFFULL, 1);
    uintptr_t notify_va = virtio_map_mmio(notify_pa & ~0xFFFULL, 1);
    uintptr_t device_va = virtio_map_mmio(device_pa & ~0xFFFULL, 1);
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
    out->is_mmio         = 0;
    out->mmio            = 0;
    return 0;
}

int
virtio_pci_find(uint16_t modern_id, uint16_t legacy_id, virtio_dev_t *out)
{
    return virtio_pci_find_nth(modern_id, legacy_id, 0, out);
}
