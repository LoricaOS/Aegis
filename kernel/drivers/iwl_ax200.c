/* iwl_ax200.c — Intel Wi-Fi 6 AX200 (8086:2723) driver.
 *
 * The AX200 is an iwlwifi "22000"-family part: a compact 16 KB MMIO register
 * window (BAR0) plus DMA rings the firmware sets up. This is a from-scratch
 * driver, developed against a real AX200 forwarded into a VM via VFIO
 * passthrough (see the Proxmox host's spare 04:00.0).
 *
 * PHASE 1 (this file): PCI bring-up — find the device, enable it, map BAR0,
 * wake to D0, and read the always-on hardware-revision / RF-ID registers. That
 * confirms the MMIO window is live and identifies the exact silicon stepping
 * (which selects the firmware image + PHY config). Firmware upload, the host-
 * command interface, scanning and association are later phases.
 *
 * Register offsets are the standard iwlwifi CSRs (see reference iwl-csr.h).
 */
#include "iwl_ax200.h"
#include "pcie.h"
#include "arch.h"
#include "kva.h"
#include "vmm.h"
#include "printk.h"
#include <stdint.h>

#define AX200_VENDOR   0x8086
#define AX200_DEVICE   0x2723

/* iwlwifi CSR register offsets within BAR0. HW_REV / HW_RF_ID are "always on"
 * (readable without requesting MAC clock access), so they are safe first reads. */
#define CSR_HW_IF_CONFIG_REG   0x000
#define CSR_INT                0x008
#define CSR_RESET              0x020
#define CSR_GP_CNTRL           0x024
#define CSR_HW_REV             0x028
#define CSR_HW_RF_ID           0x09C

/* PCI command register bits + PM capability id */
#define PCI_CMD_MEM    0x02
#define PCI_CMD_BM     0x04
#define PCI_CAP_ID_PM  0x01

/* MMIO must be uncached (device registers). Matches rtl8169's mapping flags. */
#define MMIO_FLAGS (VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS)

static volatile uint8_t *s_mmio;   /* BAR0 kernel VA */

static inline uint32_t csr_rd(uint32_t off) { return *(volatile uint32_t *)(s_mmio + off); }
static inline void     csr_wr(uint32_t off, uint32_t v) { *(volatile uint32_t *)(s_mmio + off) = v; }

/* Map a BAR's physical range into kernel VA as uncached MMIO. Mirrors the
 * rtl8169 helper — kva_alloc_pages reserves the VA, then remap each page to the
 * device's physical BAR. */
static uintptr_t
map_bar(uint64_t pa, uint32_t n_pages)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(n_pages);
    for (uint32_t i = 0; i < n_pages; i++) {
        uintptr_t page_va = va + (uint64_t)i * 4096;
        vmm_unmap_page(page_va);
        vmm_map_page(page_va, pa + (uint64_t)i * 4096, MMIO_FLAGS);
    }
    return va;
}

/* Find the Power Management capability's PMCSR offset (cap+4), or 0. */
static uint8_t
find_pm_pmcsr(const pcie_device_t *d)
{
    uint16_t status = pcie_read16(d->bus, d->dev, d->fn, 0x06);
    if (!(status & (1 << 4)))
        return 0;
    uint8_t cap = (uint8_t)pcie_read8(d->bus, d->dev, d->fn, 0x34) & 0xFCu;
    int safety = 48;
    while (cap != 0 && safety-- > 0) {
        uint8_t id   = pcie_read8(d->bus, d->dev, d->fn, cap + 0);
        uint8_t next = pcie_read8(d->bus, d->dev, d->fn, cap + 1);
        if (id == PCI_CAP_ID_PM)
            return (uint8_t)(cap + 4);
        cap = next & 0xFCu;
    }
    return 0;
}

void
iwl_ax200_init(void)
{
    /* 1. Find the AX200 among the enumerated PCIe devices. */
    const pcie_device_t *devs = pcie_get_devices();
    int n = pcie_device_count();
    const pcie_device_t *found = 0;
    for (int i = 0; i < n; i++) {
        if (devs[i].vendor_id == AX200_VENDOR && devs[i].device_id == AX200_DEVICE) {
            found = &devs[i];
            break;
        }
    }
    if (!found)
        return;   /* silent skip — no AX200 present */

    printk("[AX200] OK: found Intel Wi-Fi 6 AX200 at %x:%x.%x\n",
           (unsigned)found->bus, (unsigned)found->dev, (unsigned)found->fn);

    /* 2. Enable Memory space + Bus Master (BusMaster needed for the DMA rings
     * we set up in later phases; Memory space to reach BAR0). */
    {
        uint32_t cs = pcie_read32(found->bus, found->dev, found->fn, 0x04);
        cs &= 0xFFFF0000u;                 /* preserve status word */
        cs |= (PCI_CMD_MEM | PCI_CMD_BM);
        pcie_write32(found->bus, found->dev, found->fn, 0x04, cs);
    }

    /* 3. Wake to D0 (clear the PM power state) if a PM capability is present. */
    {
        uint8_t pmcsr = find_pm_pmcsr(found);
        if (pmcsr) {
            pcie_write32(found->bus, found->dev, found->fn, pmcsr, 0);
            for (volatile uint32_t i = 0; i < 1000000u; i++)
                __asm__ volatile("pause");   /* D3->D0 settle (<10ms) */
        }
    }

    /* 4. Map BAR0 (16 KB register window; 4 pages). */
    if (found->bar[0] == 0) {
        printk("[AX200] FAIL: BAR0 unmapped\n");
        return;
    }
    {
        uint64_t pa = found->bar[0] & ~0xFFFULL;   /* strip BAR type bits; 4K-aligned */
        s_mmio = (volatile uint8_t *)(map_bar(pa, 4) + (found->bar[0] & 0xFFFULL));
    }

    /* 5. First register reads. CSR_HW_REV is always-on, so a valid (non-0xFF..)
     * value proves the MMIO window is live and gives us the silicon stepping. */
    uint32_t hw_rev = csr_rd(CSR_HW_REV);
    if (hw_rev == 0xFFFFFFFFu) {
        printk("[AX200] FAIL: CSR read 0xFFFFFFFF (BAR0 wrong or device asleep)\n");
        return;
    }
    uint32_t rf_id  = csr_rd(CSR_HW_RF_ID);
    uint32_t if_cfg = csr_rd(CSR_HW_IF_CONFIG_REG);

    /* HW_REV low bits: step = bits [3:2], dash = bits [1:0] (iwlwifi convention). */
    printk("[AX200] HW_REV=0x%x (step=%u dash=%u) RF_ID=0x%x IF_CFG=0x%x\n",
           hw_rev,
           (unsigned)((hw_rev >> 2) & 0x3),
           (unsigned)(hw_rev & 0x3),
           rf_id, if_cfg);
    printk("[AX200] Phase 1 OK: MMIO alive. Next: firmware upload.\n");
}
