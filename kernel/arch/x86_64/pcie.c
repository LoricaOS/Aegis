/* pcie.c — PCIe ECAM enumeration (Phase 19)
 *
 * Config space layout (ECAM):
 *   base + ((bus << 20) | (dev << 15) | (fn << 12)) = 4KB config space
 *   Offset 0x00: vendor ID (16-bit)
 *   Offset 0x02: device ID (16-bit)
 *   Offset 0x08: class code [31:24], subclass [23:16], progif [15:8], rev [7:0]
 *   Offset 0x0E: header type (bit 7 = multi-function)
 *   Offset 0x10: BAR0 ... Offset 0x24: BAR5
 */
#include "pcie.h"
#include "acpi.h"
#include "printk.h"
#include "vmm.h"
#include "kva.h"
#include <stdint.h>
#include <stddef.h>

/* SAFETY: s_ecam_base is a kernel VA pointing to MMIO config space.
 * Mapped via kva_alloc_pages + vmm_map_page in pcie_init().
 * Declared volatile so the compiler does not cache config register reads. */
static volatile uint8_t *s_ecam_base = 0;

static pcie_device_t s_devices[PCIE_MAX_DEVICES];
static int           s_device_count = 0;

/* ── Legacy PCI configuration access (ports 0xCF8/0xCFC, "mechanism #1") ──
 * Fallback when the firmware exposes no MCFG/ECAM — e.g. QEMU's i440fx
 * machine (the Proxmox default). There ECAM is absent and the legacy I/O
 * ports are the only way to reach PCI config space.  When s_legacy is set,
 * the pcie_read and pcie_write32 accessors dispatch here instead of ECAM
 * MMIO, so enumeration and every driver's cap/BAR probing work unchanged. */
#define PCI_CFG_ADDR 0xCF8
#define PCI_CFG_DATA 0xCFC

static int s_legacy = 0;   /* 1 => port-based config access (no ECAM) */

static inline void cfg_outl(uint16_t port, uint32_t val)
{
    __asm__ volatile ("outl %0, %1" : : "a"(val), "Nd"(port));
}
static inline uint32_t cfg_inl(uint16_t port)
{
    uint32_t v;
    __asm__ volatile ("inl %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static uint32_t legacy_cfg_sel(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{
    return 0x80000000u
         | ((uint32_t)bus << 16)
         | ((uint32_t)(dev & 0x1F) << 11)
         | ((uint32_t)(fn  & 0x07) << 8)
         | (uint32_t)(off & 0xFC);
}

static uint32_t legacy_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{
    cfg_outl(PCI_CFG_ADDR, legacy_cfg_sel(bus, dev, fn, off));
    return cfg_inl(PCI_CFG_DATA);
}

static void legacy_write32(uint8_t bus, uint8_t dev, uint8_t fn,
                           uint16_t off, uint32_t val)
{
    cfg_outl(PCI_CFG_ADDR, legacy_cfg_sel(bus, dev, fn, off));
    cfg_outl(PCI_CFG_DATA, val);
}

static volatile uint32_t *config_addr(uint8_t bus, uint8_t dev,
                                       uint8_t fn, uint16_t off)
{
    uint64_t offset = ((uint64_t)bus  << 20) |
                      ((uint64_t)dev  << 15) |
                      ((uint64_t)fn   << 12) |
                      (off & 0xFFC);
    /* SAFETY: s_ecam_base is a valid kernel VA for ECAM MMIO; mapped in
     * pcie_init(). The offset is bounded by ECAM addressing rules. */
    return (volatile uint32_t *)(s_ecam_base + offset);
}

uint32_t pcie_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{
    if (s_legacy)
        return legacy_read32(bus, dev, fn, (uint16_t)(off & 0xFFC));
    return *config_addr(bus, dev, fn, (uint16_t)(off & 0xFFC));
}

uint8_t pcie_read8(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{
    uint32_t val = pcie_read32(bus, dev, fn, off);
    return (uint8_t)((val >> ((off & 3) * 8)) & 0xFF);
}

uint16_t pcie_read16(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{
    uint32_t val = pcie_read32(bus, dev, fn, off);
    return (uint16_t)((val >> ((off & 2) * 8)) & 0xFFFF);
}

void pcie_write32(uint8_t bus, uint8_t dev, uint8_t fn,
                  uint16_t off, uint32_t val)
{
    if (s_legacy) {
        legacy_write32(bus, dev, fn, (uint16_t)(off & 0xFFC), val);
        return;
    }
    *config_addr(bus, dev, fn, (uint16_t)(off & 0xFFC)) = val;
}

/* Decode one BAR. Advances *bar_idx past 64-bit pairs.
 * Returns the base address (MMIO); 0 for I/O BARs (not supported). */
static uint64_t decode_bar(uint8_t bus, uint8_t dev, uint8_t fn,
                            int *bar_idx)
{
    uint16_t off = (uint16_t)(0x10 + (*bar_idx) * 4);
    uint32_t lo  = pcie_read32(bus, dev, fn, off);

    if ((lo & 1) == 1) {
        /* I/O BAR — skip, not used */
        (*bar_idx)++;
        return 0;
    }

    uint8_t  type = (lo >> 1) & 0x3;
    uint64_t addr = lo & ~(uint64_t)0xF;

    if (type == 0x2) {
        /* 64-bit MMIO BAR: upper 32 bits in the next register */
        uint32_t hi = pcie_read32(bus, dev, fn, (uint16_t)(off + 4));
        addr |= ((uint64_t)hi << 32);
        (*bar_idx)++;   /* consume the extra register */
    }

    (*bar_idx)++;
    return addr;
}

static void enumerate_function(uint8_t bus, uint8_t dev, uint8_t fn)
{
    uint16_t vendor = pcie_read16(bus, dev, fn, 0x00);
    if (vendor == 0xFFFF)
        return;     /* slot not populated */

    if (s_device_count >= PCIE_MAX_DEVICES)
        return;

    pcie_device_t *d = &s_devices[s_device_count++];
    d->vendor_id  = vendor;
    d->device_id  = pcie_read16(bus, dev, fn, 0x02);
    {
        uint32_t cls  = pcie_read32(bus, dev, fn, 0x08);
        d->class_code = (uint8_t)((cls >> 24) & 0xFF);
        d->subclass   = (uint8_t)((cls >> 16) & 0xFF);
        d->progif     = (uint8_t)((cls >>  8) & 0xFF);
    }
    d->bus = bus;
    d->dev = dev;
    d->fn  = fn;

    {
        int i;
        for (i = 0; i < 6; )
            d->bar[i] = decode_bar(bus, dev, fn, &i);
    }

    printk("[PCIE] found %x:%x class=%x at %x:%x.%x\n",
           (unsigned)d->vendor_id, (unsigned)d->device_id,
           (unsigned)d->class_code, (unsigned)bus, (unsigned)dev, (unsigned)fn);
}

void pcie_init(void)
{
    if (g_mcfg_base == 0) {
        /* No ECAM (e.g. QEMU i440fx / Proxmox default machine). Fall back to
         * legacy port-based config access and enumerate the same way, so the
         * virtio-net / NVMe drivers find their devices identically. */
        uint32_t bus;
        s_legacy = 1;
        if (pcie_read16(0, 0, 0, 0x00) == 0xFFFF) {
            /* No host bridge responds — genuinely no PCI. */
            s_legacy = 0;
            printk("[PCIE] OK: skipped (no ECAM, no legacy PCI)\n");
            return;
        }
        for (bus = 0; bus < 256; bus++) {
            uint8_t dev;
            for (dev = 0; dev < 32; dev++) {
                if (pcie_read16((uint8_t)bus, dev, 0, 0x00) == 0xFFFF)
                    continue;   /* slot empty — skip all functions */
                enumerate_function((uint8_t)bus, dev, 0);
                if (pcie_read8((uint8_t)bus, dev, 0, 0x0E) & 0x80) {
                    uint8_t fn;
                    for (fn = 1; fn < 8; fn++)
                        enumerate_function((uint8_t)bus, dev, fn);
                }
            }
        }
        printk("[PCIE] OK: legacy PCI enumeration complete, %u devices\n",
               (unsigned)s_device_count);
        return;
    }

    /* Map the ECAM MMIO range into kernel VA.
     * QEMU q35 ECAM base is 0xB0000000 — outside the kernel's higher-half
     * window. Cap at 8 buses (2048 pages = 8MB) to stay within the PMM
     * budget of 128MB.  All practical devices (NVMe, AHCI, etc.) sit on
     * bus 0 in QEMU; 8 buses is generous. A server with many PCIe bridges
     * may need more — deferred to a future phase with a proper KVA region. */
#define PCIE_MAX_SCAN_BUSES 8u
    {
        uint32_t  n_buses  = (uint32_t)(g_mcfg_end_bus - g_mcfg_start_bus + 1);
        uint32_t  scan_buses = (n_buses < PCIE_MAX_SCAN_BUSES)
                               ? n_buses : PCIE_MAX_SCAN_BUSES;
        uint32_t  n_pages  = scan_buses * 256u; /* 32 devs × 8 fns × 4KB = 256 pages/bus */
        uintptr_t va_base  = (uintptr_t)kva_alloc_pages(n_pages);
        uint32_t  i;
        for (i = 0; i < n_pages; i++) {
            uint64_t pa = g_mcfg_base + (uint64_t)i * 4096;
            uintptr_t va = va_base + (uintptr_t)i * 4096;
            /* kva_alloc_pages mapped each page to a PMM frame; unmap first
             * so vmm_map_page does not panic on a double-map.
             * SAFETY: va is a kva-allocated page that is present in the PT
             * (kva_alloc_pages guarantees this); vmm_unmap_page succeeds. */
            vmm_unmap_page(va);
            /* SAFETY: ECAM MMIO — map uncached via arch-neutral VMM flags. */
            vmm_map_page(va, pa,
                         VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS);
        }
        s_ecam_base = (volatile uint8_t *)va_base;

        {
            uint32_t bus_count = 0;
            uint8_t  bus = g_mcfg_start_bus;
            for (;;) {
                uint8_t dev;
                if (bus_count >= scan_buses)
                    break;
                for (dev = 0; dev < 32; dev++) {
                    uint8_t fn;
                    uint16_t vendor0 = pcie_read16(bus, dev, 0, 0x00);
                    if (vendor0 == 0xFFFF)
                        continue;   /* no device at dev:fn0 — skip all fns */

                    enumerate_function(bus, dev, 0);

                    /* Check multi-function flag in header type byte */
                    if (pcie_read8(bus, dev, 0, 0x0E) & 0x80) {
                        for (fn = 1; fn < 8; fn++)
                            enumerate_function(bus, dev, fn);
                    }
                }
                bus_count++;
                if (bus == g_mcfg_end_bus)
                    break;
                bus++;
            }
        }
    }

    printk("[PCIE] OK: enumeration complete, %u devices\n", (unsigned)s_device_count);
}

int pcie_device_count(void)
{
    return s_device_count;
}

const pcie_device_t *pcie_get_devices(void)
{
    return s_devices;
}

const pcie_device_t *pcie_find_device(uint8_t cls, uint8_t sub, uint8_t pi)
{
    int i;
    for (i = 0; i < s_device_count; i++) {
        const pcie_device_t *d = &s_devices[i];
        if ((cls == 0xFF || d->class_code == cls) &&
            (sub == 0xFF || d->subclass   == sub) &&
            (pi  == 0xFF || d->progif     == pi))
            return d;
    }
    return NULL;
}
