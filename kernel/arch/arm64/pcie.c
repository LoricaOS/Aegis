/*
 * pcie.c — ARM64 PCIe ECAM enumeration (QEMU virt).
 *
 * Same public interface as the x86 pcie.c (pcie.h), minus the x86-only
 * legacy 0xCF8/0xCFC port path and the ACPI-MCFG base: on QEMU virt the
 * ECAM base comes from the device tree. From the virt DTB:
 *
 *   pcie@10000000: reg = <0x40 0x10000000 0x00 0x10000000>
 *       → ECAM base 0x40_10000000, size 256 MiB (buses 0-255)
 *   ranges: 32-bit MMIO window @ 0x10000000 (in the kernel device map),
 *           64-bit MMIO window @ 0x80_00000000 (drivers map BARs via KVA)
 *
 * The ECAM base is read from the DTB's pci-host-ecam-generic node at init
 * (Apple Virtualization.framework puts it at 0x4000_0000, QEMU virt at
 * 0x40_1000_0000); ECAM_BASE below is the QEMU-virt fallback. Only bus 0
 * is scanned/mapped (both platforms put every device, virtio included, on
 * bus 0; there are no PCI-PCI bridges by default).
 */
#include "pcie.h"
#include "printk.h"
#include "kva.h"
#include "fdt.h"
#include <stdint.h>
#include <stddef.h>

#define ECAM_BASE   0x4010000000UL
#define ECAM_BUSES  1u                  /* map + scan bus 0 only */

static volatile uint8_t *s_ecam_base;   /* KVA of the mapped ECAM (bus 0) */
static pcie_device_t     s_devices[PCIE_MAX_DEVICES];
static int               s_device_count;

static volatile uint32_t *
config_addr(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{
    uint64_t offset = ((uint64_t)bus << 20) | ((uint64_t)dev << 15) |
                      ((uint64_t)fn  << 12) | (off & 0xFFC);
    return (volatile uint32_t *)(s_ecam_base + offset);
}

uint32_t pcie_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{
    return *config_addr(bus, dev, fn, (uint16_t)(off & 0xFFC));
}

uint8_t pcie_read8(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{
    return (uint8_t)((pcie_read32(bus, dev, fn, off) >> ((off & 3) * 8)) & 0xFF);
}

uint16_t pcie_read16(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{
    return (uint16_t)((pcie_read32(bus, dev, fn, off) >> ((off & 2) * 8)) & 0xFFFF);
}

void pcie_write32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off, uint32_t val)
{
    *config_addr(bus, dev, fn, (uint16_t)(off & 0xFFC)) = val;
}

/* Decode one BAR; advance *bar_idx past 64-bit pairs. Returns MMIO base
 * (0 for I/O BARs, unused). Identical to the x86 decoder. */
static uint64_t
decode_bar(uint8_t bus, uint8_t dev, uint8_t fn, int *bar_idx)
{
    uint16_t off = (uint16_t)(0x10 + (*bar_idx) * 4);
    uint32_t lo  = pcie_read32(bus, dev, fn, off);
    if ((lo & 1) == 1) { (*bar_idx)++; return 0; }   /* I/O BAR */
    uint8_t  type = (lo >> 1) & 0x3;
    uint64_t addr = lo & ~(uint64_t)0xF;
    if (type == 0x2) {
        uint32_t hi = pcie_read32(bus, dev, fn, (uint16_t)(off + 4));
        addr |= ((uint64_t)hi << 32);
        (*bar_idx)++;
    }
    (*bar_idx)++;
    return addr;
}

static void
enumerate_function(uint8_t bus, uint8_t dev, uint8_t fn)
{
    uint16_t vendor = pcie_read16(bus, dev, fn, 0x00);
    if (vendor == 0xFFFF || s_device_count >= PCIE_MAX_DEVICES)
        return;
    pcie_device_t *d = &s_devices[s_device_count++];
    d->vendor_id = vendor;
    d->device_id = pcie_read16(bus, dev, fn, 0x02);
    uint32_t cls = pcie_read32(bus, dev, fn, 0x08);
    d->class_code = (uint8_t)((cls >> 24) & 0xFF);
    d->subclass   = (uint8_t)((cls >> 16) & 0xFF);
    d->progif     = (uint8_t)((cls >>  8) & 0xFF);
    d->bus = bus; d->dev = dev; d->fn = fn;
    for (int i = 0; i < 6; )
        d->bar[i] = decode_bar(bus, dev, fn, &i);
    printk("[PCIE] found %x:%x class=%x at %x:%x.%x\n",
           (unsigned)d->vendor_id, (unsigned)d->device_id,
           (unsigned)d->class_code, (unsigned)bus, (unsigned)dev, (unsigned)fn);
}

void
pcie_init(void)
{
    uint64_t ecam = ECAM_BASE, sz;
    int from_dtb = fdt_reg_by_compat("pci-host-ecam-generic", 0, &ecam, &sz);
    if (!from_dtb)
        ecam = ECAM_BASE;

    s_ecam_base = (volatile uint8_t *)kva_map_mmio(ecam, ECAM_BUSES * 256u);
    if (!s_ecam_base) {
        printk("[PCIE] WARN: ECAM map failed\n");
        return;
    }
    printk("[PCIE] ECAM@%lx (%s)\n", ecam, from_dtb ? "DTB" : "builtin");
    for (uint8_t dev = 0; dev < 32; dev++) {
        if (pcie_read16(0, dev, 0, 0x00) == 0xFFFF)
            continue;
        enumerate_function(0, dev, 0);
        if (pcie_read8(0, dev, 0, 0x0E) & 0x80)
            for (uint8_t fn = 1; fn < 8; fn++)
                enumerate_function(0, dev, fn);
    }
    printk("[PCIE] OK: enumeration complete, %u devices\n",
           (unsigned)s_device_count);
}

int pcie_device_count(void) { return s_device_count; }
const pcie_device_t *pcie_get_devices(void) { return s_devices; }

const pcie_device_t *
pcie_find_device(uint8_t class_code, uint8_t subclass, uint8_t progif)
{
    for (int i = 0; i < s_device_count; i++) {
        pcie_device_t *d = &s_devices[i];
        if ((class_code == 0xFF || d->class_code == class_code) &&
            (subclass   == 0xFF || d->subclass   == subclass) &&
            (progif     == 0xFF || d->progif     == progif))
            return d;
    }
    return NULL;
}
