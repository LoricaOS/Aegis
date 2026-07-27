/* pcie_stub.c — the "no PCI bus" backend (CONFIG_PCI off).
 *
 * Compiled in place of pcie.c for a microVM / no-PCI target (virtio-mmio only).
 * Every pcie_* entry point resolves to a no-op that reports an empty bus, so
 * every caller — the always-compiled thermal probe, any PCI driver left in, the
 * virtio PCI transport — still links and simply finds no devices. This is what
 * lets CONFIG_PCI drop the whole enumeration + ECAM path without touching the
 * call sites (the ni_syscall/nvme_stub pattern).
 */
#include "pcie.h"
#include "printk.h"

void pcie_init(void)
{
    printk("[PCIE] disabled (CONFIG_PCI off) — virtio-mmio / no-PCI build\n");
}

uint8_t  pcie_read8 (uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{ (void)bus; (void)dev; (void)fn; (void)off; return 0xFF; }

uint16_t pcie_read16(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{ (void)bus; (void)dev; (void)fn; (void)off; return 0xFFFF; }

uint32_t pcie_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off)
{ (void)bus; (void)dev; (void)fn; (void)off; return 0xFFFFFFFFu; }

void pcie_write32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off, uint32_t val)
{ (void)bus; (void)dev; (void)fn; (void)off; (void)val; }

int pcie_device_count(void) { return 0; }

const pcie_device_t *pcie_get_devices(void) { return 0; }

const pcie_device_t *pcie_find_device(uint8_t class_code, uint8_t subclass,
                                      uint8_t progif)
{ (void)class_code; (void)subclass; (void)progif; return 0; }
