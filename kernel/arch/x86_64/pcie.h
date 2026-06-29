/* pcie.h — PCIe ECAM config space access and device enumeration
 *
 * Uses MCFG MMIO base from acpi.c. Scans all bus/device/function
 * combinations. Builds a table of discovered pcie_device_t entries.
 * On systems without MCFG (e.g. -machine pc), prints a skip message
 * and returns 0 devices — callers must handle this gracefully.
 */
#ifndef PCIE_H
#define PCIE_H

#include <stdint.h>

#define PCIE_MAX_DEVICES 64

typedef struct {
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t  class_code;
    uint8_t  subclass;
    uint8_t  progif;
    uint8_t  bus, dev, fn;
    uint64_t bar[6];         /* decoded BAR base addresses (64-bit aware) */
} pcie_device_t;

/* Initialize PCIe: enumerate all devices using ECAM config space.
 * Prints [PCIE] OK or skip message. */
void pcie_init(void);

/* Raw config space read/write accessors — bus/dev/fn/offset addressing. */
uint8_t  pcie_read8 (uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off);
uint16_t pcie_read16(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off);
uint32_t pcie_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t off);
void     pcie_write32(uint8_t bus, uint8_t dev, uint8_t fn,
                      uint16_t off, uint32_t val);

/* Returns the number of devices found, and a pointer to the device table. */
int                   pcie_device_count(void);
const pcie_device_t  *pcie_get_devices(void);

/* Find first device matching class/subclass/progif. Returns NULL if not found.
 * Pass 0xFF for a field to match any value. */
const pcie_device_t *pcie_find_device(uint8_t class_code, uint8_t subclass,
                                      uint8_t progif);

#endif /* PCIE_H */
