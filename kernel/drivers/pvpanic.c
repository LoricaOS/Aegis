/* pvpanic.c — QEMU pvpanic device (guest → host panic/event notification)
 *
 * A tiny PCI device (1b36:0011) with a single MMIO byte: reading returns the
 * bitmask of events the host supports (bit0 PANICKED, bit1 CRASHLOADED); writing
 * an event tells the host the guest reached that state, so the host can take a
 * configured action (-action panic=...). Lets a host/orchestrator distinguish a
 * guest kernel panic from a hang.
 */
#include "pvpanic.h"
#include "pcie.h"
#include "vmm.h"
#include "kva.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

#define PVPANIC_VENDOR  0x1B36u
#define PVPANIC_DEVICE  0x0011u
#define PVPANIC_PANICKED    0x01u
#define PVPANIC_CRASHLOADED 0x02u

static volatile uint8_t *s_reg;

void
pvpanic_init(void)
{
    const pcie_device_t *d = NULL;
    int n = pcie_device_count();
    for (int i = 0; i < n; i++) {
        const pcie_device_t *x = &pcie_get_devices()[i];
        if (x->vendor_id == PVPANIC_VENDOR && x->device_id == PVPANIC_DEVICE) { d = x; break; }
    }
    if (!d)
        return;

    uint32_t cmd = pcie_read32(d->bus, d->dev, d->fn, 0x04);
    pcie_write32(d->bus, d->dev, d->fn, 0x04, cmd | (1u << 1));   /* mem space */

    uintptr_t va = (uintptr_t)kva_alloc_pages(1);
    if (!va)
        return;
    uint64_t pa = d->bar[0] & ~0xFFFULL;
    vmm_unmap_page(va);
    vmm_map_page(va, pa, VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS);
    s_reg = (volatile uint8_t *)(va + (d->bar[0] & 0xFFFULL));

    uint8_t events = *s_reg;
    printk("[PVPANIC] OK: host events=%x\n", events);
}

/* Signal a guest kernel panic to the host. Safe to call from the panic path. */
void
pvpanic_signal_panic(void)
{
    if (s_reg)
        *s_reg = PVPANIC_PANICKED;
}
