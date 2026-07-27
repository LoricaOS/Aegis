/* acpi_stub.c — the "no ACPI" backend (CONFIG_ACPI off).
 *
 * Compiled in place of acpi.c for a target whose firmware provides no ACPI
 * tables — most importantly Firecracker, which ships none (CPU topology comes
 * from other channels, and there is no MCFG/MADT at all). Provides the same
 * globals acpi.c exports, at their safe "nothing found" defaults, plus no-op
 * ACPI entry points, so smp.c / ioapic.c / pcie.c still link and take their
 * already-present fallback paths:
 *   - g_smp_cpu_count = 0  -> SMP runs BSP-only (g_cpu_count stays 1).
 *   - g_ioapic_addr   = 0  -> ioapic_init() skips; scheduling runs on the LAPIC
 *                            timer (a local interrupt, no I/O APIC needed), and
 *                            serial/virtio output is polled.
 *   - g_mcfg_base     = 0  -> no PCIe ECAM (PCI depends on ACPI anyway).
 *
 * This is the ni_syscall / pcie_stub pattern: the call sites stay edit-free.
 */
#include "acpi.h"
#include "printk.h"

uint64_t g_mcfg_base      = 0;
uint8_t  g_mcfg_start_bus = 0;
uint8_t  g_mcfg_end_bus   = 0;
int      g_madt_found     = 0;

smp_cpu_t g_smp_cpus[SMP_MAX_CPUS];
uint32_t  g_smp_cpu_count = 0;
uint8_t   g_bsp_apic_id   = 0;

uint64_t  g_ioapic_addr     = 0;
uint32_t  g_ioapic_gsi_base = 0;

madt_iso_t g_madt_iso[MADT_MAX_ISO];
uint32_t   g_madt_iso_count = 0;

void acpi_init(void)
{
    printk("[ACPI] disabled (CONFIG_ACPI off) — no MADT/MCFG, LAPIC-only\n");
}

void     acpi_power_button_init(void) { }
void     acpi_sci_handler(void)       { }
uint16_t acpi_get_sci_irq(void)       { return 0; }
void     acpi_do_poweroff(void)       { }
