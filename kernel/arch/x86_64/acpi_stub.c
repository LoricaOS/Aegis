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

/* No ACPI S5 register block exists on a no-ACPI target (Firecracker /
 * cloud-hypervisor / qemu-microvm ship none). sys_reboot has already synced and
 * marked the fs clean before calling us, so all that's left is to terminate the
 * microVM the portable way every no-ACPI VMM honors: a triple fault (load a null
 * IDT and raise an exception → double fault → triple fault → VM reset).
 * Firecracker and cloud-hypervisor shut the VM down on it; qemu-microvm exits
 * under -no-reboot. Without this the caller falls into a hlt loop and the VM
 * never exits — the orchestrator has to kill it. Mirrors the reboot-path triple
 * fault in sys_reboot(). */
void acpi_do_poweroff(void)
{
    printk("[AEGIS] microVM power off\n");
    struct __attribute__((packed)) { uint16_t limit; uint64_t base; }
        null_idtr = { 0, 0 };
    __asm__ volatile ("cli; lidt %0; int3" : : "m"(null_idtr));
    for (;;) __asm__ volatile ("hlt");   /* unreachable */
}
