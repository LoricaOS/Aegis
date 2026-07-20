/*
 * native_entry.c — native (non-Limine, non-UEFI) Pi 5 boot path's entry
 * into the real kernel. Called from kernel/arch/arm64/native/boot_probe.S
 * once EL2->EL1 drop, page tables, MMU-enable, and .bss zeroing are all
 * done (milestones 1-3b, verified on real hardware).
 *
 * Mirrors kernel_main_limine() (kernel/arch/arm64/main.c) exactly, per
 * the x86 multiboot2 precedent (kernel/core/bootinfo.h): no
 * aegis_bootinfo_t is built for this path, arch_mm_init_native() ingests
 * directly. Unlike Limine, no arm64_map_early_uart() call is needed here
 * -- boot_probe.S's own TTBR0 identity map already covers the real UART
 * (block index 65, see that file's page-table comment), so serial_init()
 * can go straight to the real physical address.
 */
#include "arch.h"
#include "printk.h"
#include <stdint.h>

void kernel_main_arm64(void);

void
kernel_main_native(uint64_t dtb_phys)
{
    arch_mm_init_native(dtb_phys);
    serial_set_base((volatile void *)0x107D001000UL);
    serial_init();
    printk("[SERIAL] OK: PL011 UART initialized (native boot)\n");
    kernel_main_arm64();
}
