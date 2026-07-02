/*
 * entry.S — ARM64 Limine boot protocol entry.
 *
 * Limine (base revision 3) enters here at EL1: MMU on (TTBR1 = bootloader
 * higher-half tables + HHDM, 4K granule, T0SZ/T1SZ=16), D-cache/I-cache on,
 * all interrupts masked, SP = bootloader-reclaimable stack, GPRs zero.
 *
 * Everything the old port's boot.S did by hand (EL2→EL1 drop, early MMU
 * tables, DTB fishing) is obsolete under Limine. This stub only moves onto
 * the kernel's own .bss boot stack and enters C (arm64_early_entry in
 * start.c), which programs MAIR/TCR, builds the early TTBR0 device map for
 * the UART, and calls limine_boot_entry().
 */

.section .text
.global limine_start
.type limine_start, %function
limine_start:
    msr daifset, #0xf           // mask everything until vectors exist

    /* Use SP_EL1 for all kernel execution (SPSel=1). Limine may hand off
     * with SPSel=0 (running on SP_EL0); if we stayed there, SP_EL1 would
     * be uninitialized, and the FIRST exception — which always switches to
     * SP_ELx of the target EL — would fault in the vector's stack push,
     * hanging before any handler runs (the "IRQ enabled → silent hang"
     * symptom). Selecting SP_EL1 now makes the active stack and the
     * exception stack the same, initialized, stack. */
    msr spsel, #1

    ldr x0, =boot_stack_top
    mov sp, x0
    mov x29, xzr                // terminate frame-pointer chain
    mov x30, xzr

    bl arm64_early_entry
1:  wfe
    b 1b
.size limine_start, . - limine_start

/* 16KB boot stack, 16-byte aligned (AAPCS64). */
.section .bss
.balign 16
boot_stack:
    .skip 16384
.global boot_stack_top
boot_stack_top:
