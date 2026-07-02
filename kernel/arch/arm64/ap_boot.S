/*
 * ap_boot.S — secondary-core (AP) entry trampoline.
 *
 * PSCI CPU_ON starts an AP at THIS physical address with the MMU off, at
 * EL1, interrupts masked. x0 = the context_id we passed = the physical
 * address of that AP's ap_params block. We install the same translation
 * regime the BSP runs (TTBR1 kernel tables + an identity map of the kernel
 * image's 1GB region in TTBR0 so the PC stays valid across the MMU enable),
 * turn the MMU on, then branch to the higher-half C entry.
 *
 * ap_params layout (kept in sync with struct ap_params in smp.c):
 *   +0  ttbr0 (identity map phys)   +40 vbar
 *   +8  ttbr1 (kernel phys)         +48 sp_top (VA)
 *   +16 tcr                         +56 c_entry (VA)
 *   +24 mair                        +64 cpu_index
 *   +32 sctlr
 *
 * Runs at physical addresses (MMU off) until the sctlr write; that is why
 * this lives in .text but is only ever entered via its physical address.
 */

.section .text
.globl ap_trampoline
.type ap_trampoline, %function
ap_trampoline:
    ldr x1, [x0, #0]            /* ttbr0 = identity map */
    ldr x2, [x0, #8]            /* ttbr1 = kernel tables */
    ldr x3, [x0, #16]           /* tcr   */
    ldr x4, [x0, #24]           /* mair  */
    ldr x5, [x0, #32]           /* sctlr (M/C/I set, as BSP) */
    ldr x6, [x0, #40]           /* vbar  */

    msr ttbr0_el1, x1
    msr ttbr1_el1, x2
    msr tcr_el1,  x3
    msr mair_el1, x4
    msr vbar_el1, x6
    dsb sy
    isb
    tlbi vmalle1
    dsb sy
    isb

    msr sctlr_el1, x5           /* MMU on; PC is identity-mapped by ttbr0 */
    isb

    msr spsel, #1              /* use SP_EL1 */
    ldr x7, [x0, #48]          /* sp_top (VA) */
    mov sp, x7
    mov x29, xzr
    mov x30, xzr
    ldr x8, [x0, #56]          /* c_entry (higher-half VA) */
    ldr x0, [x0, #64]          /* cpu_index — load last (x0 was the params ptr) */
    br  x8                     /* into ap_c_entry(cpu_index); never returns */
.size ap_trampoline, . - ap_trampoline
