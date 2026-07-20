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
    mov x28, x0                 /* preserve params ptr across the EL drop */

    /* ── EL2 -> EL1 drop, only if the firmware handed this core off at EL2.
     * QEMU virt / PSCI enters secondaries at EL1 and skips this; stock Pi 5
     * (TF-A PSCI at EL3) hands them off at EL2, same as the BSP. Mirrors the
     * BSP's sequence in native/boot_probe.S — and, like it, deliberately does
     * NOT touch ICC_SRE_EL2: the Pi 5 GIC is v2 (no ICC_* sysregs), so that
     * access traps as undefined. `ldr =IMM` loads a constant from a PC-
     * relative literal pool, so it is position-independent with the MMU off. */
    mrs x0, CurrentEL
    lsr x0, x0, #2
    cmp x0, #2
    b.ne .Lap_at_el1

    ldr x0, =0x30C50830         /* INIT_SCTLR_EL2_MMU_OFF */
    msr sctlr_el2, x0
    isb
    mov x0, #(1 << 31)          /* HCR_EL2.RW = 1 (EL1 is AArch64) */
    msr hcr_el2, x0
    msr vttbr_el2, xzr          /* no stage-2 translation */
    mrs x0, cnthctl_el2
    orr x0, x0, #3             /* EL1PCEN | EL1PCTEN */
    msr cnthctl_el2, x0
    msr cntvoff_el2, xzr
    mov x0, #0x33FF            /* CPTR_EL2: no FP/SIMD trap to EL2 */
    msr cptr_el2, x0
    msr hstr_el2, xzr          /* no CP15 traps */
    mrs x0, midr_el1
    msr vpidr_el2, x0
    mrs x0, mpidr_el1
    msr vmpidr_el2, x0
    ldr x0, =0x30D00800         /* INIT_SCTLR_EL1_MMU_OFF */
    msr sctlr_el1, x0
    mov x0, #0x3C5             /* EL1h, D|A|I|F masked */
    msr spsr_el2, x0
    adr x0, .Lap_at_el1        /* resume physically (MMU still off) at EL1 */
    msr elr_el2, x0
    isb
    eret

.Lap_at_el1:
    msr daifset, #0xf
    msr spsel, #1              /* use SP_EL1 (set again after the real sp below) */
    mov x0, #(3 << 20)        /* CPACR_EL1.FPEN = 0b11 */
    msr cpacr_el1, x0
    isb
    mov x0, x28                /* restore params ptr for the EL1 setup below */

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
