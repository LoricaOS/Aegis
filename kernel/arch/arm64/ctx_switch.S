/*
 * ctx_switch.S — ARM64 context switch + FP/SIMD save helpers.
 *
 * void ctx_switch(aegis_task_t *outgoing [x0], aegis_task_t *incoming [x1]);
 *
 * Saves the AAPCS64 callee-saved registers (x19-x28, x29, x30) on the
 * outgoing task's kernel stack, swaps SP through the TCBs' sp field
 * (offset 0 — _Static_assert in sched.c), and restores the incoming
 * task's set.
 *
 * FP/SIMD: the kernel is built -mgeneral-regs-only and never touches the
 * V registers, so the live NEON state at any switch point belongs to the
 * outgoing task's user code (same reasoning as the x86 FXSAVE path). We
 * save V0-V31 + FPSR/FPCR of the outgoing task into its fpu_state area
 * (offset FPU_OFF) and restore the incoming task's — CPACR_EL1.FPEN was
 * enabled in start.c so these instructions don't trap at EL1.
 *
 * on_cpu (offset 8) is released (set -1) AFTER the SP swap — the exact
 * point the outgoing stack is vacated — so a reaper on another CPU can
 * never free a kernel stack this CPU still executes on (see the x86
 * ctx_switch.asm comment for the full SMP hazard analysis).
 */

.set FPU_OFF, 16    /* offsetof(aegis_task_t, fpu_state) — _Static_assert in sched.c */

.section .text
.global ctx_switch
.type ctx_switch, %function
ctx_switch:
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp x29, x30, [sp, #-16]!

    /* Save outgoing FP/SIMD (x0 = outgoing task). x2 = save area. */
    add x2, x0, #FPU_OFF
    stp q0,  q1,  [x2, #0]
    stp q2,  q3,  [x2, #32]
    stp q4,  q5,  [x2, #64]
    stp q6,  q7,  [x2, #96]
    stp q8,  q9,  [x2, #128]
    stp q10, q11, [x2, #160]
    stp q12, q13, [x2, #192]
    stp q14, q15, [x2, #224]
    stp q16, q17, [x2, #256]
    stp q18, q19, [x2, #288]
    stp q20, q21, [x2, #320]
    stp q22, q23, [x2, #352]
    stp q24, q25, [x2, #384]
    stp q26, q27, [x2, #416]
    stp q28, q29, [x2, #448]
    stp q30, q31, [x2, #480]
    mrs x3, fpsr
    mrs x4, fpcr
    str w3, [x2, #512]
    str w4, [x2, #516]

    mov x2, sp
    str x2, [x0]                // outgoing->sp = sp
    ldr x2, [x1]
    mov sp, x2                  // sp = incoming->sp

    mov w2, #-1
    str w2, [x0, #8]            // outgoing->on_cpu = -1 (after the swap)

    /* Restore incoming FP/SIMD (x1 = incoming task). */
    add x2, x1, #FPU_OFF
    ldp q0,  q1,  [x2, #0]
    ldp q2,  q3,  [x2, #32]
    ldp q4,  q5,  [x2, #64]
    ldp q6,  q7,  [x2, #96]
    ldp q8,  q9,  [x2, #128]
    ldp q10, q11, [x2, #160]
    ldp q12, q13, [x2, #192]
    ldp q14, q15, [x2, #224]
    ldp q16, q17, [x2, #256]
    ldp q18, q19, [x2, #288]
    ldp q20, q21, [x2, #320]
    ldp q22, q23, [x2, #352]
    ldp q24, q25, [x2, #384]
    ldp q26, q27, [x2, #416]
    ldp q28, q29, [x2, #448]
    ldp q30, q31, [x2, #480]
    ldr w3, [x2, #512]
    ldr w4, [x2, #516]
    msr fpsr, x3
    msr fpcr, x4

    ldp x29, x30, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret
.size ctx_switch, . - ctx_switch

/*
 * arm64_fpu_save(void *area [x0]) — snapshot the live V registers +
 * FPSR/FPCR into a 528-byte area. Used by fork (child inherits parent FP).
 */
.global arm64_fpu_save
.type arm64_fpu_save, %function
arm64_fpu_save:
    stp q0,  q1,  [x0, #0]
    stp q2,  q3,  [x0, #32]
    stp q4,  q5,  [x0, #64]
    stp q6,  q7,  [x0, #96]
    stp q8,  q9,  [x0, #128]
    stp q10, q11, [x0, #160]
    stp q12, q13, [x0, #192]
    stp q14, q15, [x0, #224]
    stp q16, q17, [x0, #256]
    stp q18, q19, [x0, #288]
    stp q20, q21, [x0, #320]
    stp q22, q23, [x0, #352]
    stp q24, q25, [x0, #384]
    stp q26, q27, [x0, #416]
    stp q28, q29, [x0, #448]
    stp q30, q31, [x0, #480]
    mrs x1, fpsr
    mrs x2, fpcr
    str w1, [x0, #512]
    str w2, [x0, #516]
    ret
.size arm64_fpu_save, . - arm64_fpu_save

/*
 * arm64_fpu_restore(const void *area [x0]) — load a saved area into the
 * live V registers + FPSR/FPCR. Used by execve (reset to defaults).
 */
.global arm64_fpu_restore
.type arm64_fpu_restore, %function
arm64_fpu_restore:
    ldp q0,  q1,  [x0, #0]
    ldp q2,  q3,  [x0, #32]
    ldp q4,  q5,  [x0, #64]
    ldp q6,  q7,  [x0, #96]
    ldp q8,  q9,  [x0, #128]
    ldp q10, q11, [x0, #160]
    ldp q12, q13, [x0, #192]
    ldp q14, q15, [x0, #224]
    ldp q16, q17, [x0, #256]
    ldp q18, q19, [x0, #288]
    ldp q20, q21, [x0, #320]
    ldp q22, q23, [x0, #352]
    ldp q24, q25, [x0, #384]
    ldp q26, q27, [x0, #416]
    ldp q28, q29, [x0, #448]
    ldp q30, q31, [x0, #480]
    ldr w1, [x0, #512]
    ldr w2, [x0, #516]
    msr fpsr, x1
    msr fpcr, x2
    ret
.size arm64_fpu_restore, . - arm64_fpu_restore
