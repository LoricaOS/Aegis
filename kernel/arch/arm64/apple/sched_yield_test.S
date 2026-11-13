/* AAPCS integer-state sentinels around the actual scheduler yield.
 * FP/SIMD and TLS are independently checked by the general-registers-only C. */
.section .text
.global apple_sched_yield_test
.type apple_sched_yield_test, %function
apple_sched_yield_test:
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp x29, x30, [sp, #-16]!
    sub sp, sp, #16
    str x0, [sp]
    mov x19, x0
    add x20, x0, #1
    add x21, x0, #2
    add x22, x0, #3
    add x23, x0, #4
    add x24, x0, #5
    add x25, x0, #6
    add x26, x0, #7
    add x27, x0, #8
    add x28, x0, #9
    bl sched_yield_to_next
    ldr x9, [sp]
    mov x0, #1
.macro check reg
    cmp \reg, x9
    b.ne 1f
    add x9, x9, #1
.endm
    check x19
    check x20
    check x21
    check x22
    check x23
    check x24
    check x25
    check x26
    check x27
    check x28
    mov x0, #0
1:
    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret
.size apple_sched_yield_test, . - apple_sched_yield_test
