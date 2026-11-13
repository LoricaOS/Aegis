/* The only FIQ-enabled foreground window. No calls and no voluntary yield.
 * Caller: deadline, own counter, peer counter, target, integer sentinel seed. */
.section .text
.global apple_preempt_wait
.global apple_preempt_wait_begin
.global apple_preempt_wait_end
.type apple_preempt_wait, %function
apple_preempt_wait:
apple_preempt_wait_begin:
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp x29, x30, [sp, #-16]!
    sub sp, sp, #16
    str x4, [sp]
    mov x9, x0
    mov x10, x1
    mov x11, x2
    mov x14, x3
    mov x15, #0x40000000
    mov x19, x4
    add x20, x4, #1
    add x21, x4, #2
    add x22, x4, #3
    add x23, x4, #4
    add x24, x4, #5
    add x25, x4, #6
    add x26, x4, #7
    add x27, x4, #8
    add x28, x4, #9
    msr daifclr, #1
    isb
1:
    ldr x12, [x10]
    cmp x12, x14
    b.lo 2f
    ldr x12, [x11]
    cmp x12, x14
    b.hs 3f
2:
    isb
    mrs x12, cntpct_el0
    cmp x12, x9
    b.hs 4f
    subs x15, x15, #1
    b.ne 1b
4:
    mov x0, #1
    b 6f
3:
    msr daifset, #3
    ldr x9, [sp]
    mov x0, #2
.macro check reg
    cmp \reg, x9
    b.ne 6f
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
6:
    msr daifset, #3
    isb
    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret
apple_preempt_wait_end:
.size apple_preempt_wait, . - apple_preempt_wait
