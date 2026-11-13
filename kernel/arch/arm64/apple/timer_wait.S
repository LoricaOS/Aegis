/* Controlled foreground window: no calls, locks, allocation or WFI. Only FIQ
 * is unmasked. A delivered interrupt must preserve the sentinel registers and
 * return here. Deadline plus an iteration cap bound the polling window. */
.section .text
.global apple_timer_wait
.global apple_timer_wait_begin
.global apple_timer_wait_end
.type apple_timer_wait, %function
apple_timer_wait:
apple_timer_wait_begin:
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp x29, x30, [sp, #-16]!
    mov x9, x0                  /* physical counter deadline */
    mov x10, x1                 /* delivered count */
    mov x11, x2                 /* failure flag */
    mov x15, #0x40000000         /* independent finite iteration cap */
    mov x19, #0x191
    mov x20, #0x202
    mov x21, #0x213
    mov x22, #0x224
    mov x23, #0x235
    mov x24, #0x246
    mov x25, #0x257
    mov x26, #0x268
    mov x27, #0x279
    mov x28, #0x28a
    msr daifclr, #1             /* F only; IRQ stays masked */
    isb
1:
    ldr x12, [x11]
    cbnz x12, 3f
    ldr x12, [x10]
    cbnz x12, 2f
    isb
    mrs x12, cntpct_el0
    cmp x12, x9
    b.hs 4f
    subs x15, x15, #1
    b.ne 1b
4:
    mov x0, #1                  /* no delivery before deadline/budget */
    b 6f
3:
    mov x0, #3                  /* unexpected source/frame */
    b 6f
2:
    mov x0, #2                  /* register corruption unless all match */
    cmp x19, #0x191
    b.ne 6f
    cmp x20, #0x202
    b.ne 6f
    cmp x21, #0x213
    b.ne 6f
    cmp x22, #0x224
    b.ne 6f
    cmp x23, #0x235
    b.ne 6f
    cmp x24, #0x246
    b.ne 6f
    cmp x25, #0x257
    b.ne 6f
    cmp x26, #0x268
    b.ne 6f
    cmp x27, #0x279
    b.ne 6f
    cmp x28, #0x28a
    b.ne 6f
    mov x0, #0
6:
    msr daifset, #3             /* no asynchronous work during reporting */
    isb
    ldp x29, x30, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret
apple_timer_wait_end:
.size apple_timer_wait, . - apple_timer_wait
