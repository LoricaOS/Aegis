/* Executed only through the native bridge's higher-half mapping. x0 points
 * to its image-owned handoff. No bootloader stack is retained. */
.section .text
.global apple_kernel_start
.type apple_kernel_start, %function
apple_kernel_start:
    msr daifset, #15
    msr spsel, #1
    ldr x1, =apple_kernel_stack_top
    mov sp, x1
    mov x29, xzr
    mov x30, xzr
    b apple_kernel_entry
.size apple_kernel_start, . - apple_kernel_start

.section .bss
.balign 16
apple_kernel_stack:
    .skip 32768
.global apple_kernel_stack_top
apple_kernel_stack_top:
