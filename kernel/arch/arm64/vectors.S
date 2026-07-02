/*
 * vectors.S — EL1 exception vector table.
 *
 * SAVE_ALL builds the 34-slot frame both cpu_state_t (idt.h) and
 * syscall_frame_t (kernel/syscall/syscall.h) describe:
 *   [x0..x30] [sp_el0] [elr_el1] [spsr_el1]   (272 bytes, 16-aligned)
 *
 * Exceptions from EL0 land on SP_EL1, which is the task's kernel stack
 * top: the previous return-to-EL0 fully unwound the frame, so SP_EL1
 * self-manages (no TSS.RSP0 equivalent needed).
 *
 * IRQs stay masked for the whole handler (hardware sets DAIF on entry;
 * nothing here clears it) — same "kernel paths run with interrupts off"
 * model as the x86 SYSCALL/ISR entries. sched_tick may ctx_switch away
 * mid-handler; the frame stays parked on this task's kernel stack and is
 * resumed when the task is switched back in.
 */

.macro SAVE_ALL
    sub sp, sp, #272
    stp x0,  x1,  [sp, #0]
    stp x2,  x3,  [sp, #16]
    stp x4,  x5,  [sp, #32]
    stp x6,  x7,  [sp, #48]
    stp x8,  x9,  [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x21, sp_el0
    mrs x22, elr_el1
    mrs x23, spsr_el1
    stp x21, x22, [sp, #248]
    str x23, [sp, #264]
.endm

.macro RESTORE_ALL
    ldp x21, x22, [sp, #248]
    ldr x23, [sp, #264]
    msr sp_el0,   x21
    msr elr_el1,  x22
    msr spsr_el1, x23
    ldp x0,  x1,  [sp, #0]
    ldp x2,  x3,  [sp, #16]
    ldp x4,  x5,  [sp, #32]
    ldp x6,  x7,  [sp, #48]
    ldp x8,  x9,  [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #272
.endm

.macro VECTOR handler
    .balign 0x80
    b \handler
.endm

.section .text

.balign 0x800
.global exception_vectors
exception_vectors:
    /* Current EL with SP_EL0 (EL1t). The kernel normally runs on SP_EL1
     * (EL1h), but wire these to the same handlers so a stray EL1t context
     * (e.g. if the bootloader handed off with SPSel=0) still delivers
     * interrupts instead of silently hanging. */
    VECTOR vec_el1_sync      // sync
    VECTOR vec_el1_irq       // irq
    VECTOR vec_hang          // fiq
    VECTOR vec_el1_sync      // serror

    /* Current EL with SP_ELx — exceptions while in the kernel. */
    VECTOR vec_el1_sync
    VECTOR vec_el1_irq
    VECTOR vec_hang          // fiq
    VECTOR vec_el1_sync      // serror → same panic path

    /* Lower EL, AArch64 — user space. */
    VECTOR vec_el0_sync
    VECTOR vec_el0_irq
    VECTOR vec_hang          // fiq
    VECTOR vec_el0_sync      // serror → fault path (kills the process)

    /* Lower EL, AArch32 — unsupported. */
    VECTOR vec_hang
    VECTOR vec_hang
    VECTOR vec_hang
    VECTOR vec_hang

.type vec_hang, %function
vec_hang:
1:  wfe
    b 1b
.size vec_hang, . - vec_hang

.type vec_el1_sync, %function
vec_el1_sync:
    SAVE_ALL
    mov x0, sp
    bl  arm64_fault_el1       // panics on a real kernel fault; returns only
                             // after rewriting the frame's ELR to a uaccess
                             // fixup, in which case we resume there.
    RESTORE_ALL
    eret
.size vec_el1_sync, . - vec_el1_sync

.type vec_el1_irq, %function
vec_el1_irq:
    SAVE_ALL
    mov x0, sp
    bl  arm64_irq
    RESTORE_ALL
    eret
.size vec_el1_irq, . - vec_el1_irq

.type vec_el0_sync, %function
vec_el0_sync:
    SAVE_ALL
    mov x0, sp
    bl  arm64_sync_el0
    RESTORE_ALL
    eret
.size vec_el0_sync, . - vec_el0_sync

.type vec_el0_irq, %function
vec_el0_irq:
    SAVE_ALL
    mov x0, sp
    bl  arm64_irq
    RESTORE_ALL
    eret
.size vec_el0_irq, . - vec_el0_irq
