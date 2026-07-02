/*
 * proc_enter.S — EL0 entry trampolines.
 *
 * Both are reached by `ret` from ctx_switch (they are the x30 slot of a
 * hand-built callee-save frame) and end in ERET to EL0. Every GPR is
 * zeroed (or loaded from the child's saved frame) before ERET — no kernel
 * register values may leak to user space.
 */

.section .text

/*
 * proc_enter_user — first entry into a fresh process (proc_spawn / execve).
 *
 * Stack on entry (low → high), built by proc.c / sys_exec.c:
 *   [spsr] [elr = ELF entry] [user_sp] [ttbr0 = user table phys]
 *
 * sched.c already loaded TTBR0 via vmm_switch_to before switching this
 * task in; the frame's ttbr0 slot makes first entry self-contained anyway
 * (belt and braces — execve reuses the running task without a switch).
 */
.global proc_enter_user
.type proc_enter_user, %function
proc_enter_user:
    ldp x0, x1, [sp], #16       // x0 = spsr, x1 = elr
    ldp x2, x3, [sp], #16       // x2 = user_sp, x3 = ttbr0 phys

    msr spsr_el1, x0
    msr elr_el1, x1
    msr sp_el0, x2

    msr ttbr0_el1, x3
    dsb ish
    tlbi vmalle1
    dsb ish
    isb

    b   zero_gprs_eret
.size proc_enter_user, . - proc_enter_user

/*
 * fork_child_return — first scheduling of a fork/clone child.
 *
 * Stack on entry: a full 34-slot SAVE_ALL frame (x0-x30, sp_el0, elr,
 * spsr) built by sys_fork/sys_clone with x0=0 (the child's return value).
 * TTBR0 was loaded by sched.c (vmm_switch_to) before the switch-in.
 * Restore exactly like vectors.S RESTORE_ALL and ERET.
 */
.global fork_child_return
.type fork_child_return, %function
fork_child_return:
    /* Load THIS (child) task's TTBR0 before returning to EL0. The scheduler
     * only restores a task's address space when it RESUMES from its own
     * ctx_switch point; a fork child's first run lands here with the
     * parent's TTBR0 still active, so we must install the child's here (the
     * proc_enter_user spawn/exec path does the equivalent from its frame).
     * bl clobbers x0-x18/x30, but the full frame is restored below. */
    bl  arm64_load_current_ttbr0

    ldr x21, [sp, #248]         // sp_el0
    ldr x22, [sp, #256]         // elr_el1
    ldr x23, [sp, #264]         // spsr_el1
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
    eret
.size fork_child_return, . - fork_child_return

/* zero_gprs_eret — clear every GPR, then ERET (fresh-process hygiene). */
.type zero_gprs_eret, %function
zero_gprs_eret:
    mov x0,  xzr
    mov x1,  xzr
    mov x2,  xzr
    mov x3,  xzr
    mov x4,  xzr
    mov x5,  xzr
    mov x6,  xzr
    mov x7,  xzr
    mov x8,  xzr
    mov x9,  xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr
    mov x15, xzr
    mov x16, xzr
    mov x17, xzr
    mov x18, xzr
    mov x19, xzr
    mov x20, xzr
    mov x21, xzr
    mov x22, xzr
    mov x23, xzr
    mov x24, xzr
    mov x25, xzr
    mov x26, xzr
    mov x27, xzr
    mov x28, xzr
    mov x29, xzr
    mov x30, xzr
    eret
.size zero_gprs_eret, . - zero_gprs_eret
