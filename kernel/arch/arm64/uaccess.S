/*
 * uaccess.S — fault-tolerant user<->kernel copy for ARM64.
 *
 * uint64_t arm64_uaccess_copy(void *dst [x0], const void *src [x1],
 *                             uint64_t len [x2]);
 * 8-byte-wide copy with a byte tail (unaligned ldr/str on Normal memory is
 * architecturally fine; this backs every syscall's user<->kernel transfer, so
 * a byte loop was ~8x the work). Returns the number of bytes NOT copied
 * (0 = full success), the Linux convention: on a fault mid-word the whole
 * word counts as uncopied (conservative, aborts are precise so nothing was
 * partially stored). Backs copy_from_user / copy_to_user (uaccess.h).
 *
 * The user-touching load and store are registered in the kernel exception
 * table (__ex_table) as {fault_pc, fixup_pc} pairs. If the copy faults —
 * e.g. a sibling CLONE_VM thread unmapped the user buffer mid-syscall, the
 * validate-then-copy TOCTOU class — the EL1 data-abort handler
 * (arm64_fault_el1) looks up the faulting PC and redirects execution to the
 * fixup below instead of panicking. A ring-0 fault on a user buffer can no
 * longer take the kernel down.
 *
 * Both the load and the store are registered: one side is the user pointer
 * (the expected fault) and the other is kernel (a fault there is a caller
 * bug, redirected to the same partial-copy fixup rather than panicking —
 * matches the "either side" coverage of x86's rep movsb).
 */

.section .text
.global arm64_uaccess_copy
.type arm64_uaccess_copy, %function
arm64_uaccess_copy:
    cbz     x2, 2f              // len == 0 → nothing to copy
    cmp     x2, #8
    b.lo    1f                  // short copy → byte loop only
3:                              // 8-byte main loop
.Lu_load8:
    ldr     x3, [x1]
.Lu_store8:
    str     x3, [x0]
    add     x0, x0, #8
    add     x1, x1, #8
    sub     x2, x2, #8
    cmp     x2, #8
    b.hs    3b
    cbz     x2, 2f
1:                              // byte tail (< 8 bytes)
.Lu_load:
    ldrb    w3, [x1]
.Lu_store:
    strb    w3, [x0]
    add     x0, x0, #1
    add     x1, x1, #1
    subs    x2, x2, #1
    b.ne    1b
2:
    mov     x0, #0              // all bytes copied
    ret
.Lu_fixup:
    mov     x0, x2              // x2 = bytes remaining = bytes NOT copied
    ret
.size arm64_uaccess_copy, . - arm64_uaccess_copy

    /* {fault_pc, fixup_pc} entries. 8-byte aligned; the linker gathers
     * __ex_table between __start_ex_table / __stop_ex_table (linker-arm64.ld). */
    .pushsection __ex_table, "a"
    .align 3
    .quad .Lu_load8,  .Lu_fixup
    .quad .Lu_store8, .Lu_fixup
    .quad .Lu_load,   .Lu_fixup
    .quad .Lu_store,  .Lu_fixup
    .popsection
