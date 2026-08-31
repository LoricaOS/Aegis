/*
 * uaccess.S — fault-tolerant user<->kernel copy for ARM64.
 *
 * uint64_t arm64_copy_{from,to}_user(void *dst [x0], const void *src [x1],
 *                                    uint64_t len [x2]);
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
 * PAN is cleared only for this leaf copy and restored on both normal and fault
 * returns. Both accesses remain in __ex_table so a bad kernel pointer is
 * contained too, matching x86's rep-movsb coverage.
 */

.section .text
.arch_extension pan
.global arm64_copy_from_user
.type arm64_copy_from_user, %function
arm64_copy_from_user:
    adrp    x4, arch_smap_enabled
    add     x4, x4, :lo12:arch_smap_enabled
    ldr     w5, [x4]
    cbz     x2, 2f              // len == 0 → nothing to copy
    cbz     w5, 4f
    msr     pan, #0
    isb
4:
    cmp     x2, #8
    b.lo    1f                  // short copy → byte loop only
3:                              // 8-byte main loop
.Luf_load8:
    ldr     x3, [x1]
.Luf_store8:
    str     x3, [x0]
    add     x0, x0, #8
    add     x1, x1, #8
    sub     x2, x2, #8
    cmp     x2, #8
    b.hs    3b
    cbz     x2, 2f
1:                              // byte tail (< 8 bytes)
.Luf_load:
    ldrb    w3, [x1]
.Luf_store:
    strb    w3, [x0]
    add     x0, x0, #1
    add     x1, x1, #1
    subs    x2, x2, #1
    b.ne    1b
2:
    mov     x0, #0              // all bytes copied
    cbz     w5, 5f
    msr     pan, #1
    isb
5:
    ret
.Luf_fixup:
    mov     x0, x2              // x2 = bytes remaining = bytes NOT copied
    cbz     w5, 6f
    msr     pan, #1
    isb
6:
    ret
.size arm64_copy_from_user, . - arm64_copy_from_user

.global arm64_copy_to_user
.type arm64_copy_to_user, %function
arm64_copy_to_user:
    adrp    x4, arch_smap_enabled
    add     x4, x4, :lo12:arch_smap_enabled
    ldr     w5, [x4]
    cbz     x2, 2f
    cbz     w5, 4f
    msr     pan, #0
    isb
4:
    cmp     x2, #8
    b.lo    1f
3:
.Lut_load8:
    ldr     x3, [x1]
.Lut_store8:
    str     x3, [x0]
    add     x0, x0, #8
    add     x1, x1, #8
    sub     x2, x2, #8
    cmp     x2, #8
    b.hs    3b
    cbz     x2, 2f
1:
.Lut_load:
    ldrb    w3, [x1]
.Lut_store:
    strb    w3, [x0]
    add     x0, x0, #1
    add     x1, x1, #1
    subs    x2, x2, #1
    b.ne    1b
2:
    mov     x0, #0
    cbz     w5, 5f
    msr     pan, #1
    isb
5:
    ret
.Lut_fixup:
    mov     x0, x2
    cbz     w5, 6f
    msr     pan, #1
    isb
6:
    ret
.size arm64_copy_to_user, . - arm64_copy_to_user

    /* {fault_pc, fixup_pc} entries. 8-byte aligned; the linker gathers
     * __ex_table between __start_ex_table / __stop_ex_table (linker-arm64.ld). */
    .pushsection __ex_table, "a"
    .align 3
    .quad .Luf_load8,  .Luf_fixup
    .quad .Luf_store8, .Luf_fixup
    .quad .Luf_load,   .Luf_fixup
    .quad .Luf_store,  .Luf_fixup
    .quad .Lut_load8,  .Lut_fixup
    .quad .Lut_store8, .Lut_fixup
    .quad .Lut_load,   .Lut_fixup
    .quad .Lut_store,  .Lut_fixup
    .popsection
