/*
 * Resident-m1n1 transport experiment, NOT a production kernel entry.
 * EL1, MMU/caches off, three 16 KiB stage-2 pages supplied by the monitor.
 * No peripheral accesses and no firmware/key-store protocol requests.
 */
.section .text, "ax"
.global debug_transport_start
debug_transport_start:
    msr daifset, #15
    mov x9, #0x80000000
    add x9, x9, #0xc, lsl #12
    mov sp, x9
    adr x10, debug_transport_report
    mov x9, #1
    str x9, [x10]
    mrs x9, CurrentEL
    str x9, [x10, #8]
    mrs x9, ID_AA64MMFR0_EL1
    str x9, [x10, #16]
    mrs x9, SCTLR_EL1
    str x9, [x10, #24]
    dsb sy
    mov x0, #1
    adr x1, debug_transport_message
    mov x2, #(debug_transport_message_end - debug_transport_message)
.global debug_transport_log_trap
debug_transport_log_trap:
    brk #0x4242
    adr x10, debug_transport_report
    mov x9, #2
    str x9, [x10]
    dsb sy
    mov x0, #2
    mov x1, x10
    mov x2, #32
.global debug_transport_exit_trap
debug_transport_exit_trap:
    brk #0x4242
1:  wfe
    b 1b
.global debug_transport_message
debug_transport_message:
    .ascii "AEGIS DEBUG: resident m1n1 USB transport\n"
debug_transport_message_end:

.section .data, "aw"
.global debug_transport_report
debug_transport_report:
    .zero 32
