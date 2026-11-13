/* No libc, file descriptors, entropy, capabilities or trusted result buffer.
 * Actual SVC results are checked here and independently at the kernel boundary. */
.text
.global _start
_start:
    orr x0, x0, x1
.irp reg,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
    orr x0, x0, x\reg
.endr
    cbnz x0, user_fail
    mov x1, sp
    tst x1, #15
    b.ne user_fail
    sub sp, sp, #512
    mov x19, sp
    mov x8, #172
.global user_svc_pid
user_svc_pid:
    svc #0
    cmp x0, #1
    b.ne user_fail
    mov x8, #174
.global user_svc_uid
user_svc_uid:
    svc #0
    cbnz x0, user_fail
    mov x0, x19
    mov x8, #160
.global user_svc_uname
user_svc_uname:
    svc #0
    cbnz x0, user_fail
    ldrb w0, [x19]
    cmp w0, #'A'
    b.ne user_fail
    ldrb w0, [x19, #4]
    cmp w0, #'s'
    b.ne user_fail
    ldrb w0, [x19, #260]
    cmp w0, #'a'
    b.ne user_fail
    ldr x0, =0xffffffff80200000
    mov x8, #160
.global user_svc_badptr
user_svc_badptr:
    svc #0
    cmn x0, #14
    b.ne user_fail
    mov x0, #2
    mov x1, #1
    mov x2, #0
    mov x8, #198
.global user_svc_socket
user_svc_socket:
    svc #0
    cmn x0, #1
    b.ne user_fail
    ldr x16, =0xffffffff80200000
.global user_kernel_read
user_kernel_read:
    ldr x0, [x16]               /* must fault: mapped privileged kernel text */
    adr x16, _start
.global user_text_write
user_text_write:
    str wzr, [x16]             /* must fault: user RX is not writable */
    add x16, sp, #496
    mov w0, #0x03c0
    movk w0, #0xd65f, lsl #16  /* RET, but the user stack is NX */
    str w0, [x16]
    blr x16
.global user_nx_resume
user_nx_resume:
    mov x0, #0x5a
.global user_done
user_done:
    brk #0x5a                  /* diagnostic terminal event, not a syscall */
.global user_fail
user_fail:
    brk #0x5b
    b user_fail
