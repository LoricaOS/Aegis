#ifndef AEGIS_SYSCALL_H
#define AEGIS_SYSCALL_H

#include <stdint.h>

/* syscall_frame_t — saved user register state on the kernel stack.
 * Layout is architecture-specific, matching the exception entry asm. */

#ifdef __aarch64__
/* ARM64: 34-slot frame from SAVE_ALL_EL0 in vectors.S.
 * x0-x30 at offsets [0..30], sp_el0 at [31], elr_el1 at [32], spsr at [33]. */
typedef struct syscall_frame {
    uint64_t regs[31];    /* x0-x30 */
    uint64_t user_sp;     /* sp_el0 */
    uint64_t elr;         /* elr_el1 (return address) */
    uint64_t spsr;        /* spsr_el1 */
} syscall_frame_t;
#else
/* x86-64: pushed by syscall_entry.asm (SYSCALL/SYSRET path).
 *
 * The frame includes callee-saved registers (rbx, rbp, r12-r15) so that
 * signal_deliver_sysret can save the full user register state into the
 * signal frame and sys_rt_sigreturn can restore it.  Without these,
 * sigreturn after a SYSRET-path signal delivery would zero the callee-saved
 * registers (C5 audit finding). */
typedef struct syscall_frame {
    uint64_t r10;       /* offset +0:  saved user r10 (Linux arg4) */
    uint64_t r9;        /* offset +8:  saved user r9  (Linux arg6) */
    uint64_t r8;        /* offset +16: saved user r8  (Linux arg5) */
    uint64_t rbx;       /* offset +24: callee-saved */
    uint64_t rbp;       /* offset +32: callee-saved */
    uint64_t r12;       /* offset +40: callee-saved */
    uint64_t r13;       /* offset +48: callee-saved */
    uint64_t r14;       /* offset +56: callee-saved */
    uint64_t r15;       /* offset +64: callee-saved */
    uint64_t rflags;    /* offset +72: saved user RFLAGS (r11 at entry) */
    uint64_t rip;       /* offset +80: saved user RIP  (rcx at entry) */
    uint64_t user_rsp;  /* offset +88: saved user RSP (pushed first) */
} syscall_frame_t;
#endif

/* Arch-portable frame accessors — used by sys_fork, sys_execve, sys_sigreturn */
#ifdef __aarch64__
#define FRAME_IP(f)       ((f)->elr)
#define FRAME_SP(f)       ((f)->user_sp)
#define FRAME_RETVAL(f)   ((f)->regs[0])
/* ARM64 has no separate rflags; SPSR serves the same purpose */
#define FRAME_FLAGS(f)    ((f)->spsr)
#else
#define FRAME_IP(f)       ((f)->rip)
#define FRAME_SP(f)       ((f)->user_rsp)
#define FRAME_RETVAL(f)   (0)  /* x86 return is in rax, set by sysret */
#define FRAME_FLAGS(f)    ((f)->rflags)
#endif

uint64_t syscall_dispatch(syscall_frame_t *frame, uint64_t num,
                          uint64_t arg1, uint64_t arg2, uint64_t arg3,
                          uint64_t arg4, uint64_t arg5, uint64_t arg6);

#endif /* AEGIS_SYSCALL_H */
