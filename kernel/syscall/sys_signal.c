/* sys_signal.c — Signal handling syscalls */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "signal.h"
#include "tty.h"
#include "kbd.h"

/*
 * sys_rt_sigaction — syscall 13
 *
 * arg1 = signum, arg2 = user pointer to new k_sigaction_t (NULL = query),
 * arg3 = user pointer to old k_sigaction_t output (NULL = discard),
 * arg4 = sigset size in bytes (must be 8)
 *
 * Installs a signal handler for signum. Copies old handler to oldact if non-NULL.
 */
uint64_t
sys_rt_sigaction(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    if (arg4 != 8) return SYS_ERR(EINVAL);
    int signum = (int)arg1;
    if (signum <= 0 || signum >= 64) return SYS_ERR(EINVAL);
    /* Only SIGKILL and SIGSTOP are uncatchable (POSIX). SIGCONT IS catchable —
     * shells / foreground-pgrp managers install a SIGCONT handler to redraw the
     * prompt or re-signal children after being resumed. The old reject list
     * also barred SIGCONT, which was over-restrictive (and inconsistent with
     * sigprocmask/sigreturn, which only special-case SIGKILL|SIGSTOP). The
     * delivery path already handles a SIGCONT handler: signal_deliver checks
     * SIG_DFL (SIGCONT default = ignore/continue) before building a handler
     * frame, so an installed handler runs on resume as POSIX requires.
     * Recovered from the April audit (96d55a6), lost in refactoring. */
    if (signum == SIGKILL || signum == SIGSTOP)
        return SYS_ERR(EINVAL);

    aegis_process_t *proc = current_proc();

    /* Copy out old action first (before overwriting) */
    if (arg3 != 0) {
        COPY_TO_USER(arg3, &proc->sigactions[signum]);
    }

    /* Install new action */
    if (arg2 != 0) {
        k_sigaction_t sa;
        COPY_FROM_USER(&sa, arg2);
        /* Validate handler: must be SIG_DFL (0), SIG_IGN (1),
         * or a user-space address — never a kernel address. */
        if (sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN) {
            if (!user_ptr_valid((uint64_t)(uintptr_t)sa.sa_handler, 1))
                return SYS_ERR(EFAULT);
        }
        /* Validate restorer similarly if provided */
        if (sa.sa_restorer != 0) {
            if (!user_ptr_valid((uint64_t)(uintptr_t)sa.sa_restorer, 1))
                return SYS_ERR(EFAULT);
        }
        proc->sigactions[signum] = sa;
    }
    return 0;
}

/*
 * sys_rt_sigprocmask — syscall 14
 *
 * arg1 = how (SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2)
 * arg2 = user pointer to new sigset_t (uint64_t; NULL = query only)
 * arg3 = user pointer to old sigset_t output (NULL = discard)
 * arg4 = sigset size in bytes (must be 8)
 */
uint64_t
sys_rt_sigprocmask(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    if (arg4 != 8) return SYS_ERR(EINVAL);

    aegis_process_t *proc = current_proc();

    /* Copy out old mask */
    if (arg3 != 0) {
        COPY_TO_USER(arg3, &proc->signal_mask);
    }

    /* Apply new mask */
    if (arg2 != 0) {
        uint64_t newset;
        COPY_FROM_USER(&newset, arg2);
        switch (arg1) {
        case 0: proc->signal_mask |=  newset; break; /* SIG_BLOCK */
        case 1: proc->signal_mask &= ~newset; break; /* SIG_UNBLOCK */
        case 2: proc->signal_mask  =  newset; break; /* SIG_SETMASK */
        default: return SYS_ERR(EINVAL);
        }
        /* SIGKILL and SIGSTOP cannot be masked */
        proc->signal_mask &= ~((1ULL << SIGKILL) | (1ULL << SIGSTOP));
    }
    return 0;
}

/*
 * sys_rt_sigreturn — syscall 15
 *
 * Called by musl's __restore_rt after a signal handler returns.
 * frame->user_rsp points at the rt_sigframe_t.pretcode slot.
 *
 * Reads rt_sigframe_t from user stack, restores the full register context
 * (rip, rflags, rsp, r8-r15, rbx, rbp) into the syscall_frame_t, restores
 * signal_mask from uc_sigmask, and returns SIGRETURN_MAGIC to tell
 * syscall_entry.asm to skip signal delivery.
 */
uint64_t
sys_rt_sigreturn(syscall_frame_t *frame)
{
    aegis_process_t *proc = current_proc();

#ifdef __aarch64__
    /* AArch64: the handler returns via `ret` (x30 = restorer) — nothing was
     * popped off the user stack — and signal_deliver set SP_EL0 to the
     * rt_sigframe base. So the frame is exactly at SP_EL0, with NO x86-style
     * pretcode adjustment (subtracting 8 here reads the gregs one slot low,
     * restoring a garbage ELR from the stack → a wild jump). */
    uint64_t sigframe_addr = FRAME_SP(frame);
#else
    /* musl's __restore_rt calls sys_rt_sigreturn via SYSCALL with RSP still
     * pointing past the pretcode slot — the signal handler's `ret` already
     * popped pretcode (8 bytes) before jumping to __restore_rt.  Linux
     * compensates with `frame = regs->sp - sizeof(long)`.  Do the same: the
     * actual rt_sigframe_t starts at frame->user_rsp - 8. */
    uint64_t sigframe_addr = FRAME_SP(frame) - sizeof(uint64_t);
#endif
    if (!user_ptr_valid(sigframe_addr, sizeof(rt_sigframe_t))) {
        sched_exit(); /* signal frame corrupted — terminate */
        __builtin_unreachable();
    }
    rt_sigframe_t sf;
    copy_from_user(&sf, (const void *)(uintptr_t)sigframe_addr,
                   sizeof(sf));

    /* Restore interrupted execution context */
#ifdef __aarch64__
    /* Full GPR restore: signal_deliver saved x0-x30 into gregs[0..30];
     * the ERET path replays the whole frame, so every register must come
     * back from the (user-controlled) sigframe — then be sanitized. */
    for (int ri = 0; ri < 31; ri++)
        frame->regs[ri] = (uint64_t)sf.gregs[ri];
    FRAME_IP(frame) = (uint64_t)sf.gregs[REG_RIP];
    FRAME_SP(frame) = (uint64_t)sf.gregs[REG_RSP];

    /* SECURITY (X1 equivalent): the restored PC must be a user address —
     * a crafted frame must not make the kernel ERET into the higher half. */
    if (FRAME_IP(frame) > USER_ADDR_MAX) {
        sched_exit(); /* kernel PC in sigframe — kill the process */
        __builtin_unreachable();
    }

    /* SECURITY (X2 equivalent): sanitize the restored PSTATE. The sigframe
     * is user-controlled — a crafted SPSR could request EL1 (M[3:0]),
     * masked interrupts (DAIF), or debug single-step (SS). Preserve only
     * the arithmetic flags NZCV; force EL0t with interrupts enabled. */
    frame->spsr = (uint64_t)sf.gregs[REG_EFL] & 0xF0000000UL;
#else
    frame->rip      = (uint64_t)sf.gregs[REG_RIP];
    frame->rflags   = (uint64_t)sf.gregs[REG_EFL];
    frame->user_rsp = (uint64_t)sf.gregs[REG_RSP];
    frame->r8       = (uint64_t)sf.gregs[REG_R8];
    frame->r9       = (uint64_t)sf.gregs[REG_R9];
    frame->r10      = (uint64_t)sf.gregs[REG_R10];
    /* Restore callee-saved registers (C5 audit fix).  These are popped by
     * syscall_entry.asm after the frame body (r10/r9/r8). */
    frame->rbx      = (uint64_t)sf.gregs[REG_RBX];
    frame->rbp      = (uint64_t)sf.gregs[REG_RBP];
    frame->r12      = (uint64_t)sf.gregs[REG_R12];
    frame->r13      = (uint64_t)sf.gregs[REG_R13];
    frame->r14      = (uint64_t)sf.gregs[REG_R14];
    frame->r15      = (uint64_t)sf.gregs[REG_R15];

    /* SECURITY (X1): Validate restored RIP is canonical and in user space.
     * On Intel, SYSRET with a non-canonical RCX causes #GP in ring 0 — this
     * is the CVE-2014-4699 class of vulnerability. A malicious signal frame
     * could set RIP to a non-canonical address (e.g. 0x8000000000000000) to
     * trigger a kernel-mode #GP. Reject any RIP above the user-space ceiling. */
    if (frame->rip > 0x00007FFFFFFFFFFF) {
        sched_exit(); /* non-canonical or kernel RIP — kill the process */
        __builtin_unreachable();
    }

    /* SECURITY (X2): Sanitize restored RFLAGS to prevent privilege escalation.
     * The signal frame is user-controlled — a crafted frame could set:
     *   IF=0  → disable interrupts, hanging the system
     *   IOPL=3 → grant user-mode direct I/O port access
     *   NT=1  → crash on iret (nested task flag)
     *   TF=1  → single-step trap flood
     *   AC=1  → alignment check exceptions
     * Preserve only arithmetic flags (CF, PF, AF, ZF, SF, OF) and DF.
     * Force IF=1 (interrupts enabled), IOPL=0, NT=0, TF=0, AC=0. */
    frame->rflags = (frame->rflags & 0xCD5) | 0x202;
#endif

    /* Restore signal mask from saved uc_sigmask */
    proc->signal_mask = sf.uc_sigmask;
    /* SIGKILL and SIGSTOP cannot be masked */
    proc->signal_mask &= ~((1ULL << SIGKILL) | (1ULL << SIGSTOP));

    /* Return the interrupted syscall's saved rax (C6 saved it into
     * gregs[REG_RAX]). The syscall_entry.asm SYSRET path does NOT restore rax
     * from the frame — it sysrets with whatever this returns. Previously this
     * returned SIGRETURN_MAGIC (a flag for the asm to skip a second signal
     * check), which LEAKED 0xdeadbeefcafebabe into the interrupted syscall's
     * return value whenever a signal was delivered on a syscall's return path —
     * silently corrupting that syscall's result (e.g. an mmap address turning
     * into the poison value, crashing musl's pthread_create nondeterministically).
     * Returning the real saved rax fixes it; the asm's now-vestigial MAGIC
     * compare simply never matches and falls through to a normal (Linux-correct)
     * pending-signal check. */
    return (uint64_t)sf.gregs[REG_RAX];
}

/*
 * sys_rt_sigsuspend — syscall 130
 *
 * arg1 = user pointer to sigset_t (uint64_t mask)
 * arg2 = sigset size in bytes (must be 8)
 *
 * Atomically replaces the signal mask, blocks until a signal arrives, then
 * restores the original mask and returns -EINTR.  If a signal is already
 * pending and unmasked when sigsuspend is called, skips the block and returns
 * immediately so signal_deliver_sysret can run the handler.
 *
 * oksh's j_waitj() uses this to wait for foreground job completion:
 *   while (j->state == PRUNNING) sigsuspend(&sm_default);
 * SIGCHLD delivery (from sched_exit) wakes the block; the handler
 * j_sigchld() calls waitpid(-1, WNOHANG) and sets j->state = PEXITED.
 */
uint64_t
sys_rt_sigsuspend(uint64_t arg1, uint64_t arg2)
{
    if (arg2 != 8) return SYS_ERR(EINVAL);

    aegis_process_t *proc = current_proc();

    uint64_t newmask;
    COPY_FROM_USER(&newmask, arg1);
    /* SIGKILL and SIGSTOP cannot be masked */
    newmask &= ~((1ULL << SIGKILL) | (1ULL << SIGSTOP));

    uint64_t old_mask = proc->signal_mask;
    proc->signal_mask = newmask;

    /* Block only if no unmasked signal is already pending. */
    if (!(proc->pending_signals & ~newmask))
        sched_block();

    /* Restore original mask before returning — signal_deliver_sysret then
     * fires the pending handler (e.g. j_sigchld for SIGCHLD). */
    proc->signal_mask = old_mask;
    return SYS_ERR(EINTR);
}

/*
 * sys_kill — syscall 62
 *
 * arg1 = pid (target process ID), arg2 = signum
 *
 * Sends signal signum to process with PID pid.
 * pid < 0: deliver to process group -pid.
 * pid == 0: deliver to calling process's own group.
 * pid > 0: deliver to individual process.
 * signal_send_pid internally guards is_user before treating a task as aegis_process_t.
 */
uint64_t
sys_kill(uint64_t arg1, uint64_t arg2)
{
    int32_t  pid = (int32_t)(uint32_t)arg1;
    int      sig = (int)arg2;
    if (sig <= 0 || sig >= 64) return SYS_ERR(EINVAL);

    /* Capability gate: sending signals is a process management operation. */
    aegis_process_t *cur = current_proc();
    if (cap_check(cur->caps, CAP_TABLE_SIZE,
                  CAP_KIND_PROC_READ, CAP_RIGHTS_WRITE) < 0)
        return SYS_ERR(EPERM);

    /* S14: Signaling init (PID 1) requires CAP_KIND_POWER.
     * This allows the compositor's Power Off button to work while
     * preventing unprivileged processes from killing init. */
    if (pid == 1 && cur->pid != 1) {
        if (cap_check(cur->caps, CAP_TABLE_SIZE,
                      CAP_KIND_POWER, CAP_RIGHTS_READ) < 0)
            return SYS_ERR(EPERM);
    }

    if (pid < 0) {
        /* kill(-pgid, sig): deliver to entire process group */
        signal_send_pgrp((uint32_t)(-pid), sig);
        return 0;
    }
    if (pid == 0) {
        /* kill(0, sig): deliver to own process group */
        signal_send_pgrp(cur->pgid, sig);
        return 0;
    }
    signal_send_pid((uint32_t)pid, sig);
    return 0;
}

/*
 * sys_setfg — syscall 360 (Aegis private)
 *
 * arg1 = pid of the foreground process (0 = clear foreground)
 *
 * Registers the foreground PID with the keyboard driver so Ctrl-C sends
 * SIGINT to that process. The shell calls this before waitpid and clears
 * it after.
 */
uint64_t
sys_setfg(uint64_t arg1)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_PROC_READ, CAP_RIGHTS_WRITE) < 0)
        return SYS_ERR(EPERM);
    /* Set fg_pgrp on the caller's controlling terminal, not blindly the
     * console.  A shell inside a PTY must only affect its own PTY's
     * fg_pgrp — changing the console's fg_pgrp would SIGTTIN the
     * compositor (lumen) which continuously reads the console TTY. */
    tty_t *tty = tty_find_controlling(proc->sid);
    if (tty)
        tty->fg_pgrp = (uint32_t)arg1;
    else
        kbd_set_tty_pgrp((uint32_t)arg1);
    return 0;
}
