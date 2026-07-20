#include "signal.h"
#include "proc.h"
#include "sched.h"
#include "printk.h"
#include <stdint.h>

#ifdef __aarch64__
/* ARM64 signal delivery — builds a signal frame on the user stack
 * and redirects ELR to the signal handler. On sigreturn, the saved
 * registers are restored from the frame. */
#include "idt.h"
#include "syscall.h"
#include "uaccess.h"
#include "syscall_util.h"
#include "vmm.h"

void
signal_deliver(cpu_state_t *s)
{
    aegis_task_t *task = sched_current();
    if (!task || !task->is_user) return;

    aegis_process_t *proc = (aegis_process_t *)task;
    uint64_t deliverable = proc->pending_signals & ~proc->signal_mask;
    if (!deliverable) return;

    /* Find lowest pending signal */
    int signum;
    for (signum = 1; signum < 32; signum++) {
        if (deliverable & (1ULL << signum)) break;
    }
    if (signum >= 32) return;

    k_sigaction_t *sa = &proc->sigactions[signum];

    /* SIG_IGN — clear and return */
    if (sa->sa_handler == SIG_IGN) {
        (void)__atomic_and_fetch(&proc->pending_signals, ~(1ULL << signum), __ATOMIC_RELAXED);
        return;
    }

    /* SIG_DFL — terminate for most signals */
    if (sa->sa_handler == SIG_DFL) {
        (void)__atomic_and_fetch(&proc->pending_signals, ~(1ULL << signum), __ATOMIC_RELAXED);
        if (signum == SIGCHLD || signum == SIGCONT) return; /* ignore */
        proc->term_signal = (uint32_t)signum;
        proc->exit_status = 128 + signum;
        sched_exit();
        __builtin_unreachable();
    }

    /* Build signal frame on user stack — or the alternate signal stack if the
     * handler is SA_ONSTACK, one is installed, and we are not already on it
     * (sp not within its range, so nested SA_ONSTACK handlers stack correctly). */
    uint64_t user_sp = s->sp_el0;
    if ((sa->sa_flags & SA_ONSTACK) && proc->altstack_size != 0) {
        uint64_t lo = proc->altstack_sp, hi = proc->altstack_sp + proc->altstack_size;
        if (!(user_sp > lo && user_sp <= hi))
            user_sp = hi;                       /* top of the alt stack (grows down) */
    }
    uint64_t new_sp = (user_sp - sizeof(rt_sigframe_t)) & ~0xFUL; /* 16-byte align */

    /* Validate new_sp */
    if (new_sp >= user_sp || new_sp > USER_ADDR_MAX || new_sp < 0x1000) {
        proc->term_signal = (uint32_t)signum;
        proc->exit_status = 128 + signum;
        sched_exit();
        __builtin_unreachable();
    }

    rt_sigframe_t sf;
    /* Zero the frame */
    {
        uint8_t *p = (uint8_t *)&sf;
        uint64_t i;
        for (i = 0; i < sizeof(sf); i++) p[i] = 0;
    }

    /* Save registers into gregs */
    {
        int i;
        for (i = 0; i < 31; i++)
            sf.gregs[i] = (int64_t)s->x[i];
        sf.gregs[REG_SP]     = (int64_t)s->sp_el0;
        sf.gregs[REG_PC]     = (int64_t)s->elr;
        sf.gregs[REG_PSTATE] = (int64_t)s->spsr;
    }

    sf.pretcode  = (uint64_t)sa->sa_restorer;
    sf.uc_sigmask = proc->signal_mask;

    /* Copy frame to user stack */
    copy_to_user((void *)(uintptr_t)new_sp, &sf, sizeof(sf));

    /* Redirect execution to signal handler */
    s->elr    = (uint64_t)sa->sa_handler;
    s->sp_el0 = new_sp;
    s->x[0]   = (uint64_t)signum;  /* first argument = signal number */
    /* x30 (LR) = restorer: an AArch64 handler returns via `ret`, so LR must
     * point at the sa_restorer trampoline (which calls rt_sigreturn). The
     * x86 path relies on the handler's `ret` popping sf.pretcode off the
     * stack; on arm64 the return address is a register, so the kernel must
     * seed it here or the handler returns to a stale LR and crashes. */
    s->x[30]  = (uint64_t)sa->sa_restorer;

    /* Block the signal during handler execution */
    proc->signal_mask |= sa->sa_mask | (1ULL << signum);
    proc->signal_mask &= ~((1ULL << SIGKILL) | (1ULL << SIGSTOP));

    /* Clear pending */
    (void)__atomic_and_fetch(&proc->pending_signals, ~(1ULL << signum), __ATOMIC_RELAXED);
}

int
signal_deliver_sysret(syscall_frame_t *frame, uint64_t *saved_rdi_ptr)
{
    /* On ARM64, we only use the iretq-equivalent (ERET) path.
     * The sysret path is x86-specific. Check for pending signals
     * and deliver via the frame if needed. */
    (void)saved_rdi_ptr;

    aegis_task_t *task = sched_current();
    if (!task || !task->is_user) return 0;

    aegis_process_t *proc = (aegis_process_t *)task;
    uint64_t deliverable = proc->pending_signals & ~proc->signal_mask;
    if (!deliverable) return 0;

    /* Find lowest pending signal */
    int signum;
    for (signum = 1; signum < 32; signum++) {
        if (deliverable & (1ULL << signum)) break;
    }
    if (signum >= 32) return 0;

    k_sigaction_t *sa = &proc->sigactions[signum];

    if (sa->sa_handler == SIG_IGN) {
        (void)__atomic_and_fetch(&proc->pending_signals, ~(1ULL << signum), __ATOMIC_RELAXED);
        return 0;
    }
    if (sa->sa_handler == SIG_DFL) {
        (void)__atomic_and_fetch(&proc->pending_signals, ~(1ULL << signum), __ATOMIC_RELAXED);
        if (signum == SIGCHLD || signum == SIGCONT) return 0;
        proc->term_signal = (uint32_t)signum;
        proc->exit_status = 128 + signum;
        sched_exit();
        __builtin_unreachable();
    }

    /* Build frame on user stack — or the alternate signal stack if the handler
     * is SA_ONSTACK, one is installed, and we are not already on it. */
    uint64_t user_sp = frame->user_sp;
    if ((sa->sa_flags & SA_ONSTACK) && proc->altstack_size != 0) {
        uint64_t lo = proc->altstack_sp, hi = proc->altstack_sp + proc->altstack_size;
        if (!(user_sp > lo && user_sp <= hi))
            user_sp = hi;                       /* top of the alt stack (grows down) */
    }
    uint64_t new_sp = (user_sp - sizeof(rt_sigframe_t)) & ~0xFUL;

    if (new_sp >= user_sp || new_sp > USER_ADDR_MAX || new_sp < 0x1000) {
        proc->term_signal = (uint32_t)signum;
        proc->exit_status = 128 + signum;
        sched_exit();
        __builtin_unreachable();
    }

    rt_sigframe_t sf;
    {
        uint8_t *p = (uint8_t *)&sf;
        uint64_t i;
        for (i = 0; i < sizeof(sf); i++) p[i] = 0;
    }

    /* Save registers from syscall frame */
    {
        int i;
        for (i = 0; i < 31; i++)
            sf.gregs[i] = (int64_t)frame->regs[i];
        sf.gregs[REG_SP]     = (int64_t)frame->user_sp;
        sf.gregs[REG_PC]     = (int64_t)frame->elr;
        sf.gregs[REG_PSTATE] = (int64_t)frame->spsr;
    }

    sf.pretcode   = (uint64_t)sa->sa_restorer;
    sf.uc_sigmask = proc->signal_mask;

    copy_to_user((void *)(uintptr_t)new_sp, &sf, sizeof(sf));

    FRAME_IP(frame) = (uint64_t)sa->sa_handler;
    FRAME_SP(frame) = new_sp;
    frame->regs[0]  = (uint64_t)signum;

    proc->signal_mask |= sa->sa_mask | (1ULL << signum);
    proc->signal_mask &= ~((1ULL << SIGKILL) | (1ULL << SIGSTOP));
    (void)__atomic_and_fetch(&proc->pending_signals, ~(1ULL << signum), __ATOMIC_RELAXED);

    return 1;
}

#else /* x86-64 */
#include "arch.h"
#include "uaccess.h"
#include "syscall_util.h"
#include "idt.h"
#include "syscall.h"
#include "vmm.h"

/* signal_terminate — record the cause of death, then exit.
 * term_signal lets sys_waitpid encode WIFSIGNALED (wstatus = signum) so
 * parents see signal deaths as such instead of exit(0); exit_status keeps
 * the 128+signum convention for raw readers (matches the ARM64 path). */
static void
signal_terminate(aegis_process_t *proc, int signum)
{
    /* Log the death — a fatal default-action signal used to kill a process
     * with zero trace, which made "the desktop silently vanished" class bugs
     * (e.g. a compositor SIGPIPE) undiagnosable in the field. One line, only
     * on abnormal termination, mirroring Linux's segfault report. */
    printk("[SIGNAL] pid=%u %s killed by signal %d\n",
           proc->pid, proc->exe_path, signum);
    proc->term_signal = (uint32_t)signum;
    proc->exit_status = 128 + (uint64_t)signum;
    sched_exit();
    __builtin_unreachable();
}

/*
 * signal_deliver — deliver the highest-priority pending signal when returning
 * to ring 3 via iretq. Called from isr.asm between isr_dispatch and
 * isr_post_dispatch, with CR3=master PML4 and IF=0.
 *
 * s->cs == ARCH_KERNEL_CS means returning to kernel mode (IRQ fired in kernel
 * hlt loop) — do not deliver. Only deliver to ring-3 (cs=ARCH_USER_CS).
 */
void
signal_deliver(cpu_state_t *s)
{
    /* Only deliver to ring-3 returns */
    if (s->cs != ARCH_USER_CS) return;

    aegis_task_t *task = sched_current();
    if (!task || !task->is_user) return;
    aegis_process_t *proc = (aegis_process_t *)task;

    uint64_t deliverable = proc->pending_signals & ~proc->signal_mask;
    if (!deliverable) return;

    int signum = (int)__builtin_ctzll(deliverable);
    (void)__atomic_and_fetch(&proc->pending_signals, ~(1ULL << (uint32_t)signum), __ATOMIC_RELAXED);

    k_sigaction_t *sa = &proc->sigactions[signum];

    if (sa->sa_handler == SIG_DFL) {
        if (signum == SIGCHLD || signum == SIGCONT) return; /* ignore */
        if (signum == SIGTSTP || signum == SIGSTOP ||
            signum == SIGTTIN || signum == SIGTTOU) {
            proc->stop_signum = (uint32_t)signum;
            /* Notify parent in case it's blocked in waitpid(WUNTRACED) */
            signal_send_pid(proc->ppid, SIGCHLD);
            sched_stop((aegis_task_t *)task);  /* yields; returns on SIGCONT */
            return;
        }
        signal_terminate(proc, signum);  /* all other SIG_DFL signals */
    }

    if (sa->sa_handler == SIG_IGN) return;

    /* Validate handler and restorer are user-space addresses.
     * A kernel-VA handler would execute kernel code at ring-3 privilege.
     * user_ptr_valid checks address is canonical and below 0x800000000000. */
    if (!user_ptr_valid((uint64_t)sa->sa_handler, 1)) {
        signal_terminate(proc, signum);  /* bad handler address */
    }
    if (sa->sa_restorer && !user_ptr_valid((uint64_t)sa->sa_restorer, 1)) {
        signal_terminate(proc, signum);  /* bad restorer address */
    }

    /* User handler: build rt_sigframe_t on user stack, redirect iretq to handler.
     * SA_ONSTACK: use the alternate signal stack if installed and we are not
     * already on it (so nested SA_ONSTACK handlers stack correctly). */
    uint64_t user_rsp = s->rsp;  /* user RSP from the iretq frame */
    if ((sa->sa_flags & SA_ONSTACK) && proc->altstack_size != 0) {
        uint64_t lo = proc->altstack_sp, hi = proc->altstack_sp + proc->altstack_size;
        if (!(user_rsp > lo && user_rsp <= hi))
            user_rsp = hi;                      /* top of the alt stack (grows down) */
    }
    uint64_t new_rsp  = ((user_rsp - sizeof(rt_sigframe_t)) & ~15ULL) - 8;

    rt_sigframe_t sf;
    __builtin_memset(&sf, 0, sizeof(sf));
    sf.pretcode            = (uint64_t)sa->sa_restorer;
    /* Fill mcontext from cpu_state_t */
    sf.gregs[REG_R8]       = (int64_t)s->r8;
    sf.gregs[REG_R9]       = (int64_t)s->r9;
    sf.gregs[REG_R10]      = (int64_t)s->r10;
    sf.gregs[REG_R11]      = (int64_t)s->r11;
    sf.gregs[REG_R12]      = (int64_t)s->r12;
    sf.gregs[REG_R13]      = (int64_t)s->r13;
    sf.gregs[REG_R14]      = (int64_t)s->r14;
    sf.gregs[REG_R15]      = (int64_t)s->r15;
    sf.gregs[REG_RDI]      = (int64_t)s->rdi;
    sf.gregs[REG_RSI]      = (int64_t)s->rsi;
    sf.gregs[REG_RBP]      = (int64_t)s->rbp;
    sf.gregs[REG_RBX]      = (int64_t)s->rbx;
    sf.gregs[REG_RDX]      = (int64_t)s->rdx;
    sf.gregs[REG_RAX]      = (int64_t)s->rax;
    sf.gregs[REG_RCX]      = (int64_t)s->rcx;
    sf.gregs[REG_RSP]      = (int64_t)s->rsp;
    sf.gregs[REG_RIP]      = (int64_t)s->rip;
    sf.gregs[REG_EFL]      = (int64_t)s->rflags;
    sf.gregs[REG_CSGSFS]   = (int64_t)s->cs;
    sf.uc_sigmask          = proc->signal_mask;

    /* Validate the destination before writing — terminate if the frame
     * address is not in user space (signal stack overflow or bad RSP). */
    if (!user_ptr_valid(new_rsp, sizeof(sf))) {
        signal_terminate(proc, signum);  /* bad sigframe address */
    }

    /* signal_deliver is called while CR3 = master PML4 (isr_common_stub
     * switches CR3 before calling isr_dispatch and this function).
     * The user stack pages are only mapped in the process's user PML4.
     * Switch to the user PML4 for copy_to_user, then back to master so
     * the rest of the kernel (isr_post_dispatch, printk, etc.) can access
     * kva-mapped objects.  isr_post_dispatch will restore the saved CR3
     * from the stack slot after this function returns. */
    vmm_switch_to(proc->pml4_phys);
    copy_to_user((void *)new_rsp, &sf, sizeof(sf));
    vmm_switch_to(vmm_get_master_pml4());

    /* Redirect iretq to handler */
    s->rip    = (uint64_t)sa->sa_handler;
    s->rsp    = new_rsp;
    s->rdi    = (uint64_t)signum;  /* first arg to handler */
    s->rax    = 0;

    /* Mask: block this signal and sa_mask while handler runs */
    proc->signal_mask |= sa->sa_mask | (1ULL << (uint32_t)signum);
}

/*
 * signal_deliver_sysret — deliver pending signal on the syscall return path.
 *
 * frame:          syscall_frame_t * — patch rip/user_rsp for user handler delivery
 * saved_rdi_ptr:  pointer to saved user rdi slot on kernel stack; write signum here
 *                 so that `pop rdi` in syscall_entry.asm loads the signal number
 *                 as the first argument to the handler.
 *
 * Returns 0 if no signal or SIG_DFL action (sched_exit never returns for SIG_DFL).
 * Returns 1 if a user handler was installed (caller sets rax=0, does sysret).
 *
 * syscall_frame_t includes callee-saved registers (rbx, rbp, r12-r15)
 * pushed by syscall_entry.asm.  All saved registers are written to the
 * signal frame's gregs[] so sys_rt_sigreturn can restore the full context.
 *
 * rdi/rsi/rdx are read from saved_rdi_ptr (pushed separately in the asm
 * for Linux ABI preservation).  rax (syscall result) is passed via rdi
 * slot overwrite.  rcx and r11 are set to rip and rflags respectively
 * (the SYSCALL instruction overwrites the originals).
 */
int
signal_deliver_sysret(syscall_frame_t *frame, uint64_t *saved_rdi_ptr)
{
    aegis_task_t *task = sched_current();
    if (!task || !task->is_user) return 0;
    aegis_process_t *proc = (aegis_process_t *)task;

    uint64_t deliverable = proc->pending_signals & ~proc->signal_mask;
    if (!deliverable) return 0;

    int signum = (int)__builtin_ctzll(deliverable);
    (void)__atomic_and_fetch(&proc->pending_signals, ~(1ULL << (uint32_t)signum), __ATOMIC_RELAXED);

    k_sigaction_t *sa = &proc->sigactions[signum];

    if (sa->sa_handler == SIG_DFL) {
        if (signum == SIGCHLD || signum == SIGCONT) return 0; /* ignore */
        if (signum == SIGTSTP || signum == SIGSTOP ||
            signum == SIGTTIN || signum == SIGTTOU) {
            proc->stop_signum = (uint32_t)signum;
            signal_send_pid(proc->ppid, SIGCHLD);
            sched_stop((aegis_task_t *)task);  /* yields; returns on SIGCONT */
            return 0;
        }
        signal_terminate(proc, signum);  /* never returns */
    }

    if (sa->sa_handler == SIG_IGN) return 0;

    /* Validate handler and restorer are user-space addresses.
     * A kernel-VA handler would execute kernel code at ring-3 privilege.
     * user_ptr_valid checks address is canonical and below 0x800000000000. */
    if (!user_ptr_valid((uint64_t)sa->sa_handler, 1)) {
        signal_terminate(proc, signum);  /* bad handler address */
    }
    if (sa->sa_restorer && !user_ptr_valid((uint64_t)sa->sa_restorer, 1)) {
        signal_terminate(proc, signum);  /* bad restorer address */
    }

    /* User handler: build rt_sigframe_t on user stack (or the alternate signal
     * stack if the handler is SA_ONSTACK and one is installed). */
    uint64_t user_rsp = frame->user_rsp;
    if ((sa->sa_flags & SA_ONSTACK) && proc->altstack_size != 0) {
        uint64_t lo = proc->altstack_sp, hi = proc->altstack_sp + proc->altstack_size;
        if (!(user_rsp > lo && user_rsp <= hi))
            user_rsp = hi;                      /* top of the alt stack (grows down) */
    }
    uint64_t new_rsp  = ((user_rsp - sizeof(rt_sigframe_t)) & ~15ULL) - 8;

    rt_sigframe_t sf;
    __builtin_memset(&sf, 0, sizeof(sf));
    sf.pretcode          = (uint64_t)sa->sa_restorer;
    /* Save all registers from the expanded syscall_frame_t.
     * Callee-saved (rbx/rbp/r12-r15) are pushed by syscall_entry.asm Step 2b.
     * Without these, sigreturn would zero them (C5 audit fix). */
    sf.gregs[REG_R8]     = (int64_t)frame->r8;
    sf.gregs[REG_R9]     = (int64_t)frame->r9;
    sf.gregs[REG_R10]    = (int64_t)frame->r10;
    sf.gregs[REG_R11]    = (int64_t)frame->rflags;  /* R11 = RFLAGS per SYSCALL */
    sf.gregs[REG_R12]    = (int64_t)frame->r12;
    sf.gregs[REG_R13]    = (int64_t)frame->r13;
    sf.gregs[REG_R14]    = (int64_t)frame->r14;
    sf.gregs[REG_R15]    = (int64_t)frame->r15;
    sf.gregs[REG_RBX]    = (int64_t)frame->rbx;
    sf.gregs[REG_RBP]    = (int64_t)frame->rbp;
    sf.gregs[REG_RCX]    = (int64_t)frame->rip;     /* RCX = return RIP per SYSCALL */
    /* rdi/rsi/rdx are saved separately by the asm (Linux ABI preservation).
     * Read them from saved_rdi_ptr stack layout. */
    sf.gregs[REG_RDI]    = (int64_t)*saved_rdi_ptr;
    sf.gregs[REG_RSI]    = (int64_t)*(saved_rdi_ptr - 1);
    sf.gregs[REG_RDX]    = (int64_t)*(saved_rdi_ptr - 2);
    /* C6: save syscall return value (rax) so sigreturn restores it.
     * The asm pushes rax before calling us: saved_rdi_ptr[-3] = rax. */
    sf.gregs[REG_RAX]    = (int64_t)*(saved_rdi_ptr - 3);
    sf.gregs[REG_RIP]    = (int64_t)frame->rip;
    sf.gregs[REG_EFL]    = (int64_t)frame->rflags;
    sf.gregs[REG_RSP]    = (int64_t)frame->user_rsp;
    sf.uc_sigmask        = proc->signal_mask;

    if (!user_ptr_valid(new_rsp, sizeof(sf))) {
        signal_terminate(proc, signum);  /* bad sigframe address */
    }

    copy_to_user((void *)new_rsp, &sf, sizeof(sf));

    /* Patch sysret frame: return to handler instead of original RIP */
    frame->rip      = (uint64_t)sa->sa_handler;
    frame->user_rsp = new_rsp;

    /* Write signum to the saved rdi slot so pop rdi loads it as handler arg1 */
    *saved_rdi_ptr = (uint64_t)signum;

    proc->signal_mask |= sa->sa_mask | (1ULL << (uint32_t)signum);
    return 1;
}

#endif /* !__aarch64__ — end of arch-specific signal_deliver/signal_deliver_sysret */

/* ── Architecture-agnostic signal functions ──────────────────────── */

/* sched_lock protects the global circular task list — defined in sched.c.
 * Every ->next walk below must hold it: sched_add (fork/clone/spawn) and
 * the sys_waitpid zombie unlink mutate the chain concurrently on SMP. */
extern spinlock_t sched_lock;

void
signal_send_pid(uint32_t pid, int signum)
{
    if (pid == 0 || signum <= 0 || signum >= 64) return;

    aegis_task_t *cur = sched_current();
    if (!cur) return;

    /* Walk under sched_lock.  The wake must use the _locked variant —
     * calling sched_wake here would re-acquire the non-recursive
     * sched_lock and self-deadlock.  Callers must NOT hold sched_lock
     * (sched_exit uses signal_send_pid_locked instead). */
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    aegis_task_t *t = cur;
    do {
        if (t->is_user) {
            aegis_process_t *p = (aegis_process_t *)t;
            if (p->pid == pid) {
                /* SMP: RMW-atomic OR so a set on another CPU isn't lost. */
                (void)__atomic_or_fetch(&p->pending_signals, (1ULL << (uint32_t)signum), __ATOMIC_RELAXED);
                /* Mark a wake even if the target is RUNNING and not (yet) in a
                 * blocking primitive. sys_rt_sigsuspend (and pause()) does
                 * `mask = new; if (!pending_unmasked) sched_block();` — a signal
                 * delivered from an ISR (e.g. Ctrl-C) in the window between that
                 * check and sched_block() finds the task RUNNING, so the wake
                 * below is skipped and wake_pending stays 0 → the task blocks
                 * with the signal pending and no waker → missed/dropped signal.
                 * Setting wake_pending makes the upcoming sched_block() return
                 * immediately so the caller re-checks. Safe per the M4 contract:
                 * every sched_block caller loops, so a spurious wake_pending on a
                 * task that does not imminently block just costs one extra loop
                 * iteration at its next block. */
                t->wake_pending = 1;
                /* A BLOCKED task wakes on any signal (its interruptible wait
                 * loop re-checks via signal_check_pending). A STOPPED task —
                 * stopped by kill(pid,SIGSTOP)/SIGTSTP, out of the run queue —
                 * must be resumed ONLY by SIGCONT, or forced to die by SIGKILL.
                 * Both were previously broken: signal_send_pid only woke
                 * BLOCKED, so kill(pid,SIGCONT) and kill(pid,SIGKILL) to a
                 * stopped process were no-ops (it stayed stopped forever). Other
                 * signals must NOT continue a stopped process (POSIX) — they
                 * stay pending until it is continued, so they do not wake it
                 * here (a blanket STOPPED-wake would let an incoming SIGCHLD/etc.
                 * prematurely resume a stopped job). */
                if (t->state == TASK_BLOCKED ||
                    (t->state == TASK_STOPPED &&
                     (signum == SIGCONT || signum == SIGKILL)))
                    sched_wake_locked(t);
                break;
            }
        }
        t = t->next;
    } while (t != cur);
    spin_unlock_irqrestore(&sched_lock, fl);
}

void
signal_send_pid_locked(uint32_t pid, int signum)
{
    /* Same as signal_send_pid but caller holds sched_lock.
     * Used by sched_exit to notify parent of SIGCHLD without releasing
     * sched_lock.  Calls sched_wake_locked so we do not attempt to
     * re-acquire the lock recursively. */
    if (pid == 0 || signum <= 0 || signum >= 64) return;

    aegis_task_t *cur = sched_current();
    if (!cur) return;
    aegis_task_t *t = cur;
    do {
        if (t->is_user) {
            aegis_process_t *p = (aegis_process_t *)t;
            if (p->pid == pid) {
                /* SMP: RMW-atomic OR so a set on another CPU isn't lost. */
                (void)__atomic_or_fetch(&p->pending_signals, (1ULL << (uint32_t)signum), __ATOMIC_RELAXED);
                /* wake_pending closes the sigsuspend check→block window — see
                 * signal_send_pid for the full rationale. */
                t->wake_pending = 1;
                /* Wake BLOCKED on any signal; wake STOPPED only for SIGCONT/
                 * SIGKILL — see signal_send_pid for the full rationale. */
                if (t->state == TASK_BLOCKED ||
                    (t->state == TASK_STOPPED &&
                     (signum == SIGCONT || signum == SIGKILL)))
                    sched_wake_locked(t);
                return;
            }
        }
        t = t->next;
    } while (t != cur);
}

void
signal_send_pgrp(uint32_t pgid, int signum)
{
    if (pgid == 0 || signum <= 0 || signum >= 64) return;

    aegis_task_t *cur = sched_current();
    if (!cur) return;

    /* Walk under sched_lock (see signal_send_pid).  sched_wake_locked
     * covers both the STOPPED and BLOCKED cases: it is identical to
     * sched_resume's body (atomic RUNNING flip + run-list insert), minus
     * the lock acquisition we already did.  Safe from ISR context: every
     * sched_lock holder runs with IF=0, so an ISR can never interrupt a
     * holder on its own CPU (tty_receive_isig relies on this — see the
     * comment block in tty.c). */
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    aegis_task_t *t = cur;
    do {
        if (t->is_user) {
            aegis_process_t *p = (aegis_process_t *)t;
            if (p->pgid == pgid && p->pid != 1) {
                /* SMP: RMW-atomic OR so a set on another CPU isn't lost. */
                (void)__atomic_or_fetch(&p->pending_signals, (1ULL << (uint32_t)signum), __ATOMIC_RELAXED);
                /* wake_pending closes the sigsuspend check→block window — see
                 * signal_send_pid for the full rationale. */
                t->wake_pending = 1;
                /* BLOCKED wakes on any signal; STOPPED only for SIGCONT/SIGKILL
                 * (a stopped job must not be continued by an unrelated signal —
                 * POSIX).  Ctrl-Z/Ctrl-C target a RUNNING foreground group, and
                 * `fg` sends SIGCONT, so normal job control is unaffected. */
                if (t->state == TASK_BLOCKED ||
                    (t->state == TASK_STOPPED &&
                     (signum == SIGCONT || signum == SIGKILL)))
                    sched_wake_locked(t);
            }
        }
        t = t->next;
    } while (t != cur);
    spin_unlock_irqrestore(&sched_lock, fl);
}

int
signal_check_pending(void)
{
    aegis_task_t *task = sched_current();
    if (!task) return 0;
    if (!task->is_user) return 0;
    aegis_process_t *proc = (aegis_process_t *)task;

    /* A blocking syscall must only be interrupted by a signal that will
     * actually be ACTED ON — i.e. one that runs a handler or terminates
     * the process.  A signal whose disposition is SIG_IGN, or a
     * default-ignored signal (SIGCHLD/SIGCONT under SIG_DFL), must be
     * invisible to the blocked task: it stays pending and the read
     * resumes.  Counting ignored signals here returned EINTR/EOF
     * spuriously — e.g. a background child exiting sent SIGCHLD (SIG_IGN
     * in the shell), which kicked the shell's readline out with EOF and
     * killed the session. */
    uint64_t pending = proc->pending_signals & ~proc->signal_mask;
    while (pending) {
        int signum = (int)__builtin_ctzll(pending);
        pending &= ~(1ULL << (uint32_t)signum);
        void (*h)(int) = proc->sigactions[signum].sa_handler;
        if (h == SIG_IGN)
            continue;
        if (h == SIG_DFL && (signum == SIGCHLD || signum == SIGCONT))
            continue;   /* default action is "ignore" — no interrupt */
        return 1;       /* this one will be delivered */
    }
    return 0;
}
