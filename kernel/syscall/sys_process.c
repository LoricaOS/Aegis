/* sys_process.c — Process lifecycle syscalls: exit, fork, clone, waitpid */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "signal.h"
#include "vfs.h"
#include "vmm.h"
#include "kva.h"
#include "tty.h"
#include "printk.h"
#include "trace.h"
#include "arch.h"
#include "futex.h"
#include "vma.h"
#include "tlb.h"   /* tlb_flush_all_cpus — COW write-protect SMP shootdown */

/* Boot-flag globals (parsed from the kernel cmdline in main.c). See proc.h. */
int g_cow_fork     = 1;   /* DEFAULT-ON; `nocow` cmdline forces eager copy     */
int g_perfbench_mm = 0;   /* `perfbench_mm` — print [PERFMM] fork timing     */

/* sched_lock protects the global circular task list (and the RUNNING-only
 * run queue) — defined in sched.c.  Every ->next walk in this file must
 * hold it: sched_add (fork/clone/spawn) and the sys_waitpid zombie unlink
 * mutate the chain concurrently on SMP. */
extern spinlock_t sched_lock;

/* s_fork_count — live user-process count, capped at MAX_PROCESSES.
 * Incremented by fork/clone (here) and spawn (proc_inc_fork_count),
 * decremented on reap in sys_waitpid.  Plain int updates would lose
 * counts under SMP, so all accesses use __atomic builtins (RELAXED:
 * pure resource counter, no ordering conveyed).  The check-then-inc in
 * fork/clone is not a single atomic op, so concurrent forks at the limit
 * can overshoot by at most (#CPUs - 1) — accepted, like Linux. */
static uint32_t s_fork_count = 1;  /* starts at 1 for init */

uint32_t proc_fork_count(void)
{
    return __atomic_load_n(&s_fork_count, __ATOMIC_RELAXED);
}

void proc_inc_fork_count(void)
{
    __atomic_fetch_add(&s_fork_count, 1, __ATOMIC_RELAXED);
}

/* ── Clone flags (Linux ABI) ──────────────────────────────────────────────── */
#define CLONE_VM             0x00000100u
#define CLONE_FS             0x00000200u
#define CLONE_FILES          0x00000400u
#define CLONE_SIGHAND        0x00000800u
#define CLONE_VFORK          0x00004000u
#define CLONE_THREAD         0x00010000u
#define CLONE_SYSVSEM        0x00040000u
#define CLONE_SETTLS         0x00080000u
#define CLONE_PARENT_SETTID  0x00100000u
#define CLONE_CHILD_CLEARTID 0x00200000u
#define CLONE_CHILD_SETTID   0x01000000u
#define CLONE_DETACHED       0x00400000u   /* legacy no-op; musl pthread sets it */

/* Flags we recognise. Some are real semantics (VM/THREAD/SETTLS/…), others
 * (DETACHED) are legacy no-ops the C library still ORs in. Any bit OUTSIDE this
 * mask is unimplemented and must be REJECTED rather than silently downgraded to
 * a plain thread clone: a caller asking for CLONE_NEWUSER / CLONE_NEWPID /
 * CLONE_NEW{NET,NS,UTS,IPC} expects real namespace isolation, and CLONE_PIDFD /
 * CLONE_IO / CLONE_PTRACE expect their documented behavior.
 *
 * CLONE_DETACHED IS in the mask: musl's pthread_create unconditionally sets it
 * (src/thread/pthread_create.c) — omitting it would EINVAL every thread create
 * and break all userspace threading (the audit-branch mask had this bug). */
#define CLONE_IMPLEMENTED_MASK \
    (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VFORK | \
     CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | \
     CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | CLONE_DETACHED)

/*
 * sys_exit — syscall 60
 *
 * arg1 = exit code (stored in proc->exit_status, returned by waitpid)
 * Calls sched_exit() which never returns.
 */
uint64_t
sys_exit(uint64_t arg1)
{
    if (sched_current()->is_user) {
        aegis_process_t *proc = current_proc();
        proc->exit_status = arg1 & 0xFF;

        /* Thread (non-leader) exit: decrement the leader's thread_count so any
         * consumer of the count sees an accurate live-thread total. The counter
         * is only incremented in sys_clone on CLONE_THREAD creation; without a
         * matching decrement here every thread exit silently inflates it for the
         * leader's lifetime. Advisory only (the waitpid leader-reap guard scans
         * task state directly, not this counter), so the unlocked read/modify is
         * acceptable. proc_find_by_pid takes sched_lock internally — call it
         * here, before this function acquires any lock. */
        if (proc->tgid != proc->pid) {
            aegis_process_t *leader = proc_find_by_pid(proc->tgid);
            if (leader && leader->thread_count > 0)
                leader->thread_count--;
        }

        /* clear_child_tid: write 0 and futex wake (for pthread_join) */
        if (sched_current()->clear_child_tid) {
            uint32_t zero = 0;
            /* Fault in the (possibly lazy-mmap'd) TLS page before writing —
             * vmm_write_user_bytes silently drops writes to not-present pages. */
            if (user_ptr_valid(sched_current()->clear_child_tid, sizeof(zero)))
                vmm_write_user_bytes(proc->pml4_phys,
                                     sched_current()->clear_child_tid,
                                     &zero, sizeof(zero));
            futex_wake_addr(sched_current()->clear_child_tid, 1, proc->pml4_phys);
        }

        /* Session leader exit: SIGHUP + SIGCONT to foreground group */
        if (proc->pid == proc->sid) {
            tty_t *ctty = tty_find_controlling(proc->sid);
            if (ctty && ctty->fg_pgrp) {
                signal_send_pgrp(ctty->fg_pgrp, SIGHUP);
                signal_send_pgrp(ctty->fg_pgrp, SIGCONT);
                ctty->session_id = 0; /* disassociate terminal */
            }
        }

        if (proc->pid == 1) {
            printk("[INIT] PID 1 exited with status %u — halting\n",
                   (uint32_t)(arg1 & 0xFF));
            arch_request_shutdown();
        }

        /* C2: Reparent orphan children to init (PID 1) so they can be
         * reaped by waitpid instead of staying as zombies forever.
         * Walk under sched_lock — the list mutates concurrently on SMP. */
        {
            irqflags_t fl = spin_lock_irqsave(&sched_lock);
            aegis_task_t *t = sched_current()->next;
            while (t != sched_current()) {
                if (t->is_user) {
                    aegis_process_t *child = (aegis_process_t *)t;
                    if (child->ppid == proc->pid)
                        child->ppid = 1;
                }
                t = t->next;
            }
            spin_unlock_irqrestore(&sched_lock, fl);
        }
    }
    sched_exit();
    __builtin_unreachable();
}

/* ── exit_group ────────────────────────────────────────────────────────── */
uint64_t sys_exit_group(uint64_t arg1)
{
    aegis_task_t *cur = sched_current();
    if (cur->is_user) {
        aegis_process_t *proc = (aegis_process_t *)cur;
        proc->exit_status = arg1 & 0xFF;

        /* Kill all other threads in the same thread group.
         *
         * The walk and the ZOMBIE flips run under sched_lock: the list
         * mutates concurrently on SMP, and the run-queue unlink must be
         * atomic with the state flip (a bare state write would leave the
         * zombie in the RUNNING-only run list, which sched_tick would
         * happily keep scheduling).  clear_child_tid writes and futex
         * wakes are deferred until after the unlock — futex_wake_addr
         * calls sched_wake, which re-acquires the non-recursive
         * sched_lock (self-deadlock), and vmm_write_user_bytes is too
         * heavyweight for a sched_lock critical section.  Only captured
         * values (pml4 phys, ctid VA) are used after the unlock: a
         * sibling zombie can be reaped and freed the instant the lock
         * drops, so the task pointers must not be dereferenced again. */
        uint32_t my_tgid = proc->tgid;
        struct { uint64_t pml4; uint64_t ctid; } tid_clears[MAX_PROCESSES];
        uint32_t n_clears = 0;
        {
            irqflags_t fl = spin_lock_irqsave(&sched_lock);
            aegis_task_t *t = cur->next;
            while (t != cur) {
                if (t->is_user) {
                    aegis_process_t *tp = (aegis_process_t *)t;
                    if (tp->tgid == my_tgid) {
                        t->state = TASK_ZOMBIE;
                        sched_dequeue_locked(t);
                        /* Do clear_child_tid for killed threads too */
                        if (t->clear_child_tid &&
                            n_clears < MAX_PROCESSES) {
                            tid_clears[n_clears].pml4 = tp->pml4_phys;
                            tid_clears[n_clears].ctid = t->clear_child_tid;
                            n_clears++;
                        }
                    }
                }
                t = t->next;
            }
            spin_unlock_irqrestore(&sched_lock, fl);
        }
        for (uint32_t k = 0; k < n_clears; k++) {
            uint32_t zero = 0;
            /* Same address space (CLONE_VM); fault in the lazy TLS page. */
            if (user_ptr_valid(tid_clears[k].ctid, sizeof(zero)))
                vmm_write_user_bytes(tid_clears[k].pml4, tid_clears[k].ctid,
                                     &zero, sizeof(zero));
            futex_wake_addr(tid_clears[k].ctid, 1, tid_clears[k].pml4);
        }

        /* Session leader exit: SIGHUP + SIGCONT to foreground group */
        if (proc->pid == proc->sid) {
            tty_t *ctty = tty_find_controlling(proc->sid);
            if (ctty && ctty->fg_pgrp) {
                signal_send_pgrp(ctty->fg_pgrp, SIGHUP);
                signal_send_pgrp(ctty->fg_pgrp, SIGCONT);
                ctty->session_id = 0; /* disassociate terminal */
            }
        }

        if (proc->pid == 1 || proc->tgid == 1) {
            printk("[INIT] PID 1 exited with status %u — halting\n",
                   (uint32_t)(arg1 & 0xFF));
            arch_request_shutdown();
        }

        /* C2: Reparent orphan children to init (PID 1).
         * Walk under sched_lock — the list mutates concurrently on SMP. */
        {
            irqflags_t fl = spin_lock_irqsave(&sched_lock);
            aegis_task_t *t = sched_current()->next;
            while (t != sched_current()) {
                if (t->is_user) {
                    aegis_process_t *child = (aegis_process_t *)t;
                    if (child->ppid == proc->pid)
                        child->ppid = 1;
                }
                t = t->next;
            }
            spin_unlock_irqrestore(&sched_lock, fl);
        }
    }
    sched_exit();
    __builtin_unreachable();
}

/*
 * sys_clone — syscall 56
 *
 * Creates a new thread (CLONE_VM) or delegates to sys_fork (no CLONE_VM).
 *
 * flags       = clone flags | signal_number (low byte stripped)
 * child_stack = user stack pointer for new thread (0 = copy parent's)
 * ptid        = user pointer for CLONE_PARENT_SETTID
 * ctid        = user pointer for CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID
 * tls         = TLS pointer for CLONE_SETTLS
 */
uint64_t
sys_clone(syscall_frame_t *frame, uint64_t flags, uint64_t child_stack,
          uint64_t ptid, uint64_t ctid, uint64_t tls,
          uint64_t u_rdi, uint64_t u_rsi, uint64_t u_rdx)
{
    /* u_rdi/u_rsi/u_rdx are the caller's raw rdi/rsi/rdx at syscall entry (the x86
     * syscall_frame_t doesn't save them). For a real clone they equal flags/
     * child_stack/ptid; for a vfork routed here (sys_vfork) they are the vfork
     * caller's registers — and musl's vfork asm keeps its RETURN ADDRESS in rdx,
     * so the child frame must carry it (a zeroed rdx → child rets to 0 → SIGSEGV). */
    /* Strip low byte (signal number — ignored). */
    uint32_t cl = (uint32_t)(flags & ~0xFFu);

    /* Reject any flag bit we don't implement so callers asking for namespace
     * isolation (CLONE_NEW*), pidfd handles (CLONE_PIDFD), CLONE_IO, or ptrace
     * bits don't get silently downgraded to a plain thread/fork clone. The
     * recognised set (incl. the legacy CLONE_DETACHED that musl sets) is in
     * CLONE_IMPLEMENTED_MASK above. */
    if (cl & ~(uint32_t)CLONE_IMPLEMENTED_MASK)
        return SYS_ERR(EINVAL);

    /* Without CLONE_VM this is a plain fork. Pass the caller's rdi/rsi/rdx
     * (= flags/child_stack/ptid for a clone) so the child inherits them. */
    if (!(cl & CLONE_VM))
        return sys_fork(frame, flags, child_stack, ptid);

    /* ── Thread creation (CLONE_VM set) ─────────────────────────────────── */

    /* H4: Reject kernel addresses for TLS pointer. */
    if ((cl & CLONE_SETTLS) && tls >= 0xFFFF800000000000ULL)
        return SYS_ERR(EFAULT);

    /* H3: Reject kernel addresses for CLONE_CHILD_CLEARTID pointer. */
    if ((cl & CLONE_CHILD_CLEARTID) && ctid >= 0xFFFF800000000000ULL)
        return SYS_ERR(EFAULT);

    aegis_task_t    *parent_task = sched_current();
    if (!parent_task || !parent_task->is_user)
        return SYS_ERR(EPERM);
    aegis_process_t *parent = (aegis_process_t *)parent_task;
#ifdef __aarch64__
    (void)u_rdi; (void)u_rsi; (void)u_rdx;  /* arm64 copies frame->regs[] below */
#endif

    /* Capability gate: THREAD_CREATE gates CONCURRENT shared-address-space
     * threads. vfork (CLONE_VM|CLONE_VFORK without CLONE_THREAD) is exempt: the
     * parent is suspended for the whole window, sibling threads are frozen, and
     * the child inherits exactly the parent's caps and must exec or _exit
     * immediately — no concurrency and no authority beyond a plain fork (which
     * is itself ungated). So vfork is ungated like fork; a bare CLONE_VM thread
     * still requires THREAD_CREATE. */
    int is_vfork = (cl & CLONE_VFORK) && !(cl & CLONE_THREAD);
    if (!is_vfork &&
        cap_check(parent->caps, CAP_TABLE_SIZE,
                  CAP_KIND_THREAD_CREATE, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    /* Process limit. */
    if (__atomic_load_n(&s_fork_count, __ATOMIC_RELAXED) >= MAX_PROCESSES)
        return (uint64_t)(int64_t)-11;  /* -EAGAIN */

    /* 1. Allocate child PCB. */
    aegis_process_t *child = kva_alloc_pages(2);
    if (!child)
        return SYS_ERR(ENOMEM);  /* -ENOMEM */

    /* 2. Share address space — same PML4, no page copy. */
    child->pml4_phys = parent->pml4_phys;
    child->vfork_parent = (void *)0;  /* set below only for CLONE_VFORK */

    /* 3. File descriptor table: share or copy. */
    if (cl & CLONE_FILES) {
        fd_table_ref(parent->fd_table);
        child->fd_table = parent->fd_table;
    } else {
        child->fd_table = fd_table_copy(parent->fd_table);
        if (!child->fd_table) {
            kva_free_pages(child, 2);
            return SYS_ERR(ENOMEM);  /* -ENOMEM */
        }
    }

    /* 4. Copy capability table + authenticated flag + bound identity. */
    uint32_t ci;
    for (ci = 0; ci < CAP_TABLE_SIZE; ci++)
        child->caps[ci] = parent->caps[ci];
    child->authenticated = parent->authenticated;
    child->admin_session = parent->admin_session;
    child->auth_uid      = parent->auth_uid;
    child->auth_gid      = parent->auth_gid;

    /* 5. Scalar fields. */
    child->brk       = parent->brk;
    child->brk_base  = parent->brk_base;
    child->mmap_base = parent->mmap_base;
    __builtin_memcpy(child->mmap_free, parent->mmap_free,
                     parent->mmap_free_count * sizeof(mmap_free_t));
    child->mmap_free_count = parent->mmap_free_count;
    /* M2: child gets a fresh lock — freelist is copied, not shared. */
    {
        spinlock_t init = SPINLOCK_INIT;
        child->mmap_free_lock = init;
    }
    vma_share(child, parent);
    __builtin_memcpy(child->exe_path, parent->exe_path, sizeof(parent->exe_path));
    __builtin_memcpy(child->cwd, parent->cwd, sizeof(parent->cwd));
    __builtin_memcpy(child->vfs_scope, parent->vfs_scope, sizeof(parent->vfs_scope));
    child->vfs_scope_len = parent->vfs_scope_len;   /* VFS confinement is inherited */
    child->pid       = proc_alloc_pid();
    child->ppid      = parent->pid;
    child->uid       = parent->uid;
    child->gid       = parent->gid;
    child->pgid      = parent->pgid;
    child->sid       = parent->sid;
    child->umask     = parent->umask;

    /* Thread-group membership. */
    if (cl & CLONE_THREAD) {
        child->tgid         = parent->tgid;
        parent->thread_count++;
    } else {
        child->tgid         = child->pid;
        child->thread_count = 1;
    }

    /* Signal state: inherit mask and dispositions; clear pending. */
    child->signal_mask     = parent->signal_mask;
    __builtin_memcpy(child->sigactions, parent->sigactions,
                     sizeof(parent->sigactions));
    child->pending_signals = 0;
    child->stop_signum     = 0;
    child->exit_status     = 0;
    child->term_signal     = 0;  /* PCB not memset; stale value would forge a signal death */

    /* TLS */
    if (cl & CLONE_SETTLS)
        child->task.fs_base = tls;
    else
        child->task.fs_base = parent_task->fs_base;

    /* clear_child_tid for futex-based thread join. */
    if (cl & CLONE_CHILD_CLEARTID)
        child->task.clear_child_tid = ctid;
    else
        child->task.clear_child_tid = 0;

    child->task.state       = TASK_RUNNING;
    child->task.wake_pending = 0;
    child->task.waiting_for = 0;
    child->task.is_user     = 1;
    child->task.tid         = child->pid;
    child->task.stack_pages = 4;
    proc_trace_log("fork", child->pid, child->ppid, child->exe_path);

    /* FPU/SSE inheritance: the live registers hold the parent's user state
     * (the -mno-sse kernel hasn't touched them since SYSCALL entry, and
     * IF=0 prevents preemption), so FXSAVE them into the CHILD's area —
     * the new thread starts with a copy of the caller's FPU state, same as
     * Linux clone.  Mandatory: the child PCB is NOT memset and the area
     * must be valid before the first switch-in fxrstors it. */
    fpu_state_save_live(&child->task);

    /* 6. Allocate child kernel stack (4 pages / 16 KB). */
    uint8_t *kstack = kva_alloc_pages(4);
    if (!kstack) {
        /* Security: undo all allocations made before this point.
         * fd_table was ref'd or copied at step 3, vma_share
         * incremented the parent's vma_refcount at step 5, and
         * thread_count was bumped at step 12. Leaking any of
         * these corrupts the parent's bookkeeping permanently. */
        if (cl & CLONE_THREAD)
            parent->thread_count--;
        vma_free(child);
        fd_table_unref(child->fd_table);
        kva_free_pages(child, 2);
        return SYS_ERR(ENOMEM);  /* -ENOMEM */
    }

    /* 7. Build child initial kernel stack frame.
     *
     * Identical layout to sys_fork — a fake isr_common_stub + ctx_switch
     * frame so the child's first scheduling returns through isr_post_dispatch
     * → iretq to user space.  Only difference: when child_stack != 0, use
     * child_stack instead of frame->user_rsp for the iretq RSP slot. */
    uint64_t *sp = (uint64_t *)(kstack + 4 * 4096);
    uint64_t user_rsp = child_stack ? child_stack : FRAME_SP(frame);

#ifdef __aarch64__
    extern void fork_child_return(void);

    /* Build SAVE_ALL_EL0 frame (34 slots) for the trampoline to restore */
    sp -= 34;
    for (int fi = 0; fi < 34; fi++) sp[fi] = 0;
    for (int fi = 0; fi < 31; fi++) sp[fi] = frame->regs[fi];
    sp[0]  = 0;              /* x0 = 0 (clone returns 0 in child) */
    sp[31] = user_rsp;       /* sp_el0 */
    sp[32] = frame->elr;     /* elr_el1 (return to user) */
    sp[33] = frame->spsr;    /* spsr_el1 */

    /* ctx_switch callee-save frame: 12 slots */
    *--sp = 0;                          /* x20 */
    *--sp = 0;                          /* x19 */
    *--sp = 0;                          /* x22 */
    *--sp = 0;                          /* x21 */
    *--sp = 0;                          /* x24 */
    *--sp = 0;                          /* x23 */
    *--sp = 0;                          /* x26 */
    *--sp = 0;                          /* x25 */
    *--sp = 0;                          /* x28 */
    *--sp = 0;                          /* x27 */
    *--sp = (uint64_t)(uintptr_t)fork_child_return; /* x30 (lr) */
    *--sp = 0;                          /* x29 (fp) */
#else
    /* x86-64: build ISR + ctx_switch frame for isr_post_dispatch path. */

    /* CPU ring-3 interrupt frame (ss = highest address) */
    *--sp = ARCH_USER_DS;            /* ss = user data selector              */
    *--sp = user_rsp;               /* user RSP (child stack or parent's)   */
    *--sp = frame->rflags;          /* RFLAGS                               */
    *--sp = ARCH_USER_CS;            /* cs = user code selector              */
    *--sp = frame->rip;             /* RIP = resume point after clone()     */

    /* ISR stub: ISR_NOERR pushes error_code(0) then vector(0) */
    *--sp = 0;                      /* error_code                           */
    *--sp = 0;                      /* vector                               */

    /* GPRs: isr_common_stub pushes rax first (high) → r15 last (low). */
    *--sp = 0;                      /* rax = 0  (clone returns 0 in child)  */
    *--sp = frame->rbx;                 /* rbx (callee-saved: inherit parent) */
    *--sp = frame->rip;             /* rcx = return RIP (SYSCALL semantics) */
    *--sp = u_rdx;                  /* rdx (musl vfork keeps the ret addr here) */
    *--sp = u_rsi;                  /* rsi                                  */
    *--sp = u_rdi;                  /* rdi                                  */
    *--sp = frame->rbp;                 /* rbp (callee-saved: inherit parent) */
    *--sp = frame->r8;              /* r8                                   */
    *--sp = frame->r9;              /* r9                                   */
    *--sp = frame->r10;             /* r10                                  */
    *--sp = frame->rflags;          /* r11 = RFLAGS (SYSCALL semantics)     */
    *--sp = frame->r12;                 /* r12 (callee-saved: inherit parent) */
    *--sp = frame->r13;                 /* r13 (callee-saved: inherit parent) */
    *--sp = frame->r14;                 /* r14 (callee-saved: inherit parent) */
    *--sp = frame->r15;                 /* r15 (callee-saved: inherit parent) */

    /* CR3 slot: restored by isr_post_dispatch before iretq */
    *--sp = (uint64_t)child->pml4_phys;

    /* ctx_switch callee-save frame: ret addr + r15-r12/rbp/rbx */
    *--sp = (uint64_t)(uintptr_t)isr_post_dispatch; /* ret addr            */
    *--sp = 0;  /* rbx                                                      */
    *--sp = 0;  /* rbp                                                      */
    *--sp = 0;  /* r12                                                      */
    *--sp = 0;  /* r13                                                      */
    *--sp = 0;  /* r14                                                      */
    *--sp = 0;  /* r15  <- child->task.sp points here                       */
#endif

    child->task.sp               = (uint64_t)(uintptr_t)sp;
    child->task.stack_base       = kstack;
    child->task.kernel_stack_top = (uint64_t)(uintptr_t)(kstack + 4 * 4096);

    /* Update TSS RSP0 for parent (it remains current) */
    arch_set_kernel_stack(parent_task->kernel_stack_top);

    /* 8. Add child to run queue. */
    sched_add(&child->task);
    __atomic_fetch_add(&s_fork_count, 1, __ATOMIC_RELAXED);

    /* 9. CLONE_PARENT_SETTID: write child tid to parent's *ptid. */
    if (cl & CLONE_PARENT_SETTID) {
        if (user_ptr_valid(ptid, 4)) {
            uint32_t tid_val = child->pid;
            vmm_write_user_bytes(parent->pml4_phys, ptid,
                                 &tid_val, sizeof(tid_val));
        }
    }

    /* 10. CLONE_CHILD_SETTID: write child tid to child's *ctid.
     * Same address space (CLONE_VM), so use parent's PML4. */
    if (cl & CLONE_CHILD_SETTID) {
        uint32_t tid_val = child->pid;
        /* ctid is in the child's lazily-mmap'd TLS (shared CLONE_VM space, so
         * current==parent); fault it in or the tid write is silently dropped. */
        if (user_ptr_valid(ctid, sizeof(tid_val)))
            vmm_write_user_bytes(parent->pml4_phys, ctid,
                                 &tid_val, sizeof(tid_val));
    }

    /* 11. CLONE_VFORK: block parent until the child leaves the shared address
     * space. Aegis wakes the vfork parent on child EXIT (the SIGCHLD path in
     * sched_exit; exec-wake is not implemented), so wait for the child TCB to
     * become a zombie. Loop because sched_block() may return early (lost-wakeup
     * guard) — proceeding while the child is still RUNNING would let the parent
     * run concurrently with a child that still shares its VM. waiting_for is
     * set so sched_exit's wake scan targets this parent. The `child` TCB stays
     * valid until the parent reaps it (after this returns), so the read is
     * safe. */
    if (cl & CLONE_VFORK) {
        /* The child borrows our address space (step 2 shared the PML4). Mark it
         * so the child's execve un-shares (fresh PML4 + vma_table) instead of
         * freeing OUR pages, and wakes us. Block until the child execs (clears
         * vfork_parent) or exits (becomes a zombie). Loop: sched_block() may
         * return early (lost-wakeup guard), and running concurrently while the
         * child still shares our VM would corrupt both. */
        child->vfork_parent = parent_task;
        parent_task->waiting_for = child->pid;
        /* Freeze this thread group's OTHER threads for the vfork window so none
         * of them races the child in the shared address space (the child shares
         * our PML4 until it execs).  Cleared by the child's execve (before it
         * wakes us) or by sched_exit if the child dies first.  vfork_freeze_add
         * is self-locking (takes sched_lock); we do not hold it here. */
        vfork_freeze_add(parent->tgid);
        /* Block via sched_block_locked so the condition recheck and the
         * transition to TASK_BLOCKED are ONE critical section under sched_lock,
         * closing the same lost-wakeup window fixed in sys_waitpid: a child that
         * EXITS before exec wakes us via sched_exit→signal_send_pid_locked, which
         * only wakes a parent already TASK_BLOCKED.  With the old unlocked check
         * + sched_block(), the child could zombify on another CPU between our
         * recheck and the block → wake skipped → vfork parent hung forever.
         * (The exec-success path wakes us via sched_wake(), which sets
         * wake_pending unconditionally, so sched_block_locked's wake_pending
         * guard already covers it; vfork_parent is pointer-atomic — re-read each
         * iteration.) */
        for (;;) {
            irqflags_t vfl = spin_lock_irqsave(&sched_lock);
            if (!(child->task.state != TASK_ZOMBIE &&
                  child->vfork_parent == parent_task)) {
                spin_unlock_irqrestore(&sched_lock, vfl);
                break;
            }
            sched_block_locked(vfl);   /* releases sched_lock; returns unlocked */
        }
        vfork_freeze_remove(parent->tgid);  /* belt-and-suspenders thaw (self-locking) */
        parent_task->waiting_for = 0;
    }

    return (uint64_t)child->pid;
}

/*
 * sys_vfork — syscall 58 (true vfork).
 *
 * Routes to the CLONE_VM|CLONE_VFORK clone path: the child shares the parent's
 * ENTIRE address space including the stack (child_stack=0 → the child runs on
 * the parent's rsp), the parent is SUSPENDED until the child execs or _exits
 * (sibling threads frozen for the window), and the child's execve un-shares
 * (fresh PML4 + vma_table) and wakes the parent. This is the exact path
 * posix_spawn already uses. Sharing memory (not a fork copy) is what lets a
 * vfork+exec caller like gcc (spawning cc1/as) communicate the child's exec
 * result back to the parent.
 *
 * musl's vfork() issues the raw syscall with no args, so the caller's real
 * rdi/rsi/rdx are threaded through (rdx carries musl's saved return address).
 */
uint64_t
sys_vfork(syscall_frame_t *frame, uint64_t u_rdi, uint64_t u_rsi, uint64_t u_rdx)
{
    return sys_clone(frame,
                     CLONE_VM | CLONE_VFORK | 17u /* SIGCHLD in the low byte */,
                     0 /* child_stack=0 → share the parent's stack */,
                     0, 0, 0,
                     u_rdi, u_rsi, u_rdx);
}

/*
 * sys_fork — syscall 57
 *
 * Duplicates the calling process.  Returns child PID in the parent,
 * 0 in the child (via the fork_child_return SYSRET path).
 *
 * Steps:
 *   1. Allocate child PCB via kva.
 *   2. Copy parent fd table, capability table, and scalar fields.
 *   3. Create a new PML4 and deep-copy all user pages.
 *   4. Allocate a kernel stack for the child.
 *   5. Build the initial kernel stack frame so ctx_switch resumes at
 *      fork_child_return, which issues SYSRET back to user space with rax=0.
 *   6. Add child to the run queue.
 *   7. Return child PID to the parent.
 */
uint64_t
sys_fork(syscall_frame_t *frame, uint64_t u_rdi, uint64_t u_rsi, uint64_t u_rdx)
{
    /* u_rdi/u_rsi/u_rdx are the caller's rdi/rsi/rdx at syscall entry (the x86
     * syscall_frame_t does not save them — they arrive as arg1/arg2/arg3). The
     * child must inherit them: musl's vfork() asm stashes the return address in
     * rdx across the syscall, so a zeroed rdx crashes the vfork child. */
    aegis_task_t    *parent_task = sched_current();
    if (!parent_task || !parent_task->is_user) return SYS_ERR(EPERM);
    aegis_process_t *parent      = (aegis_process_t *)parent_task;
#ifdef __aarch64__
    (void)u_rdi; (void)u_rsi; (void)u_rdx;  /* arm64 copies frame->regs[] below */
#endif

    /* S10: Prevent fork bombs — cap total process count. */
    if (__atomic_load_n(&s_fork_count, __ATOMIC_RELAXED) >= MAX_PROCESSES)
        return (uint64_t)(int64_t)-11;  /* -EAGAIN */

    /* 1. Allocate child PCB */
    aegis_process_t *child = kva_alloc_pages(2);
    if (!child)
        return SYS_ERR(ENOMEM);   /* -ENOMEM */

    /* 2. Copy parent fd table (allocates new table, bumps driver refs) */
    child->fd_table = fd_table_copy(parent->fd_table);
    if (!child->fd_table) {
        kva_free_pages(child, 2);
        return SYS_ERR(ENOMEM);   /* -ENOMEM */
    }

    uint32_t ci;
    for (ci = 0; ci < CAP_TABLE_SIZE; ci++)
        child->caps[ci] = parent->caps[ci];
    child->authenticated = parent->authenticated;
    child->admin_session = parent->admin_session;
    child->auth_uid      = parent->auth_uid;
    child->auth_gid      = parent->auth_gid;

    child->vfork_parent    = (void *)0;  /* a forked child owns its own pml4 */
    child->brk             = parent->brk;
    child->brk_base        = parent->brk_base;
    child->mmap_base       = parent->mmap_base;
    __builtin_memcpy(child->mmap_free, parent->mmap_free,
                     parent->mmap_free_count * sizeof(mmap_free_t));
    child->mmap_free_count = parent->mmap_free_count;
    /* M2: child gets a fresh lock — freelist is copied, not shared. */
    {
        spinlock_t init = SPINLOCK_INIT;
        child->mmap_free_lock = init;
    }
    vma_clone(child, parent);
    __builtin_memcpy(child->exe_path, parent->exe_path, sizeof(parent->exe_path));
#ifdef __aarch64__
    /* ARM64: musl sets TPIDR_EL0 directly, not via arch_prctl.
     * Read the current TPIDR_EL0 value and save to child. */
    {
        uint64_t tpidr;
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tpidr));
        child->task.fs_base = tpidr;
    }
#else
    child->task.fs_base    = parent_task->fs_base;
#endif
    __builtin_memcpy(child->cwd, parent->cwd, sizeof(parent->cwd));
    __builtin_memcpy(child->vfs_scope, parent->vfs_scope, sizeof(parent->vfs_scope));
    child->vfs_scope_len = parent->vfs_scope_len;   /* VFS confinement is inherited */
    child->pid             = proc_alloc_pid();
    child->tgid            = child->pid;
    child->thread_count    = 1;
    child->ppid            = parent->pid;
    child->pgid            = parent->pgid;
    child->sid             = parent->sid;
    child->uid             = parent->uid;
    child->gid             = parent->gid;
    child->umask           = parent->umask;
    child->stop_signum     = 0;
    child->exit_status     = 0;
    child->term_signal     = 0;  /* PCB not memset; stale value would forge a signal death */
    /* Signal state: inherit mask and dispositions; clear pending (Linux semantics) */
    child->signal_mask     = parent->signal_mask;
    __builtin_memcpy(child->sigactions, parent->sigactions, sizeof(parent->sigactions));
    child->pending_signals = 0;
    child->task.state      = TASK_RUNNING;
    child->task.wake_pending = 0;
    child->task.waiting_for = 0;
    child->task.is_user    = 1;
    child->task.tid        = child->pid;   /* use pid as tid */
    child->task.stack_pages = 4;  /* 4 pages / 16 KB — see proc.c KSTACK_NPAGES */

    /* FPU/SSE inheritance (POSIX fork semantics): the live registers hold
     * the parent's user state — the -mno-sse kernel hasn't touched them
     * since SYSCALL entry and IF=0 prevents preemption — so FXSAVE them
     * into the CHILD's area.  Mandatory: the child PCB is NOT memset and
     * the area must be valid before the first switch-in fxrstors it. */
    fpu_state_save_live(&child->task);

    /* 3. Create child PML4 */
    child->pml4_phys = vmm_create_user_pml4();
    if (!child->pml4_phys) {
        /* C3: release fd_table + VMA allocated above.  The child was never
         * added to the run queue, so sched_exit (the canonical fd-table
         * owner) will never run for it — this error path must release the
         * table itself.  fd_table_copy bumped every inherited fd's driver
         * refcount via .dup(); fd_table_unref (refcount is 1 → drops to 0)
         * runs the matching .close() on each before freeing the page.  A
         * bare kva_free_pages would leak every one of those driver refs
         * (pipe peers never woken, AF_UNIX/PTY peer refs and ext2 fd-pool
         * slots leaked). */
        fd_table_unref(child->fd_table);
        /* vma_clone (step 2) allocated a fresh 8-page (32 KB) child vma_table
         * with refcount 1; vma_free drops that ref and frees the page. A bare
         * vma_clear only zeroes the entry count, leaking the whole table —
         * 32 KB of KVA-backed physical memory per failed fork, exactly under
         * the memory pressure that triggered this OOM path. Match the
         * sys_clone and other rollback paths, which already use vma_free. */
        vma_free(child);
        kva_free_pages(child, 2);
        return SYS_ERR(ENOMEM);           /* -ENOMEM */
    }

    /* 4. Duplicate the parent's user pages into the child PML4.
     *
     * Two strategies (selected by the `cow_fork` kernel cmdline flag):
     *
     *   COW (g_cow_fork): vmm_cow_user_pages marks every writable parent
     *   page read-only + VMM_FLAG_COW and shares the frame with the child
     *   (refcount++). The first write by either side faults and breaks the
     *   share — reuse-in-place if the frame is by then singly-owned (the
     *   common fork+exec case: the child execs immediately, dropping its
     *   refs), otherwise copy. fork() latency drops dramatically: no per-
     *   page 4 KB memcpy, only PTE flips.
     *
     *   Eager (default): vmm_copy_user_pages memcpy's every present page up
     *   front. Kept as the fallback / A-side for measurement.
     *
     * COW was historically disabled because vmm_cow_fault_handle always
     * copied (no reuse-in-place), making the parent's post-fork writes more
     * expensive than the eager copy. The reuse-in-place fast path (added
     * alongside this) removes that cost. (Audit item P1.)
     *
     * perfbench_mm: bracket the duplication with rdtsc and report the cycle
     * cost + page count so the eager vs COW win is measurable on serial. */
    uint64_t dup_t0 = g_perfbench_mm ? arch_get_cycles() : 0;
    int dup_rc = g_cow_fork
        ? vmm_cow_user_pages(parent->pml4_phys, child->pml4_phys)
        : vmm_copy_user_pages(parent->pml4_phys, child->pml4_phys);
    if (g_perfbench_mm) {
        uint64_t dt = arch_get_cycles() - dup_t0;
        printk("[PERFMM] fork pid=%u %s dup=%lu cycles\n",
               parent->pid, g_cow_fork ? "cow" : "eager", dt);
    }
    if (dup_rc != 0) {
        vmm_free_user_pml4(child->pml4_phys);
        /* Release the copied fd_table through its refcount/close path, not a
         * bare kva_free_pages — see the PML4-creation error path above for
         * why (child not yet scheduled; .dup'd driver refs must be .close'd). */
        fd_table_unref(child->fd_table);
        vma_free(child);   /* free the cloned vma_table, not just zero its count */
        kva_free_pages(child, 2);
        return SYS_ERR(ENOMEM);           /* -ENOMEM */
    }

    /* COW SMP correctness: vmm_cow_user_pages write-protected the parent's
     * pages with a LOCAL invlpg only. If the parent has sibling CLONE_VM
     * threads running on other CPUs, they hold stale WRITABLE TLB entries for
     * the now-COW pages and could write through them without faulting —
     * corrupting the frame the child now shares. Flush every CPU once (full
     * CR3 reload) so no stale writable translation survives. Single-threaded
     * fork (the overwhelming common case) skips this: the parent runs on this
     * CPU only, where the local invlpg already took effect. Done here with no
     * lock held (shootdown rule). Eager copy never write-protects, so it is
     * unaffected. */
    if (g_cow_fork && parent->thread_count > 1)
        tlb_flush_all_cpus();

    /* 5. Allocate child kernel stack (4 pages / 16 KB — same as proc_spawn).
     * pipe_write_fn's 4060-byte staging buffer requires at least 4 pages;
     * see proc.c KSTACK_NPAGES comment for the full budget analysis. */
    uint8_t *kstack = kva_alloc_pages(4);
    if (!kstack) {
        vmm_free_user_pml4(child->pml4_phys);
        /* Release the copied fd_table through its refcount/close path, not a
         * bare kva_free_pages — see the PML4-creation error path above for
         * why (child not yet scheduled; .dup'd driver refs must be .close'd). */
        fd_table_unref(child->fd_table);
        vma_free(child);   /* free the cloned vma_table, not just zero its count */
        kva_free_pages(child, 2);
        return SYS_ERR(ENOMEM);           /* -ENOMEM */
    }

    /* 6. Build child initial kernel stack frame.
     *
     * We build a complete fake isr_common_stub post-dispatch frame so the
     * child's first scheduling is identical to every subsequent one: ctx_switch
     * pops callee-saves, rets to isr_post_dispatch, pops GPRs from the
     * cpu_state_t, restores CR3 (child's PML4), and iretqs to user space.
     * This avoids the SYSRET path entirely, eliminating the stale-frame
     * register corruption that caused r12=0 / ss=0x18 crashes.
     *
     * Stack layout (low→high, child->task.sp = lowest address):
     *
     *   -- ctx_switch callee-save frame (7 slots) --
     *   [r15=0][r14=0][r13=0][r12=0][rbp=0][rbx=0]
     *   [isr_post_dispatch]      <- ret addr; ctx_switch rets here
     *
     *   -- fake isr_common_stub frame --
     *   [CR3 = child->pml4_phys] <- isr_post_dispatch pops → restores PML4
     *   [r15=0][r14=0][r13=0][r12=0][r11=rflags][r10][r9][r8]
     *   [rbp=0][rdi=0][rsi=0][rdx=0][rcx=rip][rbx=0][rax=0]  <- fork ret 0
     *   [vector=0][error_code=0]
     *   [rip][cs=ARCH_USER_CS][rflags][user_rsp][ss=ARCH_USER_DS]  <- CPU ring-3 frame
     *
     * isr_post_dispatch: pop CR3 → mov cr3 → pop r15..rax → add rsp,16 → iretq
     */
    uint64_t *sp = (uint64_t *)(kstack + 4 * 4096);

#ifdef __aarch64__
    /* ARM64 fork child frame: ctx_switch callee-saves + a trampoline that
     * restores the EL0 exception frame and ERETs to user space.
     * Build a ctx_switch frame that returns to fork_child_return
     * (implemented in proc_enter.S) which sets x0=0 and ERETs. */
    extern void fork_child_return(void);

    /* Build SAVE_ALL_EL0 frame (34 slots) for the trampoline to restore */
    sp -= 34;
    for (int fi = 0; fi < 34; fi++) sp[fi] = 0;
    /* Copy parent's saved regs into child frame */
    for (int fi = 0; fi < 31; fi++) sp[fi] = frame->regs[fi];
    sp[0]  = 0;              /* x0 = 0 (fork returns 0 in child) */
    sp[31] = frame->user_sp; /* sp_el0 */
    sp[32] = frame->elr;     /* elr_el1 (return to user) */
    sp[33] = frame->spsr;    /* spsr_el1 */

    /* ctx_switch callee-save frame: 12 slots (matching ctx_switch.S) */
    /* lr (x30) = fork_child_return, rest zeroed */
    *--sp = 0;                          /* x20 */
    *--sp = 0;                          /* x19 */
    *--sp = 0;                          /* x22 */
    *--sp = 0;                          /* x21 */
    *--sp = 0;                          /* x24 */
    *--sp = 0;                          /* x23 */
    *--sp = 0;                          /* x26 */
    *--sp = 0;                          /* x25 */
    *--sp = 0;                          /* x28 */
    *--sp = 0;                          /* x27 */
    *--sp = (uint64_t)(uintptr_t)fork_child_return; /* x30 (lr) */
    *--sp = 0;                          /* x29 (fp) */
#else
    /* x86-64: build ISR + ctx_switch frame for isr_post_dispatch path. */

    /* CPU ring-3 interrupt frame (ss = highest address) */
    *--sp = ARCH_USER_DS;            /* ss = user data selector              */
    *--sp = frame->user_rsp;        /* user RSP                             */
    *--sp = frame->rflags;          /* RFLAGS                               */
    *--sp = ARCH_USER_CS;            /* cs = user code selector              */
    *--sp = frame->rip;             /* RIP = resume point after fork()      */

    /* ISR stub: ISR_NOERR pushes error_code(0) then vector(0) */
    *--sp = 0;                      /* error_code                           */
    *--sp = 0;                      /* vector                               */

    /* GPRs: isr_common_stub pushes rax first (high) → r15 last (low). */
    *--sp = 0;                      /* rax = 0  (fork returns 0 in child)   */
    *--sp = frame->rbx;                 /* rbx (callee-saved: inherit parent) */
    *--sp = frame->rip;             /* rcx = return RIP (SYSCALL semantics) */
    /* Caller-saved rdx/rsi/rdi: inherit the parent's values rather than zero
     * them. A C fork() caller treats these as scratch, so zeroing was harmless
     * there — but musl's hand-written vfork() asm stashes the RETURN ADDRESS in
     * rdx across the syscall (`pop %rdx; syscall; push %rdx; ret`). Zeroing rdx
     * made the vfork child `ret` to 0 (RIP=0x0 → SIGSEGV), which broke every
     * program that vfork+execs (gcc spawning cc1/as). Faithfully copying the
     * parent's register state — as the arm64 path already does — fixes it. */
    *--sp = u_rdx;                  /* rdx (musl vfork keeps the ret addr here) */
    *--sp = u_rsi;                  /* rsi                                  */
    *--sp = u_rdi;                  /* rdi                                  */
    *--sp = frame->rbp;                 /* rbp (callee-saved: inherit parent) */
    *--sp = frame->r8;              /* r8                                   */
    *--sp = frame->r9;              /* r9                                   */
    *--sp = frame->r10;             /* r10                                  */
    *--sp = frame->rflags;          /* r11 = RFLAGS (SYSCALL semantics)     */
    *--sp = frame->r12;                 /* r12 (callee-saved: inherit parent) */
    *--sp = frame->r13;                 /* r13 (callee-saved: inherit parent) */
    *--sp = frame->r14;                 /* r14 (callee-saved: inherit parent) */
    *--sp = frame->r15;                 /* r15 (callee-saved: inherit parent) */

    /* CR3 slot: restored by isr_post_dispatch before iretq */
    *--sp = (uint64_t)child->pml4_phys;

    /* ctx_switch callee-save frame: ret addr + r15-r12/rbp/rbx */
    *--sp = (uint64_t)(uintptr_t)isr_post_dispatch; /* ret addr            */
    *--sp = 0;  /* rbx                                                      */
    *--sp = 0;  /* rbp                                                      */
    *--sp = 0;  /* r12                                                      */
    *--sp = 0;  /* r13                                                      */
    *--sp = 0;  /* r14                                                      */
    *--sp = 0;  /* r15  <- child->task.sp points here                       */
#endif

    child->task.sp               = (uint64_t)(uintptr_t)sp;
    child->task.stack_base       = kstack;
    child->task.kernel_stack_top = (uint64_t)(uintptr_t)(kstack + 4 * 4096);

    /* Update TSS RSP0 for parent (it remains current) */
    arch_set_kernel_stack(parent_task->kernel_stack_top);

    /* 7. Add child to run queue */
    sched_add(&child->task);
    __atomic_fetch_add(&s_fork_count, 1, __ATOMIC_RELAXED);

    /* Return child PID to parent */
    return (uint64_t)child->pid;
}

/*
 * sys_waitpid — syscall 61
 *
 * pid_arg = PID to wait for (-1 = any child)
 * wstatus_ptr = user pointer to write exit status (0 = ignored)
 * options = WNOHANG (1) = return 0 immediately if no zombie child
 *
 * Scans the run queue for a zombie child matching the request.
 * On match: writes exit status (if wstatus_ptr != 0), removes zombie from
 * run queue, frees its resources, and returns the child's PID.
 * If no zombie is found and WNOHANG is set: returns 0.
 * If no zombie is found and WNOHANG is not set: blocks until a child exits
 * (sched_block), then retries via goto.
 */
uint64_t
sys_waitpid(uint64_t pid_arg, uint64_t wstatus_ptr, uint64_t options)
{
    aegis_process_t *caller = current_proc();
    int32_t          pid    = (int32_t)(uint32_t)pid_arg;

retry:;
    /* Scan the task list for a matching child (stopped or zombie).
     *
     * The whole scan — and the zombie unlink — runs under sched_lock:
     * other CPUs mutate the ->next chain in sched_add (fork/clone/spawn)
     * and right here (a concurrent waitpid by another thread).  Heavy
     * work (copy_to_user, freeing the zombie's pages) runs after the
     * unlock, on values captured / a PCB unlinked inside the critical
     * section.  user_ptr_valid IS called under sched_lock — it only takes
     * vmm_window_lock, which ranks below sched_lock in the canonical
     * order (sched_lock > all others). */
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    aegis_task_t *t = sched_current()->next;
    while (t != sched_current()) {
        if (t->is_user) {
            aegis_process_t *child = (aegis_process_t *)t;

            /* Check for stopped child (WUNTRACED) */
            if (t->state == TASK_STOPPED && (options & WUNTRACED) &&
                child->ppid == caller->pid &&
                (pid == -1 || (uint32_t)pid == child->pid)) {
                uint32_t child_pid   = child->pid;
                uint32_t stop_signum = child->stop_signum;
                /* Validate before consuming the stop event so EFAULT
                 * leaves it re-reportable (same behavior as before). */
                if (wstatus_ptr && !user_ptr_valid(wstatus_ptr, 4)) {
                    spin_unlock_irqrestore(&sched_lock, fl);
                    return SYS_ERR(EFAULT);
                }
                /* Clear stop_signum so repeated waitpid doesn't re-report */
                child->stop_signum = 0;
                sched_current()->waiting_for = 0;
                spin_unlock_irqrestore(&sched_lock, fl);
                if (wstatus_ptr) {
                    /* WIFSTOPPED encoding: (signum << 8) | 0x7f */
                    uint32_t wstatus_val = (stop_signum << 8) | 0x7fU;
                    copy_to_user((void *)(uintptr_t)wstatus_ptr,
                                 &wstatus_val, 4);
                }
                return (uint64_t)child_pid;
            }

            /* Refuse to reap a group leader while any sibling thread in the
             * same group is still live (non-zombie). Siblings share the
             * leader's PML4 (clone CLONE_THREAD), and the reap path below frees
             * that PML4 (free_pml4 = tgid==pid) — doing so while a sibling can
             * still run is a kernel-page UAF the instant the sibling next
             * touches user memory. Reachable when the leader pthread_exit()s
             * (plain sys_exit, not exit_group) and the parent waitpid()s it
             * while worker threads run on. We scan the task list directly
             * rather than trust thread_count: sys_exit_group zombifies siblings
             * without a per-thread decrement, so the counter can be stale; the
             * state scan handles plain exit, exit_group and mixed teardown
             * uniformly. Already under sched_lock, so the scan is race-free.
             * Skipping leaves the zombie leader queued for a later waitpid
             * retry once the last live sibling becomes zombie. */
            int leader_not_reapable = 0;
            if (t->state == TASK_ZOMBIE && child->tgid == child->pid) {
                aegis_task_t *scan = sched_current()->next;
                while (scan != sched_current()) {
                    if (scan->is_user) {
                        aegis_process_t *sib = (aegis_process_t *)scan;
                        if (sib->tgid == child->pid &&
                            sib->pid  != child->pid &&
                            scan->state != TASK_ZOMBIE) {
                            leader_not_reapable = 1;
                            break;
                        }
                    }
                    scan = scan->next;
                }
            }

            /* Check for zombie child (normal reap) */
            if (t->state == TASK_ZOMBIE &&
                child->ppid == caller->pid &&
                (pid == -1 || (uint32_t)pid == child->pid) &&
                !leader_not_reapable) {
                /* Found a zombie to reap. */
                uint32_t child_pid = child->pid;
                uint64_t status    = child->exit_status & 0xFF;
                /* POSIX: killed-by-signal = signum in the low 7 bits
                 * (WIFSIGNALED); normal exit = code << 8 (WIFEXITED). */
                uint32_t wstatus_val = child->term_signal
                    ? (child->term_signal & 0x7FU)
                    : (uint32_t)(status << 8);

                /* Validate before unlinking so EFAULT leaves the zombie
                 * reapable (same behavior as before). */
                if (wstatus_ptr && !user_ptr_valid(wstatus_ptr, 4)) {
                    spin_unlock_irqrestore(&sched_lock, fl);
                    return SYS_ERR(EFAULT);
                }

                /* Unlink zombie from the full task list (find
                 * predecessor).  After this no other CPU can reach the
                 * PCB, so it is exclusively ours to free post-unlock. */
                aegis_task_t *prev = t;
                while (prev->next != t) prev = prev->next;
                prev->next = t->next;

                /* The process is gone — release its slot in the
                 * MAX_PROCESSES live-process limit.  s_fork_count was a
                 * monotonic counter before 1.0.7: after 63 forks since
                 * boot, fork/spawn returned EAGAIN forever (unreachable
                 * until the 1.0.6 exec fix allowed >11 execs per boot).
                 * This is the only decrement site and it runs under
                 * sched_lock, so the >0 guard cannot race another
                 * decrementer; increments are atomic (RELAXED). */
                if (__atomic_load_n(&s_fork_count, __ATOMIC_RELAXED) > 0)
                    __atomic_fetch_sub(&s_fork_count, 1, __ATOMIC_RELAXED);

                /* Capture what the free path needs, then drop the lock:
                 * the page-table teardown (vmm_free_user_pml4 walks and
                 * frees every user frame under vmm_window_lock) is far
                 * too slow for a sched_lock critical section — it would
                 * stall scheduling on every CPU.  Keeping frees outside
                 * also honours the tlb.c rule that nothing reachable from
                 * here may IPI-wait while holding a lock other CPUs spin
                 * on with interrupts off. */
                uint8_t *stack_base  = child->task.stack_base;
                uint64_t stack_pages = child->task.stack_pages;
                uint64_t pml4_phys   = child->pml4_phys;
                /* Security: threads (tgid != pid) share the leader's PML4.
                 * Freeing it here would destroy the address space of all
                 * sibling threads still running.  Only free for the group
                 * leader (tgid == pid) or standalone processes.
                 * Also skip if vfork_parent is still set: this is a vfork child
                 * that died BEFORE exec (e.g. a posix_spawn file-action failed),
                 * so its PML4 is still BORROWED from the suspended parent —
                 * freeing it would destroy the parent's image. The parent frees
                 * it on its own exit; vma_free below drops the shared vma ref. */
                int free_pml4 = (child->tgid == child->pid) &&
                                (child->vfork_parent == (void *)0);

                /* Clear waiting_for on the caller — no longer blocked. */
                sched_current()->waiting_for = 0;
                spin_unlock_irqrestore(&sched_lock, fl);

                /* Write exit status to user if requested (validated
                 * above, before the unlink). */
                if (wstatus_ptr)
                    copy_to_user((void *)(uintptr_t)wstatus_ptr,
                                 &wstatus_val, 4);

                /* SMP: wait until the dying task has actually left its kernel
                 * stack before freeing it.  A task becomes TASK_ZOMBIE in
                 * sched_exit (and wakes its parent there) while STILL EXECUTING
                 * on its own kernel stack — it does not leave that stack until
                 * the final ctx_switch, which is also where it publishes
                 * on_cpu = -1 (ctx_switch.asm).  On another CPU the just-woken
                 * parent can reach this reaper and free the stack in that
                 * window, yanking it out from under the still-running child;
                 * the freed frame returns to the PMM, gets reused (as a page
                 * table or another stack), and the child's next ret/write
                 * through its recycled stack sprays kernel memory → the SMP
                 * concurrent-startup wrong-physical-frame corruption.  Spin
                 * (with IF restored — sched_lock dropped above) until on_cpu
                 * reads -1; the dying task runs independently on its CPU and
                 * will reach ctx_switch, so this terminates.  Single-core /
                 * same-CPU (woken_parent direct switch) already has on_cpu == -1
                 * by the time we get here, so the loop is a no-op there. */
                while (__atomic_load_n(&child->task.on_cpu,
                                      __ATOMIC_ACQUIRE) >= 0)
                    arch_pause();

                /* Free zombie resources.
                 *
                 * The fd_table is deliberately NOT touched here: it is owned
                 * and released by sched_exit() on the dying task itself, which
                 * runs fd_table_unref() (closing every fd / dropping every
                 * shared CLONE_FILES reference) BEFORE the task ever reaches
                 * TASK_ZOMBIE, then NULLs child->fd_table.  By the time a
                 * zombie is reachable from this reaper its fd_table is already
                 * NULL.  Unref'ing it here would be wrong: for a CLONE_FILES
                 * table shared with a still-living sibling, a second decrement
                 * would corrupt the survivor's refcount; for an unshared table
                 * already freed by sched_exit it would be a double-free.  The
                 * defensive check below pins the invariant so a future
                 * regression in sched_exit's teardown is logged and recovered
                 * (via the refcount-correct, NULL-safe unref) instead of
                 * silently leaking — it must never fire on a correct kernel. */
                if (child->fd_table) {
                    printk("[PROC] WARN: reaping pid %u with live fd_table "
                           "(sched_exit teardown regressed)\n", child_pid);
                    fd_table_unref(child->fd_table);
                    child->fd_table = (fd_table_t *)0;
                }
                kva_free_pages(stack_base, stack_pages);
                if (free_pml4)
                    vmm_free_user_pml4(pml4_phys);
                vma_free(child);
                kva_free_pages(child, 2);

                return (uint64_t)child_pid;
            }
        }
        t = t->next;
    }

    /* No zombie found. */
    if (options & WNOHANG) {
        spin_unlock_irqrestore(&sched_lock, fl);
        return 0;
    }

    /* Block until a child changes state, then retry.  We BLOCK WITHOUT DROPPING
     * sched_lock (sched_block_locked) so the no-zombie scan above and the
     * transition to TASK_BLOCKED are one atomic critical section w.r.t. a child's
     * sched_exit (which takes sched_lock to zombify + SIGCHLD-wake the parent).
     * This closes the SMP lost-wakeup window: previously we dropped the lock
     * here and called sched_block(), and a child exiting on another CPU in that
     * gap saw this task still TASK_RUNNING and skipped the wake → the parent
     * blocked forever (a hang).  It was masked while only the BSP scheduled and
     * by the old woken_parent direct-switch grabbing the RUNNING parent — but
     * that direct-switch was the same-task-on-two-CPUs corruption, now correctly
     * gated on on_cpu < 0, which re-exposed this window under smp_sched. */
    sched_current()->waiting_for = (pid == -1) ? 0 : (uint32_t)pid;
    sched_block_locked(fl);
    goto retry;
}
