#include "sched.h"
#include "arch.h"
#include "kva.h"
#include "pmm.h"
#include "printk.h"
#include "trace.h"
#include "vmm.h"
#include "proc.h"
#include "fd_table.h"
#include "ext2.h"
#include "spinlock.h"
#include "smp.h"
#include "fb.h"
#include "stackshot.h"
#include "../limits.h"
#include <stddef.h>

/* Compile-time guard: ctx_switch.asm assumes sp is at offset 0 of TCB.
 * If anyone adds a field before sp, this catches it immediately. */
_Static_assert(offsetof(aegis_task_t, sp) == 0,
    "sp must be first field in aegis_task_t — ctx_switch depends on this");

/* ctx_switch.asm hardcodes ON_CPU_OFF equ 8 to release the outgoing task
 * (on_cpu = -1) right after saving its stack pointer. */
_Static_assert(offsetof(aegis_task_t, on_cpu) == 8,
    "on_cpu must be at offset 8 — ON_CPU_OFF in ctx_switch.asm");

#ifdef __x86_64__
/* ctx_switch.asm hardcodes FPU_STATE_OFF equ 64 for its xsave/fxsave.
 * The 64-byte alignment is a hard XSAVE/XRSTOR requirement (#GP if violated;
 * FXSAVE only needed 16).  aligned(64) on the member pads its offset to 64 and
 * raises the TCB alignment to 64; kva pages are 4 KiB aligned and the struct
 * alignment propagates to statics/stack locals, so the area is always
 * 64-aligned. */
_Static_assert(offsetof(aegis_task_t, fpu_state) == 64,
    "fpu_state must be at offset 64 — FPU_STATE_OFF in ctx_switch.asm");
_Static_assert(sizeof(((aegis_task_t *)0)->fpu_state) == 1024,
    "fpu_state must be the 1024-byte XSAVE area size");
/* ctx_switch.asm hardcodes IS_USER_OFF to skip the FPU save/restore for
 * kernel tasks (-mno-sse: they never own live FPU state). */
_Static_assert(offsetof(aegis_task_t, is_user) == 1108,
    "is_user must be at offset 1108 — IS_USER_OFF in ctx_switch.asm");
#endif

#ifdef __aarch64__
/* ctx_switch.S hardcodes FPU_OFF = 16 for its ldp/stp q. The V-register
 * store area is 512 bytes (32 × 128-bit) with FPSR/FPCR at +512. */
_Static_assert(offsetof(aegis_task_t, fpu_state) == 16,
    "fpu_state must be at offset 16 — FPU_OFF in ctx_switch.S");
_Static_assert(sizeof(((aegis_task_t *)0)->fpu_state) == 528,
    "fpu_state must be 528 bytes (V0-31 + FPSR/FPCR)");
/* ctx_switch.S saves/restores TPIDR_EL0 (userland TLS base) at FS_BASE_OFF. */
_Static_assert(offsetof(aegis_task_t, fs_base) == 592,
    "fs_base must be at offset 592 — FS_BASE_OFF in ctx_switch.S");
#endif

/* 16KB per task; values single-sourced in limits.h (shared with proc.c). */
#define STACK_PAGES  AEGIS_STACK_PAGES
#define STACK_SIZE   AEGIS_STACK_SIZE

static uint32_t      s_next_tid = 0;
static uint32_t      s_task_count = 0;
static volatile int  s_sched_ready = 0;  /* set by sched_start; guards sched_tick */

spinlock_t sched_lock = SPINLOCK_INIT;

/* Idle tasks — ONE PER CPU (g_percpu[cpu].idle_task), NEVER linked into the
 * RUNNING-only run queue (task->is_idle == 1).  Keeping idle off the queue
 * means round-robin never burns a full slice in its hlt loop.  Every pick-next
 * site falls back to THIS CPU's idle (this_cpu_idle()) when no runnable task is
 * available — per-CPU so two idle CPUs never adopt the same idle task.  An idle
 * task's state stays TASK_RUNNING but its next_run/prev_run stay NULL. */
static inline aegis_task_t *this_cpu_idle(void)
{
    return (aegis_task_t *)percpu_self()->idle_task;
}

/* RUNNING-only run queue sentinel (P3 audit fix).
 *
 * Circular doubly-linked list of tasks with state == TASK_RUNNING, threaded
 * through aegis_task_t::next_run/prev_run.  The sentinel is a stable anchor:
 * the list is always non-empty (sentinel is in the list even when there are
 * no runnable tasks), so iteration and insertion never need a null check.
 * The sentinel itself is never scheduled — sched_tick et al. skip it by
 * testing `t == &s_run_sentinel`.
 *
 * All mutations (insert/remove) require sched_lock.  The atomic-release
 * state flip from the M1 audit fix is preserved: it now happens under
 * sched_lock alongside the list insert. */
static aegis_task_t s_run_sentinel = {
    .sp               = 0,
    .stack_base       = 0,
    .kernel_stack_top = 0,
    .tid              = 0xFFFFFFFFu,
    .is_user          = 0,
    .stack_pages      = 0,
    .state            = TASK_BLOCKED,   /* never picked by iteration */
    .waiting_for      = 0,
    .fs_base          = 0,
    .clear_child_tid  = 0,
    .sleep_deadline   = 0,
    .read_nonblock    = 0,
    .next             = 0,
    .next_run         = &s_run_sentinel,
    .prev_run         = &s_run_sentinel,
};

/* Insert task at the tail of the run list (just before the sentinel).
 * Idempotent: if the task is already in the list, this is a no-op.
 * Caller must hold sched_lock. */
static void
run_list_insert_locked(aegis_task_t *task)
{
    if (task->is_idle)
        return;   /* idle is the empty-queue fallback, never queued —
                   * defends against a stray sched_wake/sched_resume on it */
    if (task->next_run != (aegis_task_t *)0)
        return;   /* already in list */
    aegis_task_t *tail = s_run_sentinel.prev_run;
    task->prev_run          = tail;
    task->next_run          = &s_run_sentinel;
    tail->next_run          = task;
    s_run_sentinel.prev_run = task;
}

/* Remove task from the run list.  Idempotent: if task is not in the list,
 * this is a no-op.  Caller must hold sched_lock. */
static void
run_list_remove_locked(aegis_task_t *task)
{
    if (task->next_run == (aegis_task_t *)0)
        return;   /* not in list */
    task->prev_run->next_run = task->next_run;
    task->next_run->prev_run = task->prev_run;
    task->next_run = (aegis_task_t *)0;
    task->prev_run = (aegis_task_t *)0;
}

/* Return the next task to run after `cur`: the next RUNNING task in the
 * run list (skipping the sentinel), or the idle task when the run list is
 * empty.  If `cur` is not in the list, start from the list head — this is
 * also what rotates AWAY from idle: the idle task is never linked in, so
 * its next_run is NULL and the pick after an idle slice is always the
 * current head of the run list (subsequent ticks then round-robin from
 * there as usual).  Returns NULL only if the list is empty AND no idle
 * task has been registered (pre-sched_start; genuine bug afterwards). */
/* vfork freeze: while a process vforks, its OTHER threads must not run — they
 * share the address space with the suspended main thread AND the vfork child
 * until the child execs.  Letting them run races the child in the shared VM
 * (Ladybird's transport threads vs the posix_spawn child).  Set to the vforking
 * tgid; the run picker skips every task in that thread group.  Cleared by the
 * child's execve (before it wakes the parent) or by sched_exit if the child dies
 * first.  ponytail: single global => one concurrent vfork (fine: the parent
 * blocks; single-core test bed).  SMP would want this under sched_lock + a stack. */
uint32_t s_vfork_frozen_tgid = 0;

static aegis_task_t *
run_list_next_locked(aegis_task_t *cur)
{
    int me = (int)percpu_self()->cpu_id;
    aegis_task_t *start;
    if (cur && cur->next_run)
        start = cur->next_run;
    else
        start = s_run_sentinel.next_run;

    /* Walk the ring once from `start`, returning the first task that is NOT
     * already executing on another CPU.  A task with on_cpu >= 0 && != me is
     * live on some other core — picking it would run it on two CPUs at once
     * (shared kernel stack/registers = corruption), so skip it.  on_cpu == me
     * means it is `cur` itself (still marked from when we switched in); it is a
     * valid fallback when nothing else is runnable.  When every task in the
     * ring is busy elsewhere (or the ring is empty), fall back to THIS CPU's
     * own idle task. */
    aegis_task_t *t = start;
    do {
        if (t != &s_run_sentinel && (t->on_cpu < 0 || t->on_cpu == me) &&
            !(s_vfork_frozen_tgid && t->is_user &&
              ((aegis_process_t *)t)->tgid == s_vfork_frozen_tgid))
            return t;
        t = t->next_run;
    } while (t != start);

    return this_cpu_idle();   /* nothing pickable — this CPU's idle */
}

void
sched_init(void)
{
    percpu_set_current((aegis_task_t *)0);
    s_next_tid   = 0;
    s_task_count = 0;
    s_run_sentinel.next_run = &s_run_sentinel;
    s_run_sentinel.prev_run = &s_run_sentinel;
    lockrank_register(&sched_lock, LOCK_RANK_SCHED);  /* debug lock-order check */
}

/* Common body of sched_spawn/sched_spawn_idle: allocate TCB + stack, build
 * the initial ctx_switch frame, link into the FULL task list and bump the
 * task count.  Does NOT insert into the RUNNING-only run queue — callers
 * decide (regular tasks are queued; the idle task never is).
 * Caller must hold sched_lock. */
static aegis_task_t *
sched_spawn_task_locked(void (*fn)(void))
{
    /* Allocate TCB (one kva page — higher-half VA, no identity-map dependency). */
    aegis_task_t *task = kva_alloc_pages(1);

    /* Allocate stack: STACK_PAGES usable pages plus one unmapped guard page
     * at the bottom.  Stack grows downward; the guard page causes a #PF on
     * overflow instead of silently corrupting adjacent KVA allocations.
     * The guard VA is permanently abandoned (bump allocator does not rewind). */
    uint8_t *stack_region = kva_alloc_pages(STACK_PAGES + 1);
    uint64_t guard_phys   = kva_page_phys(stack_region);
    vmm_unmap_page((uint64_t)(uintptr_t)stack_region);
    pmm_free_page(guard_phys);
    /* Usable stack starts one page above the (now-unmapped) guard page. */
    uint8_t *stack = stack_region + 4096UL;

    /* Set up the stack to look like ctx_switch already ran.
     * The frame layout must match the push/pop order in ctx_switch.asm/S. */
    uint64_t *sp = (uint64_t *)(stack + STACK_SIZE);
#ifdef __aarch64__
    /* ARM64 ctx_switch pushes 6 pairs via stp (x19/x20 ... x29/x30).
     * x30 (lr) = fn. Build from high to low matching ldp order:
     * [x19][x20] [x21][x22] [x23][x24] [x25][x26] [x27][x28] [x29][x30] */
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
    *--sp = (uint64_t)(uintptr_t)fn;   /* x30 (lr) — ret jumps here */
    *--sp = 0;                          /* x29 (fp) */
#else
    /* x86-64 ctx_switch pops: r15, r14, r13, r12, rbp, rbx, then ret → fn. */
    *--sp = (uint64_t)(uintptr_t)fn;   /* return address */
    *--sp = 0;                          /* rbx */
    *--sp = 0;                          /* rbp */
    *--sp = 0;                          /* r12 */
    *--sp = 0;                          /* r13 */
    *--sp = 0;                          /* r14 */
    *--sp = 0;                          /* r15 */
#endif

    task->sp               = (uint64_t)(uintptr_t)sp;
    task->stack_base       = stack;
    task->kernel_stack_top = (uint64_t)(uintptr_t)(stack + STACK_SIZE);
    /* kva pages are not zeroed — the FXSAVE area must hold valid default
     * state before the first switch-in fxrstors it (no-op on non-x86). */
    fpu_state_init(task);
    task->is_user          = 0;
    task->tid              = s_next_tid++;
    task->stack_pages      = STACK_PAGES;
    task->state            = TASK_RUNNING;
    task->wake_pending     = 0;
    task->waiting_for      = 0;
    task->on_cpu           = -1;   /* not running on any CPU yet */
    task->is_idle          = 0;
    task->next_run         = (aegis_task_t *)0;
    task->prev_run         = (aegis_task_t *)0;

    /* Add to circular list */
    aegis_task_t *cur = sched_current();
    if (!cur) {
        task->next = task;
        percpu_set_current(task);
    } else {
        /* Insert after current */
        task->next = cur->next;
        cur->next  = task;
    }

    s_task_count++;

    return task;
}

void
sched_spawn(void (*fn)(void))
{
    irqflags_t fl = spin_lock_irqsave(&sched_lock);

    aegis_task_t *task = sched_spawn_task_locked(fn);

    /* Insert into the RUNNING-only run queue. */
    run_list_insert_locked(task);

    spin_unlock_irqrestore(&sched_lock, fl);
}

void
sched_spawn_idle(void (*fn)(void))
{
    irqflags_t fl = spin_lock_irqsave(&sched_lock);

    aegis_task_t *task = sched_spawn_task_locked(fn);

    /* Register as THIS CPU's idle fallback — deliberately NOT inserted into
     * the RUNNING-only run queue (is_idle == 1 makes run_list_insert_locked
     * refuse it).  Pick-next paths select this CPU's idle only when no other
     * task is runnable here, so idle never consumes a round-robin slice while
     * real work waits.  Per-CPU: each AP calls this for its own idle task. */
    task->is_idle = 1;
    percpu_self()->idle_task = task;

    spin_unlock_irqrestore(&sched_lock, fl);
}

/* Spawn an idle task FOR a specific CPU and record it in g_percpu[cpu].idle_task.
 * Called by the BSP (whose sched_current() is valid, so sched_spawn_task_locked
 * links the idle into the global task list correctly) to pre-create each AP's
 * idle task before the APs enter the scheduler.  The idle is NOT inserted into
 * the run queue (is_idle) and is NOT made any CPU's current task here — the AP
 * adopts it in ap_entry. */
void
sched_spawn_idle_for(uint32_t cpu, void (*fn)(void))
{
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    aegis_task_t *task = sched_spawn_task_locked(fn);
    task->is_idle = 1;
    g_percpu[cpu].idle_task = task;
    spin_unlock_irqrestore(&sched_lock, fl);
}

/* True once sched_start has run — APs poll this before entering the scheduler. */
int
sched_is_ready(void)
{
    return s_sched_ready;
}

void
sched_add(aegis_task_t *task)
{
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    task->next_run = (aegis_task_t *)0;
    task->prev_run = (aegis_task_t *)0;
    /* Processes (aegis_process_t) are memset(0) before sched_add, which would
     * leave on_cpu == 0 ("running on CPU 0").  Force the not-running sentinel
     * so the SMP picker treats the new task as free. */
    task->on_cpu  = -1;
    task->is_idle = 0;
    aegis_task_t *cur = sched_current();
    if (!cur) {
        task->next = task;
        percpu_set_current(task);
    } else {
        task->next = cur->next;
        cur->next  = task;
    }
    /* Only insert into the run list if the task is actually runnable.
     * proc_spawn may set state to TASK_BLOCKED for clone() threads that
     * will be woken later — insert_if_running makes this explicit. */
    if (task->state == TASK_RUNNING)
        run_list_insert_locked(task);
    s_task_count++;
    spin_unlock_irqrestore(&sched_lock, fl);
}

/* Deferred cleanup: dying task's resources cannot be freed before ctx_switch
 * (ctx_switch writes dying->sp; the dying stack is live until the stack pointer switches).
 * Recorded in percpu_t (prev_dying_tcb/stack/stack_pages) and freed at the
 * entry of the next sched_exit call. Per-CPU storage prevents two CPUs
 * exiting tasks simultaneously from overwriting each other's dying state. */

void
sched_exit(void)
{
    {
        aegis_task_t *t = sched_current();
        if (t && t->is_user) {
            aegis_process_t *p = (aegis_process_t *)t;
            proc_trace_log("exit", p->pid, p->ppid, p->exe_path);
        }
    }
    /* ── fd-table teardown MUST run with sched_lock NOT held ──
     * fd_table_unref closes every fd when the refcount hits 0.  The pipe /
     * AF_UNIX / PTY close ops wake their blocked peer via the PUBLIC
     * sched_wake() / waitq_wake_all(), both of which do
     * spin_lock_irqsave(&sched_lock).  sched_lock is a non-recursive ticket
     * lock, so doing this while sched_lock is already held (as the old code
     * did, around the original fd_table_unref site below the lock) is a
     * permanent self-hang on the same CPU.  Hoisting it above the lock
     * acquisition keeps the close-path wakes lock-free, honouring the
     * "producers wake outside any object lock, with sched_lock not held"
     * invariant.
     *
     * Safe to run here without the lock: SYSCALL entry cleared IF
     * (IA32_SFMASK), so 'dying' is the current task and cannot be preempted
     * or migrated; nothing in the sched_lock critical section below must
     * happen before fd teardown (the zombie transition, parent SIGCHLD, and
     * yield all follow it).  fd_table_unref only frees kva-mapped kernel
     * structures (pipe_t / unix_sock_t / pty_pair_t live in higher-half kva,
     * visible from the dying task's own CR3) and never blocks/sleeps, so the
     * later switch to the master PML4 is not a prerequisite. */
    aegis_task_t *exiting = sched_current();
    if (exiting->is_user) {
        aegis_process_t *dp = (aegis_process_t *)exiting;
        /* dp->exit_status was set by sys_exit before calling sched_exit. */
        if (dp->fd_table) {
            fd_table_unref(dp->fd_table);
            dp->fd_table = (fd_table_t *)0;  /* guard against double-unref */
        }
    }

    /* ── Deferred cleanup from the PREVIOUS exiting kernel/orphaned task ──
     * Free TCB + kernel stack of the task that exited last time on this CPU.
     * Safe: ctx_switch has completed; that TCB and stack are no longer live
     * on any CPU.  The prev_dying_* fields are per-CPU (only this CPU reads or
     * writes them) so no lock guards them.
     *
     * MUST run OUTSIDE sched_lock: kva_free_pages now triggers a cross-CPU TLB
     * shootdown (vmm_unmap_page → tlb_shootdown_kernel) which spins for every
     * other CPU to ack the IPI.  A CPU spinning for sched_lock with IF=0 cannot
     * ack until it gets the lock — which this CPU won't release until the
     * shootdown completes → deadlock.  Capture the pointers under a brief
     * irq-save (keeps percpu_self stable), then free with the lock not held. */
    irqflags_t dfl = arch_irq_save();
    percpu_t *pc = percpu_self();
    void    *dying_stack = pc->prev_dying_stack;
    uint64_t dying_stack_pages = pc->prev_dying_stack_pages;
    void    *dying_tcb = pc->prev_dying_tcb;
    int      dying_tcb_pages = dying_tcb &&
                 ((aegis_task_t *)dying_tcb)->is_user ? 2 : 1;
    pc->prev_dying_tcb = NULL;
    arch_irq_restore(dfl);
    if (dying_tcb) {
        kva_free_pages(dying_stack, dying_stack_pages);
        kva_free_pages(dying_tcb, dying_tcb_pages);
    }

    irqflags_t fl = spin_lock_irqsave(&sched_lock);

    /* Switch to master PML4 so kernel structures are safely accessible.
     * TCBs are kva-mapped higher-half VAs visible from any CR3 (pd_hi is
     * shared), so this is a defensive measure rather than a hard requirement. */
    vmm_switch_to(vmm_get_master_pml4());

    aegis_task_t *s_cur = sched_current();
    if (s_cur->is_user) {
        aegis_process_t *dying = (aegis_process_t *)s_cur;
        /* dying->exit_status was set by sys_exit before calling sched_exit. */

        /* The shared fd table was already released at the TOP of sched_exit,
         * BEFORE sched_lock was acquired (dying->fd_table is NULL now).
         * fd_table_unref must run lock-free because pipe/AF_UNIX/PTY close
         * ops wake their blocked peer via sched_wake()/waitq_wake_all(),
         * which re-acquire the non-recursive sched_lock — doing so while we
         * already hold it self-hangs the CPU.  Those wakes still fire while
         * the task is TASK_RUNNING (the zombie transition is below), so woken
         * peers schedule correctly. */

        /* Mark self zombie — stays in the full task list until waitpid
         * reaps, but must be removed from the RUNNING-only run queue
         * immediately so sched_tick does not schedule a dying task. */
        s_cur->state = TASK_ZOMBIE;
        run_list_remove_locked(s_cur);
        /* vfork child dying BEFORE exec: thaw the parent's frozen threads so the
         * parent (woken by SIGCHLD below) can run.  Without this the parent stays
         * frozen and the whole tgid deadlocks. */
        if (s_cur->is_user && ((aegis_process_t *)s_cur)->vfork_parent)
            s_vfork_frozen_tgid = 0;

        /* Notify parent of child exit via SIGCHLD.
         * signal_send_pid_locked sets SIGCHLD pending on the parent and
         * calls sched_wake_locked() if the parent is TASK_BLOCKED
         * (sigsuspend path or blocking waitpid path), transitioning it to
         * TASK_RUNNING and inserting it into the run list.  We hold
         * sched_lock here, so we must use the _locked variant to avoid
         * recursive acquisition.
         * Must run before the woken_parent scan so the scan finds the
         * parent in TASK_RUNNING state. */
        if (dying->ppid != 0)
            signal_send_pid_locked(dying->ppid, SIGCHLD);

        /* Find parent for direct ctx_switch (avoids PIT dependency).
         * signal_send_pid may have transitioned the parent BLOCKED→RUNNING;
         * check TASK_RUNNING here.
         *
         * CRITICAL (SMP): only direct-switch to the parent if it is NOT already
         * executing on another CPU (on_cpu < 0).  signal_send_pid_locked wakes a
         * BLOCKED parent to RUNNING with on_cpu == -1 (sched_wake_locked does not
         * claim a CPU) — that is the legitimate fast-path target.  But a parent
         * that is RUNNING with on_cpu >= 0 is currently running elsewhere (e.g.
         * spinning for sched_lock inside its OWN waitpid).  ctx_switch'ing to it
         * would run the SAME task — and its single kernel stack — on two CPUs at
         * once, instantly corrupting that stack (saved context sprayed across it:
         * the SMP concurrent fork/exec corruption).  Skip such a parent and fall
         * through to sched_yield_to_next(); it will reap us itself when it gets
         * the lock, or be picked up by a timer tick. */
        aegis_task_t *woken_parent = (void *)0;
        aegis_task_t *t = s_cur->next;
        while (t != s_cur) {
            if (t->is_user && t->state == TASK_RUNNING && t->on_cpu < 0) {
                aegis_process_t *p = (aegis_process_t *)t;
                if (p->pid == dying->ppid &&
                    (t->waiting_for == 0 || t->waiting_for == dying->pid)) {
                    woken_parent = t;
                    break;
                }
            }
            t = t->next;
        }

        /* Shutdown detection: scan for remaining RUNNING user tasks.
         * Zombies have is_user=1 but state==TASK_ZOMBIE — they are not live.
         * Without the state check, this scan would never trigger shutdown
         * because the just-zombified task is still in the queue with is_user=1. */
        int live_users = 0;
        t = s_cur->next;
        while (t != s_cur) {
            if (t->is_user && t->state != TASK_ZOMBIE)
                live_users = 1;
            t = t->next;
        }
        if (!live_users) {
            ext2_sync();    /* flush dirty blocks to NVMe before exit */
            printk("[AEGIS] System halted.\n");
            arch_request_shutdown();
        }

        /* Yield — zombie stays in queue until waitpid reaps.
         * Do NOT use the deferred-cleanup (g_prev_dying_tcb) path; that is
         * for non-zombie kernel task exits only.
         *
         * Direct-to-parent switch: if we woke a parent, switch to it
         * immediately instead of calling sched_yield_to_next().
         * sched_yield_to_next starts scanning from zombie->next in the
         * circular queue; when the queue is task_idle→parent→zombie,
         * zombie->next==task_idle and task_idle is picked first.  On AMD
         * bare metal the 8259A PIC IRQ0 may never reach the CPU (LAPIC not
         * in ExtINT/virtual-wire mode), so task_idle's sti+hlt never gets
         * preempted and the parent is never scheduled.  Switching directly
         * to the parent eliminates the PIT dependency for this path. */
        if (woken_parent) {
            aegis_task_t *zombie_task = s_cur;
            /* Defensive regression guard (SMP): the selection above requires
             * woken_parent->on_cpu < 0, so it must not be running on another
             * CPU here.  If it is, claiming + ctx_switch'ing to it would run one
             * task on two CPUs (the kernel-stack-corruption bug fixed alongside
             * this guard).  Survivable-but-shouldn't-happen → WARN_ONCE. */
            WARN_ONCE(woken_parent->on_cpu >= 0 &&
                      woken_parent->on_cpu != (int)pc->cpu_id,
                      "sched_exit: woken_parent already running on another CPU");
            woken_parent->on_cpu = (int)pc->cpu_id;
            percpu_set_current(woken_parent);
            arch_set_kernel_stack(woken_parent->kernel_stack_top);
            if (woken_parent->is_user) {
                /* sched_exit switched to the master PML4 above; restore the
                 * parent's CR3 and FS.base before resuming it (mirrors every
                 * other pick site — incomplete restores here surface as a
                 * user-context fault, the CR2=0x8 family). */
                vmm_switch_to(((aegis_process_t *)woken_parent)->pml4_phys);
                arch_set_fs_base(woken_parent->fs_base);
            }
            spin_unlock_irqrestore(&sched_lock, fl);
            ctx_switch(zombie_task, woken_parent);
            /* unreachable — zombie never resumes after direct switch */
        } else {
            spin_unlock_irqrestore(&sched_lock, fl);
            sched_yield_to_next();
        }
        /* unreachable — zombie never resumes */
        panic_halt("[SCHED] FAIL: zombie task resumed after exit");
    }

    /* ── Kernel task (non-user) exit path ── */

    /* IF=0 throughout (IA32_SFMASK cleared IF on SYSCALL entry) —
     * no preemption can occur during list manipulation. */
    aegis_task_t *prev = s_cur;
    while (prev->next != s_cur)
        prev = prev->next;

    aegis_task_t *dying_k = s_cur;
    aegis_task_t *next_k  = dying_k->next;
    prev->next            = next_k;

    /* Remove from the RUNNING-only run queue as well.  Capture the next
     * runnable task via the run list so we preserve round-robin order
     * instead of following the full-list successor.  When the run list is
     * empty, fall back to the idle task — the full-list successor could be
     * a BLOCKED task, which must never be switched to (idle used to be a
     * permanent run-list member; it no longer is). */
    run_list_remove_locked(dying_k);
    /* Pick the next runnable task via run_list_next_locked, which SKIPS any task
     * already executing on another CPU (on_cpu >= 0 && != me) and falls back to
     * this CPU's idle.  Using the raw next_run successor here was an SMP bug: it
     * could select a task currently running on another core, then ctx_switch to
     * it — running that task (and its single kernel stack) on two CPUs at once,
     * corrupting the stack.  run_list_next_locked already encodes the correct
     * pick policy used by every other scheduler site. */
    aegis_task_t *next_run = run_list_next_locked(dying_k);
    if (next_run != (aegis_task_t *)0 && next_run != &s_run_sentinel)
        next_k = next_run;
    else if (this_cpu_idle() != (aegis_task_t *)0 && this_cpu_idle() != dying_k)
        next_k = this_cpu_idle();

    s_task_count--;

    if (next_k == dying_k) {  /* last task — everything has exited */
        arch_request_shutdown();
        for (;;) arch_halt();
    }

    next_k->on_cpu = (int)pc->cpu_id;
    percpu_set_current(next_k);
    arch_set_kernel_stack(next_k->kernel_stack_top);

    /* If the next task is a user task, switch to its PML4 AND restore its
     * FS.base (TLS).  The missing arch_set_fs_base was a latent bug: every
     * other pick site sets it before ctx_switch, and neither the ISR-return
     * path nor sysret restores FS.base (it is an MSR, not on the stack), so a
     * user task resumed here ran with a stale/zero FS.base → a musl TLS access
     * (%fs:0x8) faults at linear 0x8 (the CR2=0x8 signature). */
    if (next_k->is_user) {
        vmm_switch_to(((aegis_process_t *)next_k)->pml4_phys);
        arch_set_fs_base(next_k->fs_base);
    }

    /* Record dying kernel task for deferred cleanup at the next sched_exit entry.
     * Must be set AFTER all list manipulation and BEFORE ctx_switch:
     * ctx_switch writes dying_k->sp, so the TCB must remain valid until
     * after the stack pointer switch completes. Per-CPU storage is safe here
     * because sched_lock is held and the dying task runs on this CPU only. */
    pc->prev_dying_stack       = (void *)dying_k->stack_base;
    pc->prev_dying_stack_pages = dying_k->stack_pages;
    pc->prev_dying_tcb         = dying_k;
    spin_unlock_irqrestore(&sched_lock, fl);
    ctx_switch(dying_k, next_k);
    __builtin_unreachable();
}

/* sched_block_locked — block the current task with sched_lock ALREADY HELD by
 * the caller (fl = the flags it captured on acquire).  Releases the lock before
 * switching away.  Lets a caller make "test a condition then block" atomic w.r.t.
 * a waker that runs under sched_lock — closing the classic lost-wakeup window
 * where the waker sees the task still TASK_RUNNING (between the caller's unlock
 * and sched_block's own re-acquire) and skips the wake.  sys_waitpid uses this:
 * it scans for a zombie and, finding none, blocks WITHOUT dropping sched_lock,
 * so a child's sched_exit (which takes sched_lock to zombify + SIGCHLD-wake the
 * parent) is fully ordered either before the scan (parent reaps) or after the
 * parent is BLOCKED (parent gets woken). */
void
sched_block_locked(irqflags_t fl)
{
    aegis_task_t *old = sched_current();

    /* Lost-wakeup guard. If a wake landed after the caller registered its
     * waiter but before we took sched_lock, wake_pending is set: consume it and
     * return WITHOUT blocking so the caller re-checks its condition (all
     * sched_block callers loop). The whole check-and-block below runs under
     * sched_lock, and sched_wake_locked sets wake_pending under the same lock,
     * so a waker is fully ordered either before this check (→ we early-return)
     * or after we mark BLOCKED (→ it does a normal wake). Without this, a wake
     * in that window would be clobbered by state=BLOCKED → sleep forever. */
    if (old->wake_pending) {
        old->wake_pending = 0;
        spin_unlock_irqrestore(&sched_lock, fl);
        return;
    }

    old->state = TASK_BLOCKED;

    /* Pick the next runnable task, skipping any running on another CPU, from
     * old's run-list position (round-robin preserved).  Must run BEFORE
     * removing old so run_list_next_locked starts from old->next_run.  If old
     * is the only candidate it returns, fall back to this CPU's idle (old is
     * about to block and must not be switched to). */
    aegis_task_t *next = run_list_next_locked(old);
    run_list_remove_locked(old);

    /* Note: the task remains in the FULL circular list (next/prev via `next`)
     * so sched_exit's signal_send_pid scan and waitpid iteration can still
     * find it by pid.  It is only removed from the RUNNING-only run queue. */

    if (next == old || next == (aegis_task_t *)0)
        next = this_cpu_idle();
    if (next == (aegis_task_t *)0) {
        /* No runnable task AND no idle task registered.  The idle task is
         * spawned before sched_start on every arch, so this is a genuine
         * bug (blocking before the scheduler exists, or corruption). */
        panic_halt("[SCHED] FAIL: sched_block with no runnable task and no idle task");
    }
    next->on_cpu = (int)percpu_self()->cpu_id;
    percpu_set_current(next);

    /* Update TSS RSP0 and percpu.kernel_stack for the incoming task
     * before ctx_switch so the next syscall from this task uses its own
     * kernel stack, not the stack of whatever task ran last. */
    arch_set_kernel_stack(next->kernel_stack_top);

    /* Set FS.base for the incoming task before ctx_switch. */
    if (next->is_user)
        arch_set_fs_base(next->fs_base);

    spin_unlock_irqrestore(&sched_lock, fl);
    ctx_switch(old, next);

    /* Resumed: consume the wake_pending the waker set when it unblocked us so
     * it does not linger and spuriously short-circuit this task's NEXT block.
     * Single-core safe — only this task runs here after ctx_switch returns; on
     * SMP a concurrent fresh wake racing this clear just re-arms wake_pending
     * for a condition the caller's loop will re-check, so nothing is lost. */
    old->wake_pending = 0;

    /* Restore CR3 for the incoming user task after ctx_switch returns.
     * sched_exit switches to master PML4 before context-switching to this
     * task (via sched_yield_to_next).  Without this restore, a user task
     * that was unblocked by sched_exit would resume with master PML4 loaded,
     * causing any copy_to_user call (e.g. sys_waitpid wstatus write) to #PF
     * because user stack pages are only mapped in the process's user PML4. */
    aegis_task_t *resumed = sched_current();
    if (resumed->is_user)
        vmm_switch_to(((aegis_process_t *)resumed)->pml4_phys);

    /* Restore FS.base for the incoming user task after ctx_switch returns.
     * sched_tick does this in its path; sched_block must mirror it.
     * Without this, a user task that was blocked while another user task
     * ran and set a different FS_BASE would resume with the wrong FS_BASE,
     * corrupting TLS access (__errno_location, stack canary, etc.). */
    if (resumed->is_user)
        arch_set_fs_base(resumed->fs_base);
}

/* sched_block — acquire sched_lock and block (the common case, for callers that
 * do NOT already hold it: wait_event, nanosleep, futex, vfork, sigsuspend). */
void
sched_block(void)
{
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    sched_block_locked(fl);
}

void
sched_wake_locked(aegis_task_t *task)
{
    /* Caller holds sched_lock.  Flip state to TASK_RUNNING and insert the
     * task into the RUNNING-only run queue if it is not already there.
     *
     * The atomic-release state write (M1 audit fix) is preserved: sched_tick
     * reads task->state without the lock under some paths, and the release
     * ordering makes the state flip visible to other CPUs along with any
     * wake-up condition the caller arranged before invoking us. */
    /* Record the wake even if the task has not blocked yet — it may be in the
     * window between registering its waiter and calling sched_block(). The flag
     * makes that sched_block() return immediately instead of losing this wake
     * (consumed there). run_list_insert_locked is a no-op if the task is still
     * in the run list (RUNNING, not yet blocked), so this is safe either way. */
    task->wake_pending = 1;
    __atomic_store_n(&task->state, TASK_RUNNING, __ATOMIC_RELEASE);
    run_list_insert_locked(task);
}

void
sched_dequeue_locked(aegis_task_t *task)
{
    /* Public wrapper for run-queue removal.  Caller must hold sched_lock.
     *
     * Needed by sys_exit_group when force-zombifying sibling threads: a
     * bare `state = TASK_ZOMBIE` write is no longer sufficient now that
     * pick-next walks the RUNNING-only run list (the list membership, not
     * the state field, is what sched_tick consults), so the task must be
     * unlinked in the same critical section as the state flip or the
     * scheduler keeps switching into a zombie. */
    run_list_remove_locked(task);
}

void
sched_wake(aegis_task_t *task)
{
    /* Public entry — acquires sched_lock.  Most callers (pipe close,
     * socket rx, futex wake, signal_send_pid outside sched_exit) do not
     * hold sched_lock, so they use this variant.
     *
     * sched_exit → signal_send_pid_locked → sched_wake_locked takes the
     * other path because sched_lock is already held there. */
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    sched_wake_locked(task);
    spin_unlock_irqrestore(&sched_lock, fl);
}

void
sched_stop(aegis_task_t *task)
{
    irqflags_t fl = spin_lock_irqsave(&sched_lock);

    aegis_task_t *cur = sched_current();
    if (task != cur) {
        /* Stopping a different task: flip state and remove from run list. */
        task->state = TASK_STOPPED;
        run_list_remove_locked(task);
        spin_unlock_irqrestore(&sched_lock, fl);
        return;
    }

    /* Self-stop: mirrors sched_block exactly, but sets TASK_STOPPED. */
    aegis_task_t *old = cur;

    old->state = TASK_STOPPED;

    /* Pick next runnable, skipping tasks running on other CPUs (see
     * sched_block).  Must run before removing old so the walk starts from
     * old's position. */
    aegis_task_t *next = run_list_next_locked(old);
    run_list_remove_locked(old);

    if (next == old || next == (aegis_task_t *)0)
        next = this_cpu_idle();
    if (next == (aegis_task_t *)0)
        panic_halt("[SCHED] FAIL: sched_stop with no runnable task and no idle task");
    next->on_cpu = (int)percpu_self()->cpu_id;
    percpu_set_current(next);

    arch_set_kernel_stack(next->kernel_stack_top);

    if (next->is_user)
        arch_set_fs_base(next->fs_base);

    spin_unlock_irqrestore(&sched_lock, fl);
    ctx_switch(old, next);

    /* After ctx_switch returns (SIGCONT has resumed us), restore CR3 + FS.base.
     * Mirrors sched_block tail exactly. */
    aegis_task_t *resumed = sched_current();
    if (resumed->is_user)
        vmm_switch_to(((aegis_process_t *)resumed)->pml4_phys);

    if (resumed->is_user)
        arch_set_fs_base(resumed->fs_base);
}

void
sched_resume(aegis_task_t *task)
{
    /* Mirrors sched_wake: flip state back to RUNNING and insert the task
     * into the run queue.  Works for both TASK_STOPPED and TASK_BLOCKED
     * (SIGCONT while blocked on a read must also let the read return EINTR).
     * Acquires sched_lock; no caller currently holds it when calling this. */
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    __atomic_store_n(&task->state, TASK_RUNNING, __ATOMIC_RELEASE);
    run_list_insert_locked(task);
    spin_unlock_irqrestore(&sched_lock, fl);
}

void
sched_yield_to_next(void)
{
    irqflags_t fl = spin_lock_irqsave(&sched_lock);

    aegis_task_t *old = sched_current();
    /* old may or may not still be in the run list (zombie callers remove
     * it before invoking us).  run_list_next_locked handles both, and
     * falls back to the idle task when the run list is empty. */
    aegis_task_t *next = run_list_next_locked(old);
    if (next == (aegis_task_t *)0)
        panic_halt("[SCHED] FAIL: sched_yield_to_next with no runnable task and no idle task");
    if (next == old) {
        /* Only one runnable task (old itself) — nothing to switch to.
         * Caller is expected to have removed old from the run list before
         * calling; if we end up with old still as the only option, just
         * return and let the original context continue. */
        spin_unlock_irqrestore(&sched_lock, fl);
        return;
    }
    next->on_cpu = (int)percpu_self()->cpu_id;
    percpu_set_current(next);
    arch_set_kernel_stack(next->kernel_stack_top);

    /* Set FS.base for the incoming task before ctx_switch. */
    if (next->is_user)
        arch_set_fs_base(next->fs_base);

    spin_unlock_irqrestore(&sched_lock, fl);
    ctx_switch(old, next);

    /* Restore CR3 for the incoming user task after ctx_switch returns.
     * sched_exit calls vmm_switch_to(master_pml4) at its top, then calls
     * sched_yield_to_next to switch away from the dying task.  The task
     * that resumes here would have master PML4 loaded; any subsequent
     * copy_to_user (e.g. sys_waitpid wstatus write) would #PF because the
     * user stack pages are only mapped in the process's user PML4. */
    aegis_task_t *resumed = sched_current();
    if (resumed->is_user)
        vmm_switch_to(((aegis_process_t *)resumed)->pml4_phys);

    /* Restore FS.base for the incoming user task after ctx_switch returns.
     * sched_tick does this in its path; sched_yield_to_next must mirror it.
     * Without this, a user task that was blocked while another user task
     * ran and set a different FS_BASE would resume with the wrong FS_BASE,
     * corrupting TLS access (__errno_location, stack canary, etc.). */
    if (resumed->is_user)
        arch_set_fs_base(resumed->fs_base);
}

void
sched_start(void)
{
    aegis_task_t *first = sched_current();
    if (!first) {
        printk("[SCHED] FAIL: sched_start called with no tasks\n");
        panic_halt("[SCHED] FAIL: sched_start called with no tasks");
    }

    s_sched_ready = 1;  /* guard: sched_tick now safe to context-switch */
    first->on_cpu = (int)percpu_self()->cpu_id;  /* BSP claims the first task */
    printk("[SCHED] OK: scheduler started, %u tasks\n", s_task_count);

    /* One-way switch into the first task.
     *
     * IMPORTANT: Do NOT enable interrupts and return here. If we returned to
     * the idle loop and the first timer tick fired from there, sched_tick would call
     * ctx_switch(task_kbd, task_heartbeat) while RSP is deep in the ISR frame.
     * ctx_switch would save the ISR stack pointer into task_kbd->sp, corrupting
     * the TCB. Resuming task_kbd later would load a garbage stack pointer and crash.
     *
     * Fix: switch directly into the first task using a stack-local dummy TCB.
     * ctx_switch saves our current stack pointer into dummy.sp (which we immediately
     * abandon). The first task starts on its own correctly-constructed initial
     * stack. Each task enables interrupts at startup (arch-specific).
     *
     * sched_start() never returns.
     */
    arch_set_kernel_stack(first->kernel_stack_top);
    /* sched_start always enters the first task (kbd, a kernel task).
     * No CR3 switch here: if the first task is a user task, proc_enter_user
     * handles the PML4 switch before iretq (same as the timer-preemption
     * first-entry path). */

    /* dummy is outgoing-only: ctx_switch writes dummy.sp and fxsaves the
     * live FPU state into dummy.fpu_state (x86), both immediately abandoned.
     * The compiler 16-byte-aligns the local because the fpu_state member's
     * alignment propagates to the struct — FXSAVE requires it. */
    aegis_task_t dummy;
    ctx_switch(&dummy, first);
    __builtin_unreachable();
}

void
sched_tick(void)
{
    if (!s_sched_ready)                    /* PIT fires before sched_start */
        return;
    aegis_task_t *cur = sched_current();
    if (!cur)                              /* no tasks spawned yet */
        return;

    spin_lock(&sched_lock);

    /* Wake any tasks whose nanosleep deadline has passed.
     *
     * We still need to iterate the FULL task list (`next`) here because
     * sleeping tasks are TASK_BLOCKED and therefore NOT in the RUNNING-only
     * run queue.  The run queue does not contain them, so we cannot use it
     * to find them.  Once a sleeping task's deadline expires we flip its
     * state to TASK_RUNNING and insert it into the run list. */
    {
        uint64_t now = arch_get_ticks();
        aegis_task_t *t = cur->next;
        aegis_task_t *stop = cur;
        do {
            if (t->state == TASK_BLOCKED && t->sleep_deadline != 0 &&
                now >= t->sleep_deadline) {
                t->sleep_deadline = 0;
                t->state = TASK_RUNNING;
                run_list_insert_locked(t);
            }
            t = t->next;
        } while (t != stop);
    }

    aegis_task_t *old = cur;
    /* Walk the RUNNING-only run queue — O(R) where R = runnable count.
     * This is the whole point of the P3 audit fix: we no longer scan
     * blocked/zombie/stopped tasks here.
     *
     * `old` is normally in the run list (it is the currently running
     * task, which is TASK_RUNNING).  Two exceptions, both handled by
     * run_list_next_locked starting from the sentinel head: (a) old is
     * the idle task, which is never linked in — preempting idle therefore
     * picks the run-list head; (b) old was mid-transition when the tick
     * fired.  When the list is empty the helper returns the idle task
     * (== old while idling, so the early-return below keeps idle running
     * back-to-back). */
    aegis_task_t *next = run_list_next_locked(old);
    if (next == (aegis_task_t *)0 || next == old) {
        /* Nothing else runnable — stay on `cur`. */
        spin_unlock(&sched_lock);
        return;
    }
    next->on_cpu = (int)percpu_self()->cpu_id;
    percpu_set_current(next);

    arch_set_kernel_stack(next->kernel_stack_top);

    /* Set FS.base for the incoming task before ctx_switch so that the task
     * enters user space (or resumes) with the correct TLS pointer.
     * Must be paired with the arch_set_fs_base after ctx_switch (for the
     * outgoing task's subsequent resume). */
    if (next->is_user)
        arch_set_fs_base(next->fs_base);

    /*
     * CR3 switch policy in sched_tick:
     *
     * sched_tick always runs inside isr_common_stub which switches to the
     * master PML4 at interrupt entry.  sched_tick therefore always executes
     * with the master PML4 loaded, regardless of whether the interrupted task
     * was a kernel or user task.
     *
     * (a) Switching TO a user task: do NOT switch CR3 here.  The switch to
     *     the user PML4 is performed by proc_enter_user (first entry) or by
     *     isr_common_stub's saved-CR3 restore (subsequent preemptions).
     *
     *     CRITICAL: sched_tick runs on the OUTGOING kernel task's kva-mapped
     *     stack.  Calling vmm_switch_to(user_pml4) from mid-sched_tick would
     *     switch away from the task being context-switched out while its stack
     *     is still live on the CPU — the next stack access would use the wrong
     *     CR3 context.  CR3 switches happen only in proc_enter_user (ring-3
     *     entry) and sched_exit (task teardown).
     *
     * (b) Switching FROM a user task to a kernel task: isr_common_stub
     *     already switched to master PML4 at interrupt entry.  No further
     *     CR3 switch is needed here.
     */

    /* ctx_switch is declared in arch.h with a forward struct declaration.
     * It saves old->sp, loads next->sp, and returns into new task. */
    spin_unlock(&sched_lock);
    ctx_switch(old, next);

    /* Restore the incoming user process's FS base.
     * This must run AFTER ctx_switch returns (sched_current() is now the new task).
     * proc_enter_user handles only the first entry; preempted tasks resume
     * via isr_common_stub which does not reload FS.base. IF=0 here (PIT ISR). */
    aegis_task_t *resumed = sched_current();
    if (resumed->is_user) {
#ifdef __aarch64__
        /* arm64 has no per-task TTBR0 save/restore in the exception vectors
         * (x86 does it in isr_common_stub via the saved CR3). So the timer-
         * preemption resume path MUST reload the resumed task's address
         * space here — otherwise the RESTORE_ALL+eret returns to EL0 with
         * whatever TTBR0 was active (the preempted-out task's or master),
         * and the resumed task's code faults with a level-0 instruction
         * abort. The cooperative yields (sched_block/stop/resume) already
         * do this; sched_tick is the preemption twin. */
        vmm_switch_to(((aegis_process_t *)resumed)->pml4_phys);
#endif
        arch_set_fs_base(resumed->fs_base);
    }
}

/* dump_all_tasks — stackshot.  Walk the circular all-task list and print each
 * task's identity/state plus a kernel backtrace.  Best-effort & ISR-safe: uses
 * trylock on sched_lock so a SysRq/watchdog dump never deadlocks against code
 * that already holds it.  See stackshot.h. */
void
dump_all_tasks(const char *reason)
{
    aegis_task_t *cur = sched_current();
    printk("[STACKSHOT] ==== all tasks (%s) ====\n", reason ? reason : "?");
    if (!cur) {
        printk("[STACKSHOT] no current task\n");
        return;
    }

    irqflags_t fl = arch_irq_save();
    int locked = spin_trylock(&sched_lock);
    if (!locked)
        printk("[STACKSHOT] WARN: sched_lock busy; walk may be inconsistent\n");

    aegis_task_t *t = cur;
    int n = 0;
    do {
        const char *name = "<kthread>";
        uint32_t pid = 0;
        if (t->is_user) {
            aegis_process_t *proc = (aegis_process_t *)t;
            name = proc->exe_path[0] ? proc->exe_path : "<user>";
            pid  = proc->pid;
        }
        const char *mark = (t == cur) ? " <== current" : "";
        /* printk has no %d; on_cpu is int32 (-1 when not running on any CPU). */
        if (t->on_cpu < 0)
            printk("[STACKSHOT] pid=%u %s state=%u on_cpu=-1 sc=%u wait=%u%s\n",
                   pid, name, t->state, t->last_syscall, t->waiting_for, mark);
        else
            printk("[STACKSHOT] pid=%u %s state=%u on_cpu=%u sc=%u wait=%u%s\n",
                   pid, name, t->state, (uint32_t)t->on_cpu, t->last_syscall,
                   t->waiting_for, mark);

        if (t == cur) {
            print_backtrace_from((uint64_t)__builtin_frame_address(0), 12);
        } else if (t->on_cpu >= 0) {
            printk("    [running on cpu%u - live stack elsewhere]\n",
                   (uint32_t)t->on_cpu);
        } else {
            /* Saved ctx_switch frame.  ctx_switch pushes rbx,rbp,r12,r13,r14,r15
             * then stores rsp into ->sp, so from the saved sp:
             *   [+0]=r15 [+8]=r14 [+16]=r13 [+24]=r12 [+32]=rbp [+40]=rbx
             *   [+48]=return address. */
            uint64_t sp = t->sp;
            if (sp >= 0xFFFFFFFF80000000ULL && !(sp & 7ULL)) {
                uint64_t *s = (uint64_t *)sp;
                uint64_t resume = s[6];
                if (resume >= 0xFFFFFFFF80000000ULL)
                    printk("    [resume] 0x%lx\n", resume);
                print_backtrace_from(s[4], 12);
            } else {
                printk("    [no saved frame: sp=0x%lx]\n", sp);
            }
        }
        t = t->next;
    } while (t != cur && ++n < 256);

    if (locked)
        spin_unlock(&sched_lock);
    arch_irq_restore(fl);
    printk("[STACKSHOT] ==== end (%u tasks) ====\n", (uint32_t)(n + 1));
}
