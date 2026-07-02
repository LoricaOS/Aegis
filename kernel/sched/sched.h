#ifndef AEGIS_SCHED_H
#define AEGIS_SCHED_H

#include <stdint.h>
#include "smp.h"
#include "../core/spinlock.h"   /* irqflags_t (sched_block_locked) */

#ifdef __x86_64__
/* Set by arch_sse_init() when AVX (XSAVE) is enabled; selects XSAVE vs FXSAVE
 * in the fpu_state_* helpers and ctx_switch.asm. Defined in arch_smap.c. */
extern uint8_t g_use_xsave;
#endif

#define TASK_RUNNING  0U
#define TASK_BLOCKED  1U
#define TASK_ZOMBIE   2U
#define TASK_STOPPED  3U

typedef struct aegis_task_t {
    uint64_t             sp;               /* MUST be first — ctx_switch reads [rdi+0] */
    /* on_cpu — which CPU is currently executing this task (cpu_id), or -1 when
     * the task is not running on any CPU.  Used by the SMP scheduler so two
     * CPUs never pick the same runnable task off the shared run list.  Offset
     * is fixed at 8 (ON_CPU_OFF in ctx_switch.asm must match; enforced by a
     * _Static_assert in sched.c).  ctx_switch.asm clears it to -1 right after
     * saving the outgoing task's stack pointer — the exact point at which the
     * task is safely suspended and may be picked up by another CPU. */
    int32_t              on_cpu;           /* offset 8 */
    uint8_t              is_idle;          /* offset 12 — 1 = per-CPU idle task (never queued) */
    uint8_t              _pad_on_cpu[3];   /* offset 13-15 — keep fpu_state 16-aligned */
#if defined(__aarch64__)
    /* fpu_state — AArch64 FP/SIMD save area for this task's user NEON state:
     * 32 × 128-bit V registers (512 bytes) + FPSR + FPCR (2 × 32-bit) at
     * byte offset 512.  The kernel is built -mgeneral-regs-only and never
     * touches V registers, so the live FP state at any ctx_switch point
     * belongs to the outgoing task's user code — ctx_switch.S swaps this
     * area exactly like the x86 FXSAVE path.  aligned(16) both satisfies
     * the ldp/stp q operands and pins the field at byte offset 16
     * (FPU_OFF in ctx_switch.S — _Static_assert in sched.c). */
    __attribute__((aligned(16))) uint8_t fpu_state[528];
#elif defined(__x86_64__)
    /* fpu_state — 512-byte FXSAVE/FXRSTOR area for this task's user FPU/SSE
     * state (x87 ST0-7, FCW/FSW/FTW/FOP, XMM0-15, MXCSR).
     *
     * The kernel is compiled -mno-sse and never touches these registers, but
     * user code does (musl memcpy uses SSE).  ctx_switch.asm does
     * fxsave/fxrstor on this area so a timer preemption mid-SSE in task A
     * cannot let task B clobber A's live XMM/x87/MXCSR state.
     *
     * Offset is fixed at 16 — FPU_STATE_OFF in ctx_switch.asm must match;
     * enforced by a _Static_assert in sched.c.  The 16-byte alignment is
     * mandatory: FXSAVE/FXRSTOR #GP on a misaligned operand.  All TCBs are
     * kva page allocations (4 KiB aligned) or, for sched_start's one-shot
     * outgoing dummy, a stack local whose 16-byte alignment the compiler
     * provides because the member alignment propagates to the struct.
     *
     * Must hold VALID state before the task is first switched in (fxrstor
     * runs at switch-in): every creation path calls fpu_state_init() or
     * fpu_state_save_live() below.  All-zeros is NOT valid default state —
     * FCW=0/MXCSR=0 unmask every x87/SSE exception.
     *
     * Sized + aligned for XSAVE (AVX): 512-byte legacy FXSAVE region + 64-byte
     * XSAVE header + 256-byte YMM_Hi region = 832 bytes for XCR0=0x7; 1024
     * leaves margin.  XSAVE/XRSTOR #GP on a non-64-byte-aligned operand (FXSAVE
     * only needed 16), so alignment is 64 and the compiler pads the offset to
     * 64 — which must equal FPU_STATE_OFF in ctx_switch.asm (_Static_assert in
     * sched.c).  With g_use_xsave==0 (no AVX, e.g. qemu64) only the first 512
     * bytes are touched by FXSAVE/FXRSTOR; the rest is harmless slack. */
    __attribute__((aligned(64))) uint8_t fpu_state[1024];
#endif
    uint8_t             *stack_base;       /* bottom of kva-allocated stack (freed on exit via kva_free_pages) */
    uint64_t             kernel_stack_top; /* RSP0 value: kernel stack top for this task */
    uint32_t             tid;              /* task ID */
    uint8_t              is_user;          /* 1 = user process (aegis_process_t), 0 = kernel task */
    uint64_t             stack_pages;      /* kva pages allocated for this task's kernel stack */
    uint32_t             state;        /* TASK_RUNNING=0 TASK_BLOCKED=1 TASK_ZOMBIE=2 */
    uint32_t             wake_pending; /* lost-wakeup guard. Set by sched_wake when a wake
                                        * lands in the window after a consumer has registered
                                        * its waiter but before it reached sched_block().
                                        * sched_block() consumes it and returns WITHOUT
                                        * blocking, so the caller re-checks its condition
                                        * (every sched_block caller loops). Without this, the
                                        * state=BLOCKED in sched_block would clobber the wake
                                        * and the task would sleep forever. Cleared on the
                                        * block-resume path so it never lingers past one block. */
    uint32_t             waiting_for;  /* PID this task waits for; 0=any child */
    uint32_t             last_syscall; /* DIAG: syscall number this task last entered
                                        * (set in syscall_dispatch); shows what a BLOCKED
                                        * task is stuck in, via /proc/tasks. */
    uint64_t             fs_base;          /* per-thread TLS base (IA32_FS_BASE / TPIDR_EL0) */
    uint64_t             clear_child_tid;  /* user VA: write 0 + futex_wake on exit */
    uint64_t             sleep_deadline;   /* PIT tick when nanosleep expires; 0 = not sleeping */
    int                  read_nonblock;    /* 1 = current sys_read is O_NONBLOCK; per-task, not global */
    int                  write_nonblock;   /* 1 = current sys_write is O_NONBLOCK; per-task, mirrors read_nonblock */
    struct aegis_task_t *next;             /* circular linked list (all tasks) */
    /* RUNNING-only run queue (P3 audit fix).
     *
     * Separate circular doubly-linked list threaded through tasks whose
     * state == TASK_RUNNING, anchored at a static sentinel in sched.c.
     * sched_tick walks this list instead of the full `next` chain to avoid
     * O(N) scans of blocked/zombie/stopped tasks.
     *
     * Invariant: a task is in the run list IFF state == TASK_RUNNING AND
     * next_run != NULL.  next_run == NULL means "not currently in the list".
     * Exception: the idle task (sched_spawn_idle) stays TASK_RUNNING with
     * next_run == NULL forever — it is the empty-list fallback, never a
     * list member, so it never consumes a round-robin slice.
     * Mutations (insert/remove) require sched_lock; state-flip-only helpers
     * must call the _locked variants that also update the list. */
    struct aegis_task_t *next_run;
    struct aegis_task_t *prev_run;
#ifdef AEGIS_LOCK_DEBUG
    /* OR-mask of lock ranks this task currently holds (debug-only lock-order
     * enforcement; see core/lockrank.h).  Placed last so on_cpu/fpu_state
     * offsets — asserted against ctx_switch.asm — are unaffected, and absent
     * entirely in release builds. */
    uint32_t             lock_rank_mask;
#endif
} aegis_task_t;

#ifdef __x86_64__
/* fpu_state_init — fill a task's FXSAVE area with the x86-64 ABI default
 * FPU state.  NOT all-zeros: FCW=0 and MXCSR=0 would unmask every x87/SSE
 * exception, so the first SSE instruction in the task could raise #XM.
 * Layout (Intel SDM, FXSAVE area): FCW at byte 0 = 0x037F (all x87
 * exceptions masked, 64-bit precision), FSW=0, abridged FTW at byte 4 = 0
 * (all x87 registers empty), MXCSR at byte 24 = 0x1F80 (all SSE exceptions
 * masked, round-to-nearest).  MXCSR_MASK (byte 28) is ignored by FXRSTOR.
 * Call from every task-creation path before the task can be switched in. */
static inline void
fpu_state_init(aegis_task_t *task)
{
    int i;
    for (i = 0; i < 1024; i++)
        task->fpu_state[i] = 0;
    task->fpu_state[0]  = 0x7F;   /* FCW  = 0x037F (lo) */
    task->fpu_state[1]  = 0x03;   /* FCW  = 0x037F (hi) */
    task->fpu_state[24] = 0x80;   /* MXCSR = 0x1F80 (lo) */
    task->fpu_state[25] = 0x1F;   /* MXCSR = 0x1F80 (hi) */
    /* XSAVE header: XSTATE_BV (byte 512) = x87|SSE present (restored from the
     * legacy region above); AVX bit (2) clear → XRSTOR inits YMM to zero.
     * XCOMP_BV (byte 520) stays 0 = standard (non-compacted) format.  FXRSTOR
     * ignores bytes >= 512, so writing this unconditionally is harmless when
     * g_use_xsave == 0. */
    task->fpu_state[512] = 0x03;
}

/* fpu_state_save_live — FXSAVE the CPU's live FPU/SSE registers into a
 * task's save area.  Used by fork/clone: at syscall entry the live FPU
 * state is the parent's user state (the -mno-sse kernel never modifies
 * it), so saving it into the CHILD's area gives POSIX fork semantics —
 * the child inherits the parent's FPU registers. */
static inline void
fpu_state_save_live(aegis_task_t *task)
{
    if (g_use_xsave) {
        /* XSAVE writes XSTATE_BV + the in-use components but NOT XCOMP_BV or
         * the header's reserved bytes.  TCB pages from kva_alloc are NOT
         * zeroed, so an unzeroed area leaves XCOMP_BV garbage — and a later
         * XRSTOR #GPs unless XCOMP_BV is 0 (standard, non-compacted format).
         * Zero the whole area first so the XSAVE header is well-formed.
         * (mask EAX:EDX = 7 via mov, with eax/edx clobbered so the "r" pointer
         * is never allocated to rax/rdx.) */
        int i;
        for (i = 0; i < 1024; i++)
            task->fpu_state[i] = 0;
        __asm__ volatile("mov $7, %%eax\n\t"
                         "xor %%edx, %%edx\n\t"
                         "xsave (%0)"
                         : : "r"(task->fpu_state) : "eax", "edx", "memory");
    } else {
        __asm__ volatile("fxsave (%0)" : : "r"(task->fpu_state) : "memory");
    }
}

/* fpu_state_restore_live — FXRSTOR a task's save area into the live FPU
 * registers.  Used by execve to reset the new image's FPU state to the
 * ABI defaults (pair with fpu_state_init).  Caller must be the current
 * task and not be preempted between init and restore (syscall context
 * runs with IF=0, so this holds). */
static inline void
fpu_state_restore_live(const aegis_task_t *task)
{
    if (g_use_xsave)
        __asm__ volatile("mov $7, %%eax\n\t"
                         "xor %%edx, %%edx\n\t"
                         "xrstor (%0)"
                         : : "r"(task->fpu_state) : "eax", "edx", "memory");
    else
        __asm__ volatile("fxrstor (%0)" : : "r"(task->fpu_state) : "memory");
}
#elif defined(__aarch64__)
/* arm64 FP/SIMD helpers.  arm64_fpu_save/restore live in ctx_switch.S
 * (raw ldp/stp q — the C here is built -mgeneral-regs-only and cannot
 * name V registers). */
void arm64_fpu_save(void *area);
void arm64_fpu_restore(const void *area);

/* Default FP state = all zero: FPCR=0 (round-to-nearest, no exception
 * traps, flush-to-zero off) and FPSR=0, V registers cleared.  Call from
 * every task-creation path before the task can be switched in. */
static inline void
fpu_state_init(aegis_task_t *task)
{
    __builtin_memset(task->fpu_state, 0, sizeof(task->fpu_state));
}

/* Snapshot the CPU's live V registers into the task area (fork: the child
 * inherits the parent's live user FP state — the -mgeneral-regs-only
 * kernel hasn't touched it since SVC entry, and IF-off prevents preemption). */
static inline void
fpu_state_save_live(aegis_task_t *task)
{
    arm64_fpu_save(task->fpu_state);
}

/* Load the task area into the live V registers (execve: reset to the
 * fpu_state_init defaults before returning to the new image). */
static inline void
fpu_state_restore_live(const aegis_task_t *task)
{
    arm64_fpu_restore(task->fpu_state);
}
#else
/* Other arches — no FP context yet. */
static inline void fpu_state_init(aegis_task_t *task) { (void)task; }
static inline void fpu_state_save_live(aegis_task_t *task) { (void)task; }
static inline void fpu_state_restore_live(const aegis_task_t *task) { (void)task; }
#endif /* arch FP helpers */

/* Initialize the run queue. No tasks yet. */
void sched_init(void);

/* Allocate a TCB and 16KB stack from PMM; wire fn as entry point; add to queue. */
void sched_spawn(void (*fn)(void));

/* Spawn the idle task: same allocation/linking as sched_spawn, but the task
 * is registered as the scheduler's idle fallback and is NEVER inserted into
 * the RUNNING-only run queue.  Pick-next paths select it only when no other
 * task is runnable, so idle consumes no round-robin slice while real work
 * exists.  Must be called exactly once per boot, before sched_start. */
void sched_spawn_idle(void (*fn)(void));

/* Pre-spawn a per-CPU idle task for `cpu` (BSP-only; records into
 * g_percpu[cpu].idle_task).  Used to create AP idle tasks before they enter
 * the scheduler. */
void sched_spawn_idle_for(uint32_t cpu, void (*fn)(void));

/* True once sched_start has set the ready guard — APs poll this. */
int sched_is_ready(void);

/* Print [SCHED] OK line, then switch directly into the first task via a
 * dummy TCB (one-way ctx_switch). Does not return. Each task enables
 * interrupts on entry via the arch interrupt-enable primitive. */
void sched_start(void);

/* Preemption tick — called by the per-CPU LAPIC timer handler on x86-64
 * (vector 0x30, ~100 Hz; the PIT keeps timekeeping/polling only) and by
 * the generic-timer handler on arm64.
 * Wakes expired sleepers, advances current task and calls ctx_switch. */
void sched_tick(void);

/* Add a pre-initialized TCB to the run queue.
 * Used by proc_spawn to insert a user process without duplicating
 * the list-insertion logic from sched_spawn. */
void sched_add(aegis_task_t *task);

/* Remove the current task from the run queue and switch to the next task.
 * Called from sys_exit (syscall 60). Does not return.
 * TCB and kernel stack are freed via deferred kva_free_pages at the next sched_exit call. */
void sched_exit(void);

/* Returns the currently running task for this CPU via per-CPU GS.base. */
static inline aegis_task_t *
sched_current(void)
{
    return percpu_current();
}

/* sched_block — mark current task TASK_BLOCKED and yield.
 * Unlinks current from the run queue; switches to the next RUNNING task,
 * or to the idle task when the run queue is empty.
 * REQUIRES: sched_spawn_idle has run (true for any post-boot caller). */
extern uint32_t s_vfork_frozen_tgid;
void sched_block(void);

/* sched_block_locked — block the current task when the caller ALREADY holds
 * sched_lock (fl = flags from its spin_lock_irqsave).  Releases the lock before
 * switching away.  Makes "scan a condition, then block" atomic against a waker
 * that runs under sched_lock — closes the lost-wakeup window.  sys_waitpid uses
 * it so a concurrently-exiting child can't slip its SIGCHLD wake between the
 * parent's no-zombie scan and its transition to TASK_BLOCKED. */
void sched_block_locked(irqflags_t fl);

/* sched_wake — mark task TASK_RUNNING and insert into the run queue.
 * Acquires sched_lock internally; safe to call from any caller that does
 * NOT already hold sched_lock (pipe/socket/futex/signal_send_pid paths).
 * Use sched_wake_locked if the caller already holds sched_lock. */
void sched_wake(aegis_task_t *task);

/* sched_wake_locked — same as sched_wake but caller already holds sched_lock.
 * Used by sched_exit -> signal_send_pid_locked -> sched_wake_locked. */
void sched_wake_locked(aegis_task_t *task);

/* sched_dequeue_locked — remove a task from the RUNNING-only run queue.
 * Caller must hold sched_lock.  Idempotent (no-op if not queued).
 * Pair with a state flip away from TASK_RUNNING in the same critical
 * section — the run-list invariant is "in list IFF state == TASK_RUNNING".
 * Used by sys_exit_group when force-zombifying sibling threads. */
void sched_dequeue_locked(aegis_task_t *task);

/* sched_stop — transition a task to TASK_STOPPED.
 * If task == sched_current() (self-stop): mirrors sched_block exactly —
 * sets state, advances to next TASK_RUNNING via percpu, updates TSS/FS.base,
 * calls ctx_switch. Execution resumes when SIGCONT calls sched_resume and
 * sched_tick next schedules this task.
 * If task != sched_current(): sets task->state = TASK_STOPPED only;
 * sched_tick will skip it on next preemption. Must be called with IF=0. */
void sched_stop(aegis_task_t *task);

/* sched_resume — transition TASK_STOPPED (or TASK_BLOCKED) back to TASK_RUNNING.
 * Mirrors sched_wake: task->state = TASK_RUNNING. No list re-insertion needed. */
void sched_resume(aegis_task_t *task);

/* sched_yield_to_next — advance percpu current to the next RUNNING task
 * and ctx_switch. Used by the zombie path in sched_exit.
 * The zombie's kernel stack is still live during ctx_switch; the caller
 * must not touch task state after sched_yield_to_next returns (it returns
 * in the new task's context, not the zombie's). */
void sched_yield_to_next(void);

#endif /* AEGIS_SCHED_H */
