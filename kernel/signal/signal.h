#ifndef AEGIS_SIGNAL_H
#define AEGIS_SIGNAL_H

#include <stdint.h>

/* ── Signal numbers (POSIX, same on all architectures) ─────────── */

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1  10
#define SIGSEGV  11
#define SIGUSR2  12
#define SIGPIPE  13
#define SIGALRM  14
#define SIGTERM  15
#define SIGCHLD  17
#define SIGCONT  18
#define SIGSTOP  19
#define SIGTSTP  20
#define SIGTTIN  21
#define SIGTTOU  22
#define SIGWINCH 28

#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)

/* ── Architecture-specific signal frame structures ─────────────── */

/* k_sigaction_t: kernel's view of struct sigaction.
 * rt_sigframe_t: signal frame pushed to user stack.
 * REG_*: gregset_t indices for register save/restore.
 *
 * These differ between x86-64 and ARM64 because:
 * - Register sets are different (16 GPRs vs 31 GPRs)
 * - musl's sigaction layout differs per-arch
 * - The ucontext/mcontext structure varies */

#ifdef __aarch64__

/* ARM64 musl struct sigaction layout */
typedef struct {
    void    (*sa_handler)(int);
    uint64_t sa_flags;
    void    (*sa_restorer)(void);
    uint64_t sa_mask;
} k_sigaction_t;

/* ARM64 gregset_t indices — 31 GPRs + SP + PC + PSTATE */
#define REG_X0       0
#define REG_X1       1
#define REG_X8       8
#define REG_X29     29
#define REG_X30     30
#define REG_SP      31
#define REG_PC      32
#define REG_PSTATE  33

/* Aliases for code that uses x86 names in generic signal paths */
#define REG_RIP     REG_PC
#define REG_RSP     REG_SP
#define REG_EFL     REG_PSTATE
#define REG_R8      REG_X8

/* ARM64 signal frame — matches musl's AArch64 sigcontext layout.
 * Simplified: only save/restore GPRs + SP + PC + PSTATE.
 * Full FP/SIMD state is not saved (matching Phase 17 on x86). */
typedef struct {
    uint64_t pretcode;              /* &__restore_rt (sa_restorer) */
    uint8_t  siginfo[128];         /* struct siginfo — zeroed */
    uint64_t uc_flags;
    uint64_t uc_link;
    uint64_t uc_stack_sp;
    uint32_t uc_stack_flags;
    uint32_t uc_stack_pad;
    uint64_t uc_stack_size;
    /* mcontext_t: 34 registers (x0-x30, sp, pc, pstate) */
    int64_t  gregs[34];
    uint64_t fpregs;                /* 0 — no FP state */
    uint64_t __reserved1[8];
    uint64_t uc_sigmask;
    uint8_t  _uc_sigmask_pad[120];
} rt_sigframe_t;

#else /* x86-64 */

/* x86-64 musl struct sigaction layout */
typedef struct {
    void    (*sa_handler)(int);
    uint64_t sa_flags;
    void    (*sa_restorer)(void);
    uint64_t sa_mask;
} k_sigaction_t;

_Static_assert(sizeof(k_sigaction_t) == 32,
    "k_sigaction_t must be 32 bytes (musl struct sigaction x86-64)");

/* x86-64 gregset_t indices (Linux, REG_* in <sys/ucontext.h>) */
#define REG_R8       0
#define REG_R9       1
#define REG_R10      2
#define REG_R11      3
#define REG_R12      4
#define REG_R13      5
#define REG_R14      6
#define REG_R15      7
#define REG_RDI      8
#define REG_RSI      9
#define REG_RBP     10
#define REG_RBX     11
#define REG_RDX     12
#define REG_RAX     13
#define REG_RCX     14
#define REG_RSP     15
#define REG_RIP     16
#define REG_EFL     17
#define REG_CSGSFS  18
#define REG_ERR     19
#define REG_TRAPNO  20
#define REG_OLDMASK 21
#define REG_CR2     22

/* x86-64 signal frame — matches Linux x86-64 ABI (560 bytes). */
typedef struct {
    uint64_t pretcode;
    uint8_t  siginfo[128];
    uint64_t uc_flags;
    uint64_t uc_link;
    uint64_t uc_stack_sp;
    uint32_t uc_stack_flags;
    uint32_t uc_stack_pad;
    uint64_t uc_stack_size;
    int64_t  gregs[23];
    uint64_t fpregs;
    uint64_t __reserved1[8];
    uint64_t uc_sigmask;
    uint8_t  _uc_sigmask_pad[120];
} rt_sigframe_t;

_Static_assert(sizeof(rt_sigframe_t) == 560,
    "rt_sigframe_t must be 560 bytes");

#endif /* __aarch64__ / x86-64 */

/* ── Architecture-agnostic signal API ──────────────────────────── */

/* Magic return value from sys_rt_sigreturn — signals the syscall
 * return path to skip signal check (frame already patched). */
#define SIGRETURN_MAGIC 0xdeadbeefcafebabeULL

/* Forward declarations (avoid circular includes) */
struct cpu_state;
struct syscall_frame;

/* Deliver pending signals when returning to user mode.
 * x86-64: called from isr.asm on iretq path.
 * ARM64: stubbed (signal delivery not yet implemented). */
void signal_deliver(struct cpu_state *s);

/* Deliver pending signals on syscall return path.
 * Returns 1 if a handler was set up, 0 otherwise. */
int signal_deliver_sysret(struct syscall_frame *frame,
                          uint64_t *saved_rdi_ptr);

/* Send signal to a process by PID. Safe from ISR context. */
void signal_send_pid(uint32_t pid, int signum);

/* Same as signal_send_pid, but caller already holds sched_lock.
 * Calls sched_wake_locked / sched_resume_locked instead of the
 * lock-acquiring variants.  Used by sched_exit to signal SIGCHLD
 * to the parent while still holding sched_lock. */
void signal_send_pid_locked(uint32_t pid, int signum);

/* Send signal to all processes in a process group. */
void signal_send_pgrp(uint32_t pgid, int signum);

/* Return 1 if current process has deliverable pending signals. */
int signal_check_pending(void);

#endif /* AEGIS_SIGNAL_H */
