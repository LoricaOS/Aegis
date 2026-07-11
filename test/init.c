/* Aegis kernel test-init — a freestanding test program the kernel boots as init
 * (pid 1) from a minimal test rootfs. NO libc, NO userland dependency: raw
 * `syscall` instructions only, built with the kernel's own x86_64-elf toolchain.
 *
 * It proves the kernel boots a user process end-to-end AND that the capability
 * model holds at the syscall boundary: a privileged syscall (sethostname, gated
 * on CAP_KIND_POWER) must be DENIED for init, which holds only baseline caps —
 * the no-ambient-authority guarantee, even for pid 1. Results go to fd 1/2
 * (the kernel pre-opens both to /dev/console → serial). Harness greps the
 * "[KTEST] DONE all-pass" line.
 */

#ifdef __aarch64__
/* aarch64: nr in x8, args x0-x5, svc #0, ret in x0. */
static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
}
#else
/* x86-64: nr in rax; args rdi,rsi,rdx,r10,r8,r9; ret in rax. */
static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}
#endif
static long sys3(long n, long a, long b, long c) { return sys6(n, a, b, c, 0, 0, 0); }

/* Non-colliding syscalls: the x86 number passes through the aarch64 dispatch
 * unchanged (see kernel/syscall/syscall.c). */
#define SYS_write        1
#define SYS_getpid       39
#define SYS_exit         60
#define SYS_sethostname  170   /* gated on CAP_KIND_POWER — init HOLDS this */
#define SYS_blkdev_list  510   /* gated on CAP_KIND_DISK_ADMIN — init LACKS this */

/* Colliding syscalls: the x86 number would be MIS-translated on aarch64, so
 * use each arch's real Linux number (aarch64's are translated to the x86
 * dispatch numbers by the kernel). */
#ifdef __aarch64__
#define SYS_clone        220
#define SYS_wait4        260
#define SYS_kill         129
#define SYS_execve       221
#define SYS_rt_sigaction 134
#define SYS_rt_sigreturn 139
#else
#define SYS_clone        56
#define SYS_wait4        61
#define SYS_kill         62
#define SYS_execve       59
#define SYS_rt_sigaction 13
#define SYS_rt_sigreturn 15
#endif

#define SIGCHLD 17
#define SIGUSR1 10

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void out(const char *s) { sys3(SYS_write, 2, (long)s, slen(s)); }

/* Signal handling: a handler + a restorer trampoline. On return, the handler
 * branches to the restorer (x30/pretcode), which calls rt_sigreturn to
 * restore the interrupted context. */
static volatile int g_sig_got = 0;
static void sig_handler(int signum) { g_sig_got = signum; }
static volatile long g_cow = 0;   /* dedicated COW test page (data, not stack) */

#ifdef __aarch64__
__asm__(".globl sig_restorer\nsig_restorer:\n\tmov x8, #139\n\tsvc #0\n");
#else
__asm__(".globl sig_restorer\nsig_restorer:\n\tmovq $15, %rax\n\tsyscall\n");
#endif
extern void sig_restorer(void);

/* Kernel k_sigaction_t layout (kernel/signal/signal.h): identical on both
 * arches — handler, flags, restorer, mask, each 8 bytes. */
struct ksigaction {
    void (*sa_handler)(int);
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    unsigned long sa_mask;
};

void _start(void)
{
    int pass = 0, total = 0;

    out("[KTEST] init running\n");

    /* 1. init is pid 1 */
    total++;
    if (sys3(SYS_getpid, 0, 0, 0) == 1) { pass++; out("[KTEST] PASS getpid==1\n"); }
    else out("[KTEST] FAIL getpid\n");

    /* 2. write() returns the byte count it wrote */
    total++;
    if (sys3(SYS_write, 1, (long)"ok\n", 3) == 3) { pass++; out("[KTEST] PASS write\n"); }
    else out("[KTEST] FAIL write\n");

    /* 3. POSITIVE control: sethostname needs CAP_KIND_POWER, which init DOES
     *    hold, so it must SUCCEED — proving granted capabilities actually work
     *    (the model isn't just "deny everything"). */
    total++;
    if (sys3(SYS_sethostname, (long)"aegis", 5, 0) == 0) { pass++; out("[KTEST] PASS power-held\n"); }
    else out("[KTEST] FAIL power-should-be-held\n");

    /* 4. NEGATIVE control — the whole point: blkdev_list needs CAP_KIND_DISK_ADMIN,
     *    which init does NOT hold (and admin_session=0), so the kernel must refuse
     *    it. No ambient authority: not even pid 1 gets raw disk access for free. */
    total++;
    if (sys3(SYS_blkdev_list, 0, 0, 0) < 0) { pass++; out("[KTEST] PASS diskadmin-denied\n"); }
    else out("[KTEST] FAIL diskadmin-NOT-denied (privesc!)\n");

    /* 5. FP/SIMD state survives a context switch (arm64 only — this
     *    test-init is built -mno-sse on x86, where the FXSAVE path is
     *    already proven by the real LoricaOS userland). Load a sentinel
     *    into an FP register and spin long enough that the 100 Hz timer
     *    preempts us (ctx_switch to idle and back); the whole thing lives
     *    in one asm block so the register stays live across the
     *    preemption. A wrong FP save/restore (bad offset, corruption)
     *    brings the value back changed. */
#ifdef __aarch64__
    total++;
    {
        unsigned long sent = 0x123456789ABCDEF0UL, got = 0;
        __asm__ volatile(
            "fmov d0, %1\n"
            "mov  x9, #0x2000000\n"
            "1: subs x9, x9, #1\n"
            "b.ne 1b\n"
            "fmov %0, d0\n"
            : "=r"(got) : "r"(sent) : "x9", "v0", "memory");
        if (got == sent) { pass++; out("[KTEST] PASS fp-survives-switch\n"); }
        else out("[KTEST] FAIL fp-corrupted-across-switch\n");
    }
#endif

    /* 6. fork (via clone(SIGCHLD)) + copy-on-write isolation + wait/reap.
     *    A stack variable is COW-shared with the child; the child writes it
     *    (breaking COW on its own page) and exits with a status derived from
     *    what it read back; the parent reaps and checks BOTH the child's exit
     *    status AND that its own copy is untouched. Exercises the fork frame
     *    (fork_child_return), vmm_cow_user_pages, and vmm_cow_fault_handle. */
    total++;
    {
        g_cow = 0xAAAA;                    /* parent writes the shared page */
        long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (pid == 0) {
            g_cow = 0xBBBB;                /* COW break in the child only */
            sys3(SYS_exit, (g_cow == 0xBBBB) ? 7 : 8, 0, 0);
        }
        int status = 0;
        sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
        int cs = (status >> 8) & 0xff;
        /* parent must NOT have observed the child's write (COW isolation) */
        if (pid > 0 && cs == 7 && g_cow == 0xAAAA) {
            pass++; out("[KTEST] PASS fork+cow (child isolated)\n");
        } else out("[KTEST] FAIL fork/cow\n");
    }

    /* 7. Signal delivery + sigreturn. Install a SIGUSR1 handler, kill self,
     *    and check the handler ran and returned cleanly. On arm64 this
     *    exercises signal_deliver (incl. the x30=restorer fix) and
     *    sys_rt_sigreturn's full-frame restore. */
    total++;
    {
        struct ksigaction act;
        act.sa_handler  = sig_handler;
        act.sa_flags    = 0;
        act.sa_restorer = sig_restorer;
        act.sa_mask     = 0;
        g_sig_got = 0;
        sys6(SYS_rt_sigaction, SIGUSR1, (long)&act, 0, 8, 0, 0);
        long mypid = sys3(SYS_getpid, 0, 0, 0);
        sys3(SYS_kill, mypid, SIGUSR1, 0);
        if (g_sig_got == SIGUSR1) { pass++; out("[KTEST] PASS signal+sigreturn\n"); }
        else out("[KTEST] FAIL signal\n");
    }

    /* 8. execve: fork a child that execs a SECOND binary (/bin/exectest).
     *    Validates the full exec path — ELF load of a new image + the EL0/
     *    ring-3 entry trampoline. exectest exits 42; execve only returns on
     *    failure, in which case the child exits 99.
     *
     *    exectest ALSO doubles as the service-tier privilege-laundering guard:
     *    it ships `service DISK_ADMIN` policy and probes blkdev_list. The kernel
     *    must refuse an admin-gated cap through the unconditional SERVICE tier,
     *    so exectest exits 42 (refused, good) — NOT 43 (granted = privesc). */
    total++;
    {
        long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (pid == 0) {
            static char *const argv[] = { (char *)"/bin/exectest", 0 };
            static char *const envp[] = { 0 };
            sys3(SYS_execve, (long)"/bin/exectest", (long)argv, (long)envp);
            sys3(SYS_exit, 99, 0, 0);   /* exec failed */
        }
        int status = 0;
        sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
        int cs = (status >> 8) & 0xff;
        if (pid > 0 && cs == 42) { pass++; out("[KTEST] PASS exec\n"); }
        else if (cs == 43) out("[KTEST] FAIL svc-tier-DISK_ADMIN-granted (privesc!)\n");
        else out("[KTEST] FAIL exec\n");
    }

    /* 9. Concurrent multi-core scheduling: fork 4 children that each spin
     *    (long enough to overlap in wall time) and exit with a distinct
     *    code; the parent reaps all four and checks every code came back.
     *    Under -smp N the children run on different cores simultaneously,
     *    exercising cross-core scheduling, per-core COW faults, and TLB
     *    coherence. Correct (sequential) on a single core too. */
    total++;
    {
        long pids[4];
        int i, ok = 1;
        for (i = 0; i < 4; i++) {
            long p = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
            if (p == 0) {
                volatile unsigned long x = 0;
                for (unsigned long s = 0; s < 8000000UL; s++) x++;
                sys3(SYS_exit, 20 + i, 0, 0);
            }
            if (p < 0) ok = 0;
            pids[i] = p;
        }
        int seen = 0;
        for (i = 0; i < 4; i++) {
            int status = 0;
            long w = sys6(SYS_wait4, pids[i], (long)&status, 0, 0, 0, 0);
            int cs = (status >> 8) & 0xff;
            if (w == pids[i] && cs >= 20 && cs <= 23) seen |= (1 << (cs - 20));
        }
        if (ok && seen == 0xF) { pass++; out("[KTEST] PASS smp-fork (4 concurrent)\n"); }
        else out("[KTEST] FAIL smp-fork\n");
    }

    if (pass == total) out("[KTEST] DONE all-pass\n");
    else                out("[KTEST] DONE FAIL\n");

    sys3(SYS_exit, 0, 0, 0);
    for (;;) { }
}
