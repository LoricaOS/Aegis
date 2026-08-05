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
#define SYS_exit         60
#define SYS_sethostname  170   /* gated on CAP_KIND_POWER — init HOLDS this */
#define SYS_blkdev_list  510   /* gated on CAP_KIND_DISK_ADMIN — init LACKS this */
#define SYS_vfs_confine  518   /* Aegis: confine self to a subtree (no cap) */

/* Colliding syscalls: the x86 number would be MIS-translated on aarch64, so
 * use each arch's real Linux number (aarch64's are translated to the x86
 * dispatch numbers by the kernel). */
#ifdef __aarch64__
#define SYS_getpid       172   /* was non-colliding (x86 39 passed through) until
                                * the mount syscall added aarch64 umount2(39) →
                                * 39 now collides, so use the real aarch64 nr */
#define SYS_mount        40
#define SYS_clone        220
#define SYS_wait4        260
#define SYS_kill         129
#define SYS_execve       221
#define SYS_rt_sigaction 134
#define SYS_rt_sigreturn 139
#define SYS_sigaltstack  132
#define SYS_mmap         222
#define SYS_mremap       216
#define SYS_brk          214
#define SYS_clock_gettime  113
#define SYS_clock_nanosleep 115
#define SYS_sched_yield  124
#define SYS_tgkill       131
/* The *at forms are the only ones aarch64 has; musl builds every legacy call
 * out of them, so the test must use them too — that is precisely the path
 * where the kernel's aarch64 translation has to preserve the flags. */
#define SYS_mkdirat      34
#define SYS_unlinkat     35
#define SYS_symlinkat    36
#define SYS_openat       56
#define SYS_close        57
#define SYS_readlinkat   78
#define SYS_newfstatat   79
#define SYS_pipe2        59
#define SYS_read         63
#define SYS_exit_group   94
#else
#define SYS_getpid       39
#define SYS_mount        165
#define SYS_clone        56
#define SYS_wait4        61
#define SYS_kill         62
#define SYS_execve       59
#define SYS_rt_sigaction 13
#define SYS_rt_sigreturn 15
#define SYS_sigaltstack  131
#define SYS_mmap         9
#define SYS_mremap       25
#define SYS_brk          12
#define SYS_clock_gettime  228
#define SYS_clock_nanosleep 230
#define SYS_sched_yield  24
#define SYS_tgkill       234
#define SYS_stat         4
#define SYS_lstat        6
#define SYS_close        3
#define SYS_openat       257
#define SYS_mkdir        83
#define SYS_rmdir        84
#define SYS_unlink       87
#define SYS_symlink      88
#define SYS_readlink     89
#define SYS_pipe2        293
#define SYS_read         0
#define SYS_exit_group   231
#endif

#define AT_FDCWD             -100
#define AT_SYMLINK_NOFOLLOW  0x100
#define AT_REMOVEDIR         0x200

/* Portable wrappers over the two syscall dialects, so the checks below read
 * the same on both arches. */
static long k_mkdir(const char *p)
{
#ifdef __aarch64__
    return sys3(SYS_mkdirat, AT_FDCWD, (long)p, 0755);
#else
    return sys3(SYS_mkdir, (long)p, 0755, 0);
#endif
}
static long k_rmdir(const char *p)
{
#ifdef __aarch64__
    return sys3(SYS_unlinkat, AT_FDCWD, (long)p, AT_REMOVEDIR);
#else
    return sys3(SYS_rmdir, (long)p, 0, 0);
#endif
}
static long k_unlink(const char *p)
{
#ifdef __aarch64__
    return sys3(SYS_unlinkat, AT_FDCWD, (long)p, 0);
#else
    return sys3(SYS_unlink, (long)p, 0, 0);
#endif
}
static long k_symlink(const char *target, const char *link)
{
#ifdef __aarch64__
    return sys3(SYS_symlinkat, (long)target, AT_FDCWD, (long)link);
#else
    return sys3(SYS_symlink, (long)target, (long)link, 0);
#endif
}
static long k_readlink(const char *p, char *buf, unsigned long bufsiz)
{
#ifdef __aarch64__
    return sys6(SYS_readlinkat, AT_FDCWD, (long)p, (long)buf, (long)bufsiz, 0, 0);
#else
    return sys3(SYS_readlink, (long)p, (long)buf, (long)bufsiz);
#endif
}
/* Fills the caller's struct-stat buffer; returns 0 or negative errno. */
static long k_stat_at(const char *p, void *st, int nofollow)
{
#ifdef __aarch64__
    return sys6(SYS_newfstatat, AT_FDCWD, (long)p, (long)st,
                nofollow ? AT_SYMLINK_NOFOLLOW : 0, 0, 0);
#else
    return sys3(nofollow ? SYS_lstat : SYS_stat, (long)p, (long)st, 0);
#endif
}
/* st_mode's byte offset differs per arch (x86-64 puts st_nlink first). */
static unsigned k_stat_mode(const void *st)
{
#ifdef __aarch64__
    return *(const unsigned *)((const char *)st + 16);
#else
    return *(const unsigned *)((const char *)st + 24);
#endif
}
#define K_IFMT  0170000
#define K_IFDIR 0040000
#define K_IFLNK 0120000

#define SIGCHLD 17
#define SIGUSR1 10
#define SIGUSR2 12
#define SA_ONSTACK 0x08000000UL
#define PROT_RW        0x3        /* PROT_READ | PROT_WRITE */
#define MAP_ANON_PRIV  0x22       /* MAP_PRIVATE | MAP_ANONYMOUS */
#define MREMAP_MAYMOVE 1

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void out(const char *s) { sys3(SYS_write, 2, (long)s, slen(s)); }

/* Signal handling: a handler + a restorer trampoline. On return, the handler
 * branches to the restorer (x30/pretcode), which calls rt_sigreturn to
 * restore the interrupted context. */
static volatile int g_sig_got = 0;
static void sig_handler(int signum) { g_sig_got = signum; }

/* Globals for the exit_group teardown case (14). The cloned THREAD lands on a
 * fresh stack, so it must not read anything off its creator's frame — every
 * value it needs lives here. */
static volatile long g_tg_rfd = -1;
static volatile long g_cow = 0;   /* dedicated COW test page (data, not stack) */

/* sigaltstack test: a SA_ONSTACK handler records the stack region it ran on
 * (the address of a local), which must fall inside g_altstack if delivery used
 * the alternate signal stack. */
static char g_altstack[8192];
static volatile unsigned long g_altsp = 0;
static void sig_alt_handler(int signum) {
    char probe;
    g_altsp = (unsigned long)(void *)&probe;
    g_sig_got = signum;
}
struct kstack { void *ss_sp; int ss_flags; unsigned long ss_size; };

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

    /* 4b. NEGATIVE control — mount needs CAP_KIND_MOUNT, which init does NOT
     *     hold, so the kernel must refuse sys_mount (fail closed): a filesystem
     *     mounted over /etc would be a privilege-escalation primitive. */
    total++;
    if (sys6(SYS_mount, 0, (long)"/mnt/x", (long)"tmpfs", 0, 0, 0) < 0)
        { pass++; out("[KTEST] PASS mount-denied\n"); }
    else out("[KTEST] FAIL mount-NOT-denied (privesc!)\n");

    /* 4c. VFS confinement — a CHILD confines itself to /tmp (so init stays
     *     unconfined for the tests below), then: an in-scope create succeeds, an
     *     out-of-scope open is refused (EACCES), and widening back out is
     *     refused (one-way). Purely additive authority-dropping, no cap. */
    total++;
    {
        long cpid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (cpid == 0) {
            int ok = 1;
            if (sys3(SYS_vfs_confine, (long)"/tmp", 0, 0) != 0) ok = 0;
            /* in-scope create → valid fd */
            if (sys6(SYS_openat, AT_FDCWD, (long)"/tmp/cjail", 0x40 | 1, 0644, 0, 0) < 0)
                ok = 0;
            /* out-of-scope open must be denied */
            if (sys6(SYS_openat, AT_FDCWD, (long)"/", 0, 0, 0, 0) >= 0)
                ok = 0;
            /* one-way: widening the scope must be refused */
            if (sys3(SYS_vfs_confine, (long)"/", 0, 0) == 0)
                ok = 0;
            /* The METADATA syscalls must honour the scope too. symlink, link,
             * readlink, chmod, chown, lchown and utimensat all resolve through
             * resolve_path(), which used to only prepend cwd — it never
             * consulted the scope, so all seven ignored confinement outright.
             * Creating a symlink in /etc from a process confined to /tmp must
             * be refused. */
            if (k_symlink("t", "/etc/ktest_escape") == 0)
                ok = 0;
            /* Same syscall, but escaping via "..". This is the divergence
             * between the two path resolvers: the lexical canonicalizer behind
             * the scope check pops ONE component per "..", while ext2_walk used
             * to CLAMP ".." to the filesystem root. So the checker saw
             * "/etc/..." only if it canonicalized -- and the version that
             * didn't handed ext2 the raw string, which walked ".." to root and
             * created the link outside the scope anyway. Both resolvers agree
             * now, and the path is canonicalized before it is checked. */
            if (k_symlink("t", "/tmp/../etc/ktest_escape2") == 0)
                ok = 0;
            /* descendants inherit confinement: a grandchild must ALSO be denied
             * "/" (it inherited /tmp scope across fork). */
            long gpid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
            if (gpid == 0)
                sys3(SYS_exit,
                     (sys6(SYS_openat, AT_FDCWD, (long)"/", 0, 0, 0, 0) < 0) ? 0 : 1,
                     0, 0);
            long gstatus = -1;
            sys6(SYS_wait4, gpid, (long)&gstatus, 0, 0, 0, 0);
            if (((gstatus >> 8) & 0xff) != 0) ok = 0;   /* grandchild escaped scope */
            sys3(SYS_exit, ok ? 0 : 1, 0, 0);
        }
        long cstatus = -1;
        sys6(SYS_wait4, cpid, (long)&cstatus, 0, 0, 0, 0);
        int cok = (((cstatus >> 8) & 0xff) == 0);
        /* Belt and braces, from the UNCONFINED parent: neither escape may have
         * left anything behind in /etc. If the child's syscall "failed" but the
         * link exists, the deny was cosmetic. */
        {
            char st[256];
            if (k_stat_at("/etc/ktest_escape",  st, 1) == 0) cok = 0;
            if (k_stat_at("/etc/ktest_escape2", st, 1) == 0) cok = 0;
            /* Positive control: ".." must still RESOLVE for an unconfined
             * process. ext2_walk no longer special-cases it (it clamped ".."
             * to the fs root, which is why the two resolvers disagreed) and
             * instead looks it up as the ordinary directory entry it is. This
             * is the check that the replacement lookup actually works — and
             * note the old clamp was plainly wrong for real paths too:
             * "/a/b/../c" resolved to "/c". */
            if (k_stat_at("/bin/../bin/exectest", st, 0) != 0) cok = 0;
        }
        if (cok) { pass++; out("[KTEST] PASS vfs-confine\n"); }
        else out("[KTEST] FAIL vfs-confine (confinement escapable!)\n");
    }

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

    /* 7b. sigaltstack + SA_ONSTACK. Install an alternate signal stack, register
     *     a SA_ONSTACK handler for SIGUSR2, raise it, and confirm the handler
     *     ran ON the alt stack (a local's address lands inside g_altstack).
     *     Was a no-op stub aliased to rt_sigaction. */
    total++;
    {
        struct kstack ss = { g_altstack, 0, sizeof(g_altstack) };
        struct ksigaction act;
        act.sa_handler  = sig_alt_handler;
        act.sa_flags    = SA_ONSTACK;
        act.sa_restorer = sig_restorer;
        act.sa_mask     = 0;
        g_altsp = 0;
        g_sig_got = 0;
        long r = sys3(SYS_sigaltstack, (long)&ss, 0, 0);
        sys6(SYS_rt_sigaction, SIGUSR2, (long)&act, 0, 8, 0, 0);
        sys3(SYS_kill, sys3(SYS_getpid, 0, 0, 0), SIGUSR2, 0);
        unsigned long lo = (unsigned long)(void *)g_altstack;
        unsigned long hi = lo + sizeof(g_altstack);
        if (r == 0 && g_sig_got == SIGUSR2 && g_altsp >= lo && g_altsp < hi) {
            pass++; out("[KTEST] PASS sigaltstack (handler on alt stack)\n");
        } else out("[KTEST] FAIL sigaltstack\n");
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
        if (pid > 0 && cs == 42) { pass++; out("[KTEST] PASS exec (+procfs cap gate)\n"); }
        else if (cs == 43) out("[KTEST] FAIL svc-tier-DISK_ADMIN-granted (privesc!)\n");
        else if (cs == 44) out("[KTEST] FAIL procfs-unreachable (gate untestable)\n");
        else if (cs == 45) out("[KTEST] FAIL proc-stackshot-ungated (freeze+leak!)\n");
        else out("[KTEST] FAIL exec\n");
    }

    /* 8b. mremap: grow a lazy anon mapping in place (data preserved + new area
     *     usable), then shrink it back. Was absent (ENOSYS). */
    total++;
    {
        long p = sys6(SYS_mmap, 0, 4096, PROT_RW, MAP_ANON_PRIV, -1, 0);
        int ok = (p > 0);
        if (ok) {
            volatile unsigned char *m = (volatile unsigned char *)p;
            m[0] = 0x42; m[4095] = 0x24;
            long p2 = sys6(SYS_mremap, p, 4096, 8192, MREMAP_MAYMOVE, 0, 0);
            if (p2 != p) ok = 0;                       /* grew in place */
            else {
                m[8191] = 0x7;                         /* the new area is usable */
                if (m[0] != 0x42 || m[4095] != 0x24 || m[8191] != 0x7) ok = 0;
                long p3 = sys6(SYS_mremap, p, 8192, 4096, 0, 0, 0);   /* shrink back */
                if (p3 != p || m[0] != 0x42) ok = 0;
            }
        }
        if (ok) { pass++; out("[KTEST] PASS mremap (grow-in-place + shrink)\n"); }
        else out("[KTEST] FAIL mremap\n");
    }

    /* 8c. Audit regressions (2026-07-30 pass): two integer-underflow paths that
     *     were stock-reachable from an unprivileged process.
     *
     *     C1 — readlink(path, buf, 0): the ext2 backend did `tlen = bufsiz - 1`
     *     with bufsiz uint32, underflowing to 0xFFFFFFFF and running a ~4G-byte
     *     copy off both ends of a 256-byte kernel stack buffer. Must be EINVAL.
     *     A bufsiz of exactly 2^32 hit the same bug by narrowing to 0.
     *
     *     H1/H3 — mremap with a huge new_size: unbounded, so `old+new` wrapped
     *     the address space (yielding a VMA overlapping every other mapping →
     *     later double-free) and the grow scan ran billions of unpreemptible
     *     page walks with IF=0. Must be EINVAL, not a wedged core. */
    total++;
    {
        int ok = 1;
        char lbuf[64];

        /* A fast symlink (target <= 60 bytes, stored inline in i_block) — the
         * common on-disk case the underflow was reachable through. The target
         * need not exist; readlink just returns the stored string. */
        if (k_mkdir("/ktrl") == 0 && k_symlink("/tgt45678", "/ktrl/rl") == 0) {
            /* The underflow trigger itself. */
            if (k_readlink("/ktrl/rl", lbuf, 0) >= 0) ok = 0;
            /* Same bug via 32-bit narrowing of the length argument. */
            if (k_readlink("/ktrl/rl", lbuf, 0x100000000UL) == 0) ok = 0;
            /* ...while an ordinary readlink still works. */
            if (k_readlink("/ktrl/rl", lbuf, sizeof(lbuf)) != 9) ok = 0;
            k_unlink("/ktrl/rl");
            k_rmdir("/ktrl");
        } else ok = 0;

        long q = sys6(SYS_mmap, 0, 4096, PROT_RW, MAP_ANON_PRIV, -1, 0);
        if (q > 0) {
            /* Wraps the address space when unchecked. */
            if (sys6(SYS_mremap, q, 4096, -8192L, MREMAP_MAYMOVE, 0, 0) > 0)
                ok = 0;
            /* Huge but non-wrapping: the unpreemptible-scan wedge. If this
             * regresses, the harness times out rather than failing here. */
            if (sys6(SYS_mremap, q, 4096, 0x7FFFFFFFFFFF0000L,
                     MREMAP_MAYMOVE, 0, 0) > 0)
                ok = 0;
            /* The mapping must be untouched and still growable afterwards. */
            if (sys6(SYS_mremap, q, 4096, 8192, MREMAP_MAYMOVE, 0, 0) != q)
                ok = 0;
        } else ok = 0;

        if (ok) { pass++; out("[KTEST] PASS readlink/mremap underflow guards\n"); }
        else out("[KTEST] FAIL readlink/mremap underflow guards\n");
    }

    /* 8d. brk grow/shrink and the heap VMA that tracks it.
     *
     *     Nothing else in this suite touches brk (the test programs are
     *     freestanding, so there is no musl malloc to drive it), yet the audit
     *     fix for M5 changed how brk reserves its range: it now reserves
     *     [brk, new) in the VMA table via vma_insert BEFORE mapping, which is
     *     what makes it atomic against a sibling MAP_FIXED landing mid-grow
     *     (previously that hit vmm_map_user_page's double-map panic). That
     *     reservation also merges into the heap VMA, replacing the by-hand
     *     len fixup the grow path used to do. If the merge ever stopped
     *     happening, the heap would end up described by two entries and the
     *     second grow below would overlap the first — so exercise
     *     grow / write / grow / shrink / regrow and check the data survives. */
    total++;
    {
        int ok = 1;
        long b0 = sys3(SYS_brk, 0, 0, 0);                  /* query */
        if (b0 <= 0) ok = 0;
        else {
            if (sys3(SYS_brk, b0 + 8192, 0, 0) != b0 + 8192) ok = 0;
            if (ok) {
                volatile unsigned char *h = (volatile unsigned char *)b0;
                h[0] = 0xA5; h[8191] = 0x5A;
                /* Second grow must EXTEND the same heap VMA, not overlap it. */
                if (sys3(SYS_brk, b0 + 12288, 0, 0) != b0 + 12288) ok = 0;
                if (h[0] != 0xA5 || h[8191] != 0x5A) ok = 0;  /* data preserved */
                h[12287] = 0x7;                               /* new page usable */
                /* Shrink all the way back, then regrow: the bookkeeping has to
                 * stay consistent across the whole cycle. */
                if (sys3(SYS_brk, b0, 0, 0) != b0) ok = 0;
                if (sys3(SYS_brk, b0 + 4096, 0, 0) != b0 + 4096) ok = 0;
                h[0] = 0x11;                                  /* refaults clean */
                if (h[0] != 0x11) ok = 0;
                if (sys3(SYS_brk, b0, 0, 0) != b0) ok = 0;

                /* The invariant the reservation relies on: the heap is
                 * described by exactly ONE VMA. Grow twice, then count
                 * "[heap]" in /proc/self/maps — if the reservation ever stops
                 * merging into the existing heap entry, the heap gets split
                 * across several entries and the extras go stale (they keep
                 * describing ranges brk has since dropped). Checking the
                 * syscall's return values alone cannot see that. */
                if (sys3(SYS_brk, b0 + 4096, 0, 0) != b0 + 4096) ok = 0;
                if (sys3(SYS_brk, b0 + 8192, 0, 0) != b0 + 8192) ok = 0;
                int mf = (int)sys6(SYS_openat, AT_FDCWD,
                                   (long)"/proc/self/maps", 0, 0, 0, 0);
                if (mf < 0) ok = 0;
                else {
                    char mb[2048];
                    long n = sys3(SYS_read, mf, (long)mb, (long)sizeof(mb) - 1);
                    sys3(SYS_close, mf, 0, 0);
                    if (n <= 0) ok = 0;
                    else {
                        int heaps = 0;
                        for (long q = 0; q + 6 <= n; q++)
                            if (mb[q] == '[' && mb[q+1] == 'h' && mb[q+2] == 'e' &&
                                mb[q+3] == 'a' && mb[q+4] == 'p' && mb[q+5] == ']')
                                heaps++;
                        if (heaps != 1) ok = 0;
                    }
                }
                if (sys3(SYS_brk, b0, 0, 0) != b0) ok = 0;
            }
        }
        if (ok) { pass++; out("[KTEST] PASS brk (grow/shrink + heap VMA)\n"); }
        else out("[KTEST] FAIL brk (grow/shrink + heap VMA)\n");
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

    /* 9. Directory + symlink surface. Every one of these was silently broken
     *    at some point: rmdir under /tmp fell through to ext2 and returned
     *    EPERM; unlink/rmdir resolved THROUGH a final-component symlink; and
     *    on aarch64 the flags of unlinkat/newfstatat were dropped in
     *    translation, so rmdir() unlinked and lstat() followed. A recursive
     *    delete built on those primitives escapes the tree it was given, so
     *    these are correctness AND safety checks. */
    {
        char st[256];
        int ok = 1;

        /* Empty vs non-empty on the ext2 root. */
        ok &= (k_mkdir("/ktdir") == 0);
        ok &= (k_mkdir("/ktdir/sub") == 0);
        ok &= (k_rmdir("/ktdir") < 0);            /* not empty → must refuse */
        ok &= (k_rmdir("/ktdir/sub") == 0);
        total++;
        if (ok) { pass++; out("[KTEST] PASS rmdir (empty vs non-empty)\n"); }
        else out("[KTEST] FAIL rmdir\n");

        /* A symlink is its own object: lstat must not follow it, stat must,
         * and unlink must remove the LINK, leaving the target alone. */
        ok = 1;
        ok &= (k_mkdir("/ktdir/tgt") == 0);
        ok &= (k_symlink("/ktdir/tgt", "/ktdir/lnk") == 0);
        ok &= (k_stat_at("/ktdir/lnk", st, 1) == 0);
        ok &= ((k_stat_mode(st) & K_IFMT) == K_IFLNK);   /* lstat: the link  */
        ok &= (k_stat_at("/ktdir/lnk", st, 0) == 0);
        ok &= ((k_stat_mode(st) & K_IFMT) == K_IFDIR);   /* stat: the target */
        ok &= (k_unlink("/ktdir/lnk") == 0);
        ok &= (k_stat_at("/ktdir/tgt", st, 1) == 0);     /* target survived  */
        ok &= (k_rmdir("/ktdir/tgt") == 0);
        ok &= (k_rmdir("/ktdir") == 0);
        total++;
        if (ok) { pass++; out("[KTEST] PASS symlink (lstat/stat/unlink)\n"); }
        else out("[KTEST] FAIL symlink\n");

        /* /tmp is ramfs, a different backend with its own routing. */
        ok = 1;
        ok &= (k_mkdir("/tmp/ktdir") == 0);
        ok &= (k_mkdir("/tmp/ktdir/sub") == 0);
        ok &= (k_rmdir("/tmp/ktdir") < 0);        /* not empty → must refuse */
        ok &= (k_rmdir("/tmp/ktdir/sub") == 0);
        ok &= (k_rmdir("/tmp/ktdir") == 0);
        total++;
        if (ok) { pass++; out("[KTEST] PASS ramfs mkdir/rmdir (/tmp)\n"); }
        else out("[KTEST] FAIL ramfs mkdir/rmdir\n");
    }

    /* 10. clock_nanosleep honors TIMER_ABSTIME. Read monotonic t0, sleep until
     *     an absolute deadline ~50 ms out, confirm we actually waited, and that a
     *     deadline already in the past returns immediately. Was aliased to
     *     nanosleep(req) discarding clk_id+flags → ABSTIME silently became a
     *     relative sleep of the whole deadline's magnitude. */
    total++;
    {
        /* Run in a fresh child: interruptible sleeps return early on ANY pending
         * signal, and the smp-fork test above leaves a SIGCHLD pending on some
         * arches — a clean child isolates the timing check from that. Child exits
         * 0 iff the absolute-deadline sleep actually waited (~50 ms) AND a past
         * deadline returned immediately. */
        long cp = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (cp == 0) {
            long ts0[2] = {0,0}, ts1[2] = {0,0};
            sys3(SYS_clock_gettime, 1 /*MONOTONIC*/, (long)ts0, 0);
            long tgt[2] = { ts0[0], ts0[1] + 50L*1000000L };   /* +50 ms */
            if (tgt[1] >= 1000000000L) { tgt[0]++; tgt[1] -= 1000000000L; }
            long r  = sys6(SYS_clock_nanosleep, 1, 1 /*TIMER_ABSTIME*/, (long)tgt, 0, 0, 0);
            sys3(SYS_clock_gettime, 1, (long)ts1, 0);
            long elapsed_ms = (ts1[0]-ts0[0])*1000L + (ts1[1]-ts0[1])/1000000L;
            long past[2] = { ts0[0], ts0[1] };                 /* already-past deadline */
            long r2 = sys6(SYS_clock_nanosleep, 1, 1, (long)past, 0, 0, 0);
            sys3(SYS_exit, (r == 0 && r2 == 0 && elapsed_ms >= 30) ? 0 : 1, 0, 0);
        }
        int st = 0;
        sys6(SYS_wait4, cp, (long)&st, 0, 0, 0, 0);
        if (cp > 0 && ((st >> 8) & 0xff) == 0) {
            pass++; out("[KTEST] PASS clock_nanosleep (ABSTIME honored)\n");
        } else out("[KTEST] FAIL clock_nanosleep\n");
    }

    /* 11. tgkill delivers a thread-directed signal (tid==pid in Aegis). Install a
     *     SIGUSR1 handler, tgkill(pid,pid,SIGUSR1), confirm it ran. Was aliased on
     *     arm64 to rt_sigaction — a lying syscall that broke raise()/abort(). */
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
        sys3(SYS_tgkill, mypid, mypid, SIGUSR1);           /* tgid, tid, sig */
        if (g_sig_got == SIGUSR1) { pass++; out("[KTEST] PASS tgkill (thread-directed)\n"); }
        else out("[KTEST] FAIL tgkill\n");
    }

    /* 12. sched_yield returns cleanly (was a no-op nanosleep(0) alias on arm64;
     *     now a real scheduler yield). Single-threaded we assert it returns 0
     *     without hanging. */
    total++;
    {
        if (sys3(SYS_sched_yield, 0, 0, 0) == 0) { pass++; out("[KTEST] PASS sched_yield\n"); }
        else out("[KTEST] FAIL sched_yield\n");
    }

    /* 13. uaccess boundary: a stat-family destination in the KERNEL half must be
     *     refused, not written. emit_stat used to hand its raw arg2 to
     *     copy_to_user with no user_ptr_valid, so stat/fstat/lstat wrote 144
     *     attacker-influenced bytes (st_size is a chosen qword) anywhere in the
     *     kernel — and since the physmap aliases all RAM writable, that was an
     *     arbitrary PHYSICAL write from an unprivileged process. sys_utimensat
     *     had the mirror bug on the read side: 32 bytes copied FROM an
     *     unvalidated pointer into inode timestamps you read back with stat(),
     *     i.e. an arbitrary kernel read oracle.
     *
     *     The address must be one that is actually MAPPED in the kernel half —
     *     an unmapped or non-canonical one returns EFAULT through copy_to_user's
     *     fixup whether or not the range check exists, which would make this
     *     test pass spuriously. The physmap base is mapped, so this is
     *     discriminating on x86-64. (On arm64 it may be unmapped, in which case
     *     the check still passes but proves less.) If the range check is ever
     *     removed, the failure is loud: this writes into low physical memory. */
    total++;
    {
        volatile long kdst = (long)0xFFFF800010000000UL;  /* physmap + 256 MB */
        int ok = 1;

        /* stat() and lstat() into kernel memory → must fail */
        ok &= (k_stat_at("/", (void *)kdst, 0) < 0);
        ok &= (k_stat_at("/", (void *)kdst, 1) < 0);
#ifndef __aarch64__
        /* fstat(fd 1) into kernel memory → must fail. Nothing gates fstat at
         * all (not even an fd capability), so this was the cheapest route to
         * the primitive. x86 only: aarch64 reaches fstat via newfstatat and
         * would need AT_EMPTY_PATH, which this kernel does not implement. */
        ok &= (sys3(5 /*SYS_fstat*/, 1, kdst, 0) < 0);
#endif
        /* A valid destination must still work — this is a range check, not a
         * blanket refusal. Guards against "fixing" it by breaking stat. */
        {
            char st[256];
            ok &= (k_stat_at("/", st, 0) == 0);
        }

        if (ok) { pass++; out("[KTEST] PASS uaccess-stat-dest (kernel ptr refused)\n"); }
        else out("[KTEST] FAIL uaccess-stat-dest (ARBITRARY KERNEL WRITE!)\n");
    }

    /* 14. exit_group must UNWIND a blocked sibling thread, not zombify it where
     *     it stands. A thread parked in a pipe read owns a waitq_entry_t on its
     *     KERNEL stack, linked into that pipe's read_waiters. The old
     *     sys_exit_group flipped siblings to TASK_ZOMBIE + dequeued them
     *     without waking them, so the entry stayed linked; waitpid then
     *     kva_free_pages'd the stack, and the next waitq_wake_all on that pipe
     *     walked freed memory and handed sched_wake() whatever had been
     *     reissued there — a run-list splice into an attacker-shaped task whose
     *     ->sp ctx_switch loads. Ring 0, from baseline caps only
     *     (THREAD_CREATE is baseline).
     *
     *     Shape: child clones a thread that blocks reading an empty pipe, then
     *     exit_group()s. We reap it and then WRITE to that pipe, which is what
     *     walks read_waiters. Three things are asserted: the reap completes at
     *     all (a leader is not reapable while a sibling is non-zombie, so a
     *     teardown that fails to kill the sibling HANGS here), the status is
     *     the one exit_group passed, and the post-reap pipe traffic survives.
     *
     *     This is a "does not corrupt" test, so a regression shows up as a
     *     panic/hang rather than a clean FAIL — which is exactly what the old
     *     behaviour deserved. */
    total++;
    {
        int  ok = 1;
        int  pfd[2] = { -1, -1 };   /* pipe2 writes two ints, not two longs */
        if (sys3(SYS_pipe2, (long)pfd, 0, 0) != 0) ok = 0;
        if (ok) {
            g_tg_rfd = pfd[0];
            long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
            if (pid == 0) {
                /* ---- child (group leader) ---- */
                long stk = sys6(SYS_mmap, 0, 65536, PROT_RW, MAP_ANON_PRIV, -1, 0);
                if (stk > 0) {
                    /* CLONE_VM|FS|FILES|SIGHAND|THREAD == a real thread: shares
                     * our address space AND our tgid, which is what makes it a
                     * sibling exit_group has to tear down. Stack grows down, so
                     * hand clone the TOP, 16-aligned — but leave a page of slack
                     * BELOW the exact end. A cloned child resumes in the middle
                     * of _start, which still has a live frame and addresses its
                     * locals as POSITIVE offsets from rsp (it opens
                     * `sub $0x890,%rsp`). Handed the exact end, the first such
                     * access lands past the mapping, where there is no VMA to
                     * fault against, and the thread takes a SIGSEGV that has
                     * nothing to do with what it was written to test. */
                    long top = (stk + 65536 - 4096) & ~15L;
                    long t = sys6(SYS_clone, 0x100 | 0x200 | 0x400 | 0x800 | 0x10000,
                                  top, 0, 0, 0, 0);
                    if (t == 0) {
                        /* ---- sibling thread, on the fresh stack ---- */
                        char b;
                        for (;;)
                            sys3(SYS_read, g_tg_rfd, (long)&b, 1);  /* parks */
                    }
                }
                /* Let the sibling reach the blocking read before we exit. */
                struct { long s, ns; } ts = { 0, 150000000L };  /* 150 ms */
                sys6(SYS_clock_nanosleep, 0, 0, (long)&ts, 0, 0, 0);
                sys3(SYS_exit_group, 77, 0, 0);
                sys3(SYS_exit, 98, 0, 0);   /* unreachable */
            }
            int status = 0;
            long w = sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
            if (w != pid || ((status >> 8) & 0xff) != 77) ok = 0;
            /* Drain any reparented sibling zombie so it does not leak into the
             * later cases (exit_group reparents orphans to init == us). */
            { int st2 = 0; while (sys6(SYS_wait4, -1, (long)&st2, 1 /*WNOHANG*/,
                                       0, 0, 0) > 0) { } }
            /* THE PROBE: this walks the pipe's read_waiters. If the dead
             * thread's entry is still linked, it points at a freed kernel
             * stack. */
            if (sys3(SYS_write, pfd[1], (long)"x", 1) != 1) ok = 0;
            { char b = 0;
              if (sys3(SYS_read, pfd[0], (long)&b, 1) != 1 || b != 'x') ok = 0; }
            sys3(SYS_close, pfd[0], 0, 0);
            sys3(SYS_close, pfd[1], 0, 0);
        }
        if (ok) { pass++; out("[KTEST] PASS exit_group-blocked-sibling (unwound)\n"); }
        else out("[KTEST] FAIL exit_group-blocked-sibling\n");
    }

    /* 15. exit_group called by a NON-LEADER thread must still wake the parent
     *     blocked in wait4. Case 14 has the leader call exit_group, so the
     *     leader zombifies LAST (thread_group_teardown does not return until
     *     every sibling is a zombie) and the waiting parent always sees a
     *     complete group on its first look. Invert that and the wedge appears:
     *
     *       - the thread calls exit_group, so the LEADER is SIGKILLed by the
     *         teardown like any other sibling and zombifies FIRST;
     *       - the leader's SIGCHLD wakes us, but sys_waitpid refuses to reap a
     *         leader while a sibling is still live (it would free the shared
     *         PML4), so we skip it and block again;
     *       - the sibling then zombifies and notifies ITS ppid — which
     *         sys_clone set to the thread's creator, another thread of the same
     *         dying group, never us.
     *
     *     Nothing else reports the group is complete, so the parent sleeps
     *     forever. On a real system that parent is the shell, and the console
     *     goes silent with the kernel otherwise healthy.
     *
     *     Ordering is deterministic, not racy: the teardown waits for the
     *     leader to reach TASK_ZOMBIE before the thread that called exit_group
     *     runs its own. Like case 14 this is a liveness test, so a regression
     *     shows up as the harness timing out here rather than a clean FAIL. */
    total++;
    {
        int ok = 1;
        int pfd[2] = { -1, -1 };
        if (sys3(SYS_pipe2, (long)pfd, 0, 0) != 0) ok = 0;
        if (ok) {
            long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
            if (pid == 0) {
                /* ---- child: the group LEADER ---- */
                long stk = sys6(SYS_mmap, 0, 65536, PROT_RW, MAP_ANON_PRIV, -1, 0);
                if (stk > 0) {
                    /* Slack below the exact end — see case 14 for the hazard. */
                    long top = (stk + 65536 - 4096) & ~15L;
                    long t = sys6(SYS_clone, 0x100 | 0x200 | 0x400 | 0x800 | 0x10000,
                                  top, 0, 0, 0, 0);
                    if (t == 0) {
                        /* ---- sibling thread, on the fresh stack ----
                         * Straight into exit_group: no locals, no delay. It
                         * does not matter whether the leader has reached its
                         * read() yet, because thread_group_teardown does not
                         * return until every sibling is a zombie — so the
                         * leader zombifies before this thread does either way,
                         * which is the whole point of the case. */
                        sys3(SYS_exit_group, 88, 0, 0);
                    }
                }
                /* Park the leader so the teardown has to kill it where it
                 * blocks — the shape a shell's child is in when this bites. */
                { char b; for (;;) sys3(SYS_read, pfd[0], (long)&b, 1); }
            }
            /* THE PROBE: a BLOCKING wait4. WNOHANG would poll its own way out
             * of the bug and prove nothing — the defect is precisely that the
             * blocked parent is never woken again. */
            int status = 0;
            long w = sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
            if (w != pid) ok = 0;
            { int st2 = 0; while (sys6(SYS_wait4, -1, (long)&st2, 1 /*WNOHANG*/,
                                       0, 0, 0) > 0) { } }
            sys3(SYS_close, pfd[0], 0, 0);
            sys3(SYS_close, pfd[1], 0, 0);
        }
        if (ok) { pass++; out("[KTEST] PASS exit_group-from-thread (parent woken)\n"); }
        else out("[KTEST] FAIL exit_group-from-thread\n");
    }

    /* 16. Reaping a group leader must also free its thread zombies. A thread is
     *     waitable by nobody — sys_clone sets ppid to the CREATING thread, so a
     *     sibling's ppid names another thread of the same group and no waitpid
     *     can ever match it. They used to stay in the task list for the rest of
     *     the boot, each holding a PCB, a kernel stack and one of the 256
     *     process slots.
     *
     *     Asserting on "fork eventually fails" does NOT discriminate, which is
     *     worth recording because it is the obvious test to write. Leaked slots
     *     plateau just below the ceiling: once the count is high enough that the
     *     child's thread clones fail, the iteration stops leaking, the leader is
     *     still reaped for -1, and the parent's fork keeps succeeding forever. A
     *     test built on it passes on the broken kernel.
     *
     *     So assert what the leak actually destroys: the ability to CREATE
     *     threads. Each child reports whether all three of its clones succeeded,
     *     and one failure fails the case. At three leaked slots per iteration
     *     that ceiling is reached around iteration 83, so 100 iterations clear
     *     it with margin while staying well inside the harness timeout. */
    total++;
    {
        int ok = 1;
        for (int i = 0; i < 100 && ok; i++) {
            long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
            if (pid < 0) { ok = 0; break; }
            if (pid == 0) {
                /* ---- child: the group leader ---- */
                int failed = 0;
                for (int j = 0; j < 3; j++) {
                    long stk = sys6(SYS_mmap, 0, 16384, PROT_RW, MAP_ANON_PRIV,
                                    -1, 0);
                    if (stk <= 0) { failed = 1; break; }
                    /* Hand clone a stack pointer with slack ABOVE it. The child
                     * resumes inside _start, whose locals gcc addresses at
                     * POSITIVE offsets from rsp (it opens `sub $0x890,%rsp`), so
                     * an exact-end pointer puts the first spill just past the
                     * mapping — a SIGSEGV with no VMA to fault against, which is
                     * the kernel behaving correctly. Cases 14 and 15 get away
                     * with the exact end only because their thread bodies happen
                     * to compile to no stack access at all. */
                    long top = (stk + 16384 - 4096) & ~15L;
                    long t = sys6(SYS_clone,
                                  0x100 | 0x200 | 0x400 | 0x800 | 0x10000,
                                  top, 0, 0, 0, 0);
                    if (t < 0) { failed = 1; break; }
                    if (t == 0)
                        for (;;) sys3(SYS_sched_yield, 0, 0, 0);
                }
                sys3(SYS_exit_group, failed, 0, 0);
            }
            int st = 0;
            if (sys6(SYS_wait4, pid, (long)&st, 0, 0, 0, 0) != pid) { ok = 0; break; }
            /* Non-zero == the child could not create its threads, i.e. the slots
             * from earlier iterations were never returned. */
            if (((st >> 8) & 0xff) != 0) { ok = 0; break; }
        }
        if (ok) { pass++; out("[KTEST] PASS thread-zombie reap (slots returned)\n"); }
        else out("[KTEST] FAIL thread-zombie reap\n");
    }

    if (pass == total) out("[KTEST] DONE all-pass\n");
    else                out("[KTEST] DONE FAIL\n");

    sys3(SYS_exit, 0, 0, 0);
    for (;;) { }
}
