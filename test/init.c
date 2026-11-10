/* Aegis kernel test-init — a freestanding test program the kernel boots as init
 * (pid 1) from a minimal test rootfs. NO libc, NO userland dependency: raw
 * `syscall` instructions only, built with the kernel's own x86_64-elf toolchain.
 *
 * It proves the kernel boots a user process end-to-end AND that the capability
 * model holds at the syscall boundary: a privileged syscall (sethostname, gated
 * on CAP_KIND_POWER) succeeds with its explicit bootstrap grant, while raw
 * disk access is denied —
 * the no-ambient-authority guarantee, even for pid 1. Results go to fd 1/2
 * (the kernel pre-opens both to /dev/console → serial). Harness greps the
 * "[KTEST] DONE all-pass" line.
 */

#include "../kernel/cap/cap.h"

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
#define SYS_vfs_confine  518   /* reserved; unsafe lexical version retired */
#define SYS_cap_rights_limit 520
#define SYS_cap_query    362
#define SYS_admin_session 517
#define SYS_admin_session_active 519
#define SYS_admin_self   AEGIS_SYS_ADMIN_SELF

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
#define SYS_mprotect     226
#define SYS_munmap       215
#define SYS_set_tid_address 96
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
#define SYS_ppoll        73    /* aarch64 has no poll(2); dispatch maps 73→271 */
#define SYS_getdents64   61
#define SYS_read         63
#define SYS_exit_group   94
#define SYS_recvfrom     207
#define SYS_getrandom    278
#define SYS_inotify_init1 26
#define SYS_inotify_add_watch 27
#define SYS_inotify_rm_watch 28
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
#define SYS_mprotect     10
#define SYS_munmap       11
#define SYS_set_tid_address 218
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
#define SYS_ppoll        271
#define SYS_getdents64   217
#define SYS_read         0
#define SYS_exit_group   231
#define SYS_recvfrom     45
#define SYS_getrandom    318
#define SYS_inotify_init1 294
#define SYS_inotify_add_watch 254
#define SYS_inotify_rm_watch 255
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
/* st_blocks is at byte 64 in both supported userspace stat layouts. */
static long k_stat_blocks(const void *st)
{
    return *(const long *)((const char *)st + 64);
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

/* Linux clone places TLS before child-TID on arm64, after it on x86. */
static long k_clone(long flags, long stack, long ptid, long ctid, long tls)
{
#ifdef __aarch64__
    return sys6(SYS_clone, flags, stack, ptid, tls, ctid, 0);
#else
    return sys6(SYS_clone, flags, stack, ptid, ctid, tls, 0);
#endif
}

static volatile int g_vm_control;

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void out(const char *s) { sys3(SYS_write, 2, (long)s, slen(s)); }

static int empty_child_authority(void)
{
    cap_slot_t caps[CAP_TABLE_SIZE];
    for (int attempt = 0; attempt < 3; attempt++) {
        if (sys3(SYS_cap_query, 0, (long)caps, sizeof(caps)) != CAP_TABLE_SIZE)
            return 0;
        for (unsigned i = 0; i < CAP_TABLE_SIZE; i++)
            if (caps[i].kind || caps[i].rights) return 0;
        if (sys3(SYS_write, 2, (long)"!", 1) != -1 ||
            sys6(SYS_openat, AT_FDCWD, (long)"/proc/uptime", 0, 0, 0, 0) != -1 ||
            sys3(SYS_sethostname, (long)"forbidden", 9, 0) != -1)
            return 0;
        /* Repeated no-op drops cannot refresh policy or bootstrap grants. */
        if (sys3(SYS_admin_session, 0, 0, 0) != 0) return 0;
    }
    return 1;
}

/* Both bootstrap init and its empty fork child lack ADMIN_AUTH. SELF must
 * reject them, and undefined legacy selectors must fail as EINVAL rather
 * than being interpreted as parent elevation. Check each call's cap/flag
 * nonpublication, not just its errno. These Aegis numbers are arch-shared. */
static int denied_admin_issuance(void)
{
    cap_slot_t before[CAP_TABLE_SIZE], after[CAP_TABLE_SIZE];
    if (sys3(SYS_cap_query, 0, (long)before, sizeof(before)) != CAP_TABLE_SIZE ||
        sys3(SYS_admin_session_active, 0, 0, 0) != 0)
        return 0;
    for (unsigned i = 0; i < CAP_TABLE_SIZE; i++)
        if (before[i].kind == CAP_KIND_ADMIN_AUTH) return 0;
    const long invalid[] = { 2, 3, -1L, 1L << 32, (1L << 32) | 1, (1L << 32) | 2 };
    for (unsigned call = 0; call <= sizeof(invalid) / sizeof(invalid[0]); call++) {
        long ret = call == 0 ? sys3(SYS_admin_self, 0, 0, 0)
                            : sys3(SYS_admin_session, invalid[call - 1], 0, 0);
        if (ret != (call == 0 ? -1 /* EPERM */ : -22 /* EINVAL */) ||
            sys3(SYS_cap_query, 0, (long)after, sizeof(after)) != CAP_TABLE_SIZE ||
            sys3(SYS_admin_session_active, 0, 0, 0) != 0)
            return 0;
        for (unsigned i = 0; i < CAP_TABLE_SIZE; i++)
            if (before[i].kind != after[i].kind || before[i].rights != after[i].rights)
                return 0;
    }
    return 1;
}

/* Signal handling: a handler + a restorer trampoline. On return, the handler
 * branches to the restorer (x30/pretcode), which calls rt_sigreturn to
 * restore the interrupted context. */
static volatile int g_sig_got = 0;
static void sig_handler(int signum) { g_sig_got = signum; }

/* Globals for the exit_group teardown case (14). The cloned THREAD lands on a
 * fresh stack, so it must not read anything off its creator's frame — every
 * value it needs lives here. */
static volatile long g_tg_rfd = -1;
static volatile int g_lifecycle_mode;
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

/* The self-exec lifecycle modes below need fresh baseline policy, not inherited
 * fork authority. Keep the fd in argv: pre-exec formatting needs no caps. */
static void exec_lifecycle(int mode, int fd)
{
    char m[] = { (char)('0' + mode), 0 };
    char f[12];
    unsigned v = (unsigned)fd, n = 0;
    do { f[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    for (unsigned i = 0; i < n / 2; i++) {
        char c = f[i]; f[i] = f[n - i - 1]; f[n - i - 1] = c;
    }
    f[n] = 0;
    char *argv[] = { (char *)"/bin/vigil", (char *)"lifecycle", m, f, 0 };
    char *envp[] = { 0 };
    sys3(SYS_execve, (long)argv[0], (long)argv, (long)envp);
    sys3(SYS_exit, 99, 0, 0);
    for (;;) { }
}

/* Runs only after exec has independently issued THREAD_CREATE and VFS_READ.
 * New-stack thread bodies use globals, never the creator's local frame. */
static void lifecycle_child(int mode, int fd)
{
    g_tg_rfd = fd;
    g_lifecycle_mode = mode;
    int count = mode == 3 ? 3 : 1;
    for (int j = 0; j < count; j++) {
        long stk = sys6(SYS_mmap, 0, 65536, PROT_RW, MAP_ANON_PRIV, -1, 0);
        if (stk <= 0) { sys3(SYS_exit_group, 98, 0, 0); for (;;) { } }
        long t = k_clone(0x100 | 0x200 | 0x400 | 0x800 | 0x10000,
                         (stk + 65536 - 4096) & ~15L, 0, 0, 0);
        if (t < 0) { sys3(SYS_exit_group, 98, 0, 0); for (;;) { } }
        if (t == 0) {
            if (g_lifecycle_mode == 2) sys3(SYS_exit_group, 88, 0, 0);
            for (;;) {
                char b;
                if (g_lifecycle_mode == 1) {
                    if (sys3(SYS_read, g_tg_rfd, (long)&b, 1) < 0)
                        sys3(SYS_exit_group, 98, 0, 0);
                }
                else sys3(SYS_sched_yield, 0, 0, 0);
            }
        }
    }
    if (mode == 2) {
        char b;
        for (;;) sys3(SYS_read, g_tg_rfd, (long)&b, 1);
    }
    if (mode == 1) {
        long ts[2] = { 0, 150000000L };
        sys6(SYS_clock_nanosleep, 0, 0, (long)ts, 0, 0, 0);
    }
    sys3(SYS_exit_group, mode == 1 ? 77 : 0, 0, 0);
    for (;;) { }
}

/* Capture argv before a C prologue changes the initial ABI stack. */
#ifdef __aarch64__
__asm__(".global _start\n_start:\nmov x0, sp\nbl test_main\n1: b 1b\n");
#else
__asm__(".global _start\n_start:\nmov %rsp, %rdi\nand $-16, %rsp\ncall test_main\n1: jmp 1b\n");
#endif

__attribute__((used)) static void test_main(const unsigned long *stack)
{
    if (stack[0] == 4) {
        const char *arg = (const char *)stack[2];
        const char *m = (const char *)stack[3], *f = (const char *)stack[4];
        if (arg[0] == 'l' && m[0] >= '1' && m[0] <= '3' && !m[1]) {
            int fd = 0;
            for (unsigned i = 0; i < 10 && f[i]; i++) {
                if (f[i] < '0' || f[i] > '9' || fd > 1000000)
                    sys3(SYS_exit, 98, 0, 0);
                fd = fd * 10 + f[i] - '0';
            }
            lifecycle_child(m[0] - '0', fd);
        }
    }
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

    total++;
    {
        char random[16];
        long got = sys3(SYS_getrandom, (long)random, sizeof(random), 0);
        long bad = sys3(SYS_getrandom, (long)random, sizeof(random), 0x80000000);
        if (got == (long)sizeof(random) && bad == -22) {
            pass++; out("[KTEST] PASS getrandom ready + flags validated\n");
        } else out("[KTEST] FAIL getrandom\n");
    }

    /* Unsupported compatibility surfaces must fail explicitly: a successful
     * inert inotify fd hangs watchers forever, while ignoring MSG_PEEK consumes
     * data the caller asked to leave queued. */
    total++;
    {
        char byte;
        long ino = sys3(SYS_inotify_init1, 0, 0, 0);
        long add = sys3(SYS_inotify_add_watch, -1, 0, 0);
        long rm = sys3(SYS_inotify_rm_watch, -1, -1, 0);
        long peek = sys6(SYS_recvfrom, -1, (long)&byte, 1, 0x2, 0, 0);
        long waitall = sys6(SYS_recvfrom, -1, (long)&byte, 1, 0x100, 0, 0);
        if (ino == -38 && add == -38 && rm == -38 &&
            peek == -95 && waitall == -95) {
            pass++; out("[KTEST] PASS unsupported syscall semantics fail honestly\n");
        } else out("[KTEST] FAIL unsupported syscall semantics accepted\n");
    }

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

    /* 4c. The old process-wide path scope followed in-scope symlinks outside
     * its root. It is retired until every operation uses the inode-rooted dirfd
     * resolver; fake confinement is worse than an explicit refusal. */
    total++;
    if (sys3(SYS_vfs_confine, (long)"/tmp", 0, 0) == -95)
        { pass++; out("[KTEST] PASS unsafe vfs-confine retired\n"); }
    else out("[KTEST] FAIL unsafe vfs-confine still active\n");

    total++;
    {
        cap_slot_t before[CAP_TABLE_SIZE], after[CAP_TABLE_SIZE];
        long before_count = sys3(SYS_cap_query, 0, (long)before, sizeof(before));
        int ok = before_count == CAP_TABLE_SIZE && denied_admin_issuance();
        long pid = k_clone(SIGCHLD, 0, 0, 0, 0);
        if (pid == 0) sys3(SYS_exit, denied_admin_issuance() ? 0 : 98, 0, 0);
        int status = 0;
        ok &= pid > 0 && sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) == pid &&
              status == 0;
        /* The child's invalid selectors must not elevate its direct parent,
         * either through cap publication or the separate admin-session flag. */
        long after_count = sys3(SYS_cap_query, 0, (long)after, sizeof(after));
        ok &= sys3(SYS_admin_session_active, 0, 0, 0) == 0;
        if (before_count == CAP_TABLE_SIZE && after_count == CAP_TABLE_SIZE) {
            for (unsigned i = 0; i < CAP_TABLE_SIZE; i++)
                ok &= before[i].kind == after[i].kind && before[i].rights == after[i].rights;
        } else ok = 0;
        if (ok) { pass++; out("[KTEST] PASS admin SELF denied + invalid legacy selectors preserve caller/parent authority\n"); }
        else out("[KTEST] FAIL admin issuance denial or authority changed\n");
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

    total++;
    {
        long pid = k_clone(SIGCHLD, 0, 0, 0, 0);
        if (pid == 0) sys3(SYS_exit, empty_child_authority() ? 0 : 98, 0, 0);
        int st = 0;
        if (pid > 0 && sys6(SYS_wait4, pid, (long)&st, 0, 0, 0, 0) == pid && st == 0) {
            pass++; out("[KTEST] PASS independent child empty and admin-drop cannot regrant\n");
        } else out("[KTEST] FAIL independent child authority\n");
    }

    /* mprotect must preserve private fork isolation across a read-only
     * source mapping, including PROT_NONE save/restore. Revoking WRITE on a
     * COW mapping must also revoke the fault handler's permission to write. */
    total++;
    {
        int ok = 1;
        long page = sys6(SYS_mmap, 0, 4096, PROT_RW, MAP_ANON_PRIV, -1, 0);
        if (page <= 0) ok = 0;
        for (int mode = 0; mode < 3 && ok; mode++) {
            sys3(SYS_mprotect, page, 4096, PROT_RW);
            *(volatile unsigned *)page = 0x1234;
            if (mode < 2) ok &= sys3(SYS_mprotect, page, 4096, 1) == 0;
            long pid = k_clone(SIGCHLD, 0, 0, 0, 0);
            if (pid == 0) {
                if (mode == 1 && sys3(SYS_mprotect, page, 4096, 0) != 0)
                    sys3(SYS_exit, 98, 0, 0);
                if (sys3(SYS_mprotect, page, 4096, mode == 2 ? 1 : PROT_RW) != 0)
                    sys3(SYS_exit, 98, 0, 0);
                *(volatile unsigned *)page = 0x5678;
                sys3(SYS_exit, 7, 0, 0);
            }
            int st = 0;
            if (pid <= 0 || sys6(SYS_wait4, pid, (long)&st, 0, 0, 0, 0) != pid)
                ok = 0;
            else if (mode == 2) ok &= (st & 0x7f) == 11; /* SIGSEGV */
            else ok &= st == (7 << 8);
            ok &= *(volatile unsigned *)page == 0x1234;
        }
        if (page > 0) sys3(SYS_munmap, page, 4096, 0);
        if (ok) { pass++; out("[KTEST] PASS mprotect COW isolation and write revocation\n"); }
        else out("[KTEST] FAIL mprotect COW isolation or revocation\n");
    }

    /* Exit clear_child_tid must neither bypass read-only permission nor
     * modify another process's still-shared private frame. */
    total++;
    {
        int ok = 1;
        long page = sys6(SYS_mmap, 0, 4096, PROT_RW, MAP_ANON_PRIV, -1, 0);
        if (page <= 0) ok = 0;
        if (ok) {
            *(volatile unsigned *)page = 0x7654;
            ok &= sys3(SYS_mprotect, page, 4096, 1) == 0;
            long pid = k_clone(SIGCHLD, 0, 0, 0, 0);
            if (pid == 0) {
                long tid = sys3(SYS_set_tid_address, page, 0, 0);
                sys3(SYS_exit, tid > 0 ? 0 : 98, 0, 0);
            }
            int st = 0;
            ok &= pid > 0 && sys6(SYS_wait4, pid, (long)&st, 0, 0, 0, 0) == pid && st == 0;
            ok &= *(volatile unsigned *)page == 0x7654;
            sys3(SYS_munmap, page, 4096, 0);
        }
        if (ok) { pass++; out("[KTEST] PASS clear-tid respects readonly COW\n"); }
        else out("[KTEST] FAIL clear-tid readonly COW\n");
    }

    total++;
    {
        int ok = 1;
        const char *path = "/tmp/.kt-mmap-access";
        long fd = sys6(SYS_openat, AT_FDCWD, (long)path, 0x242, 0600, 0, 0);
        if (fd < 0) ok = 0;
        if (fd >= 0) { ok &= sys3(SYS_write, fd, (long)"mmap", 4) == 4; sys3(SYS_close, fd, 0, 0); }
        fd = sys6(SYS_openat, AT_FDCWD, (long)path, 1, 0, 0, 0);
        ok &= fd >= 0 && sys6(SYS_mmap, 0, 4096, 1, 2, fd, 0) == -13;
        if (fd >= 0) sys3(SYS_close, fd, 0, 0);
        fd = sys6(SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
        ok &= fd >= 0 && sys6(SYS_mmap, 0, 4096, PROT_RW, 1, fd, 0) == -13;
        long page = fd >= 0 ? sys6(SYS_mmap, 0, 4096, 1, 1, fd, 0) : -1;
        ok &= page > 0;
        if (page > 0) { ok &= *(volatile char *)page == 'm'; sys3(SYS_munmap, page, 4096, 0); }
        if (fd >= 0) sys3(SYS_close, fd, 0, 0);
        k_unlink(path);
        if (ok) { pass++; out("[KTEST] PASS mmap fd read/write authority\n"); }
        else out("[KTEST] FAIL mmap fd authority\n");
    }

    total++;
    {
#ifdef __aarch64__
        const long bad = 0x0001000000000000L;
#else
        const long bad = 0x0000800000000000L;
#endif
        const long thread = 0x100 | 0x800 | 0x10000;
        int ok = k_clone(0x100 | SIGCHLD, 0, 0, 0, 0) == -22;
        ok &= k_clone(thread | 0x80000, 0, 0, 0, bad) == -14;
        ok &= k_clone(SIGCHLD | 0x80000, 0, 0, 0, bad) == -14;
        ok &= k_clone(thread | 0x200000, 0, 0, bad - 2, 0) == -14;
        ok &= k_clone(thread | 0x100000, 0, bad - 2, 0, 0) == -14;
        ok &= k_clone(thread, bad, 0, 0, 0) == -14;
        ok &= k_clone(SIGCHLD, bad, 0, 0, 0) == -14;
        ok &= k_clone((1L << 40) | SIGCHLD, 0, 0, 0, 0) == -22;
#ifndef __aarch64__
        ok &= sys3(158 /* arch_prctl */, 0x1002 /* ARCH_SET_FS */, bad, 0) == -14;
#endif
        long page = sys6(SYS_mmap, 0, 4096, PROT_RW, MAP_ANON_PRIV, -1, 0);
        long stk = sys6(SYS_mmap, 0, 65536, PROT_RW, MAP_ANON_PRIV, -1, 0);
        if (page <= 0 || stk <= 0) ok = 0;
        if (page > 0 && stk > 0) {
            *(volatile unsigned *)page = 0x9876;
            sys3(SYS_mprotect, page, 4096, 1);
            ok &= k_clone(thread | 0x100000, stk + 32768, page, 0, 0) == -14;
            ok &= k_clone(thread | 0x1000000, stk + 32768, 0, page, 0) == -14;
            ok &= *(volatile unsigned *)page == 0x9876;
        }
        if (page > 0) sys3(SYS_munmap, page, 4096, 0);
        if (stk > 0) sys3(SYS_munmap, stk, 65536, 0);
        if (ok) { pass++; out("[KTEST] PASS clone VM TLS stack and TID boundaries\n"); }
        else out("[KTEST] FAIL clone VM TLS stack or TID boundaries\n");
    }

    /* Positive vfork control: the suspended parent observes a shared write
     * only after the child exits. Existing thread tests below cover THREAD. */
    total++;
    {
        int ok = 1;
        long stk = sys6(SYS_mmap, 0, 65536, PROT_RW, MAP_ANON_PRIV, -1, 0);
        if (stk <= 0) ok = 0;
        if (ok) {
            g_vm_control = 0;
            long pid = k_clone(0x100 | 0x4000 | SIGCHLD, stk + 32768, 0, 0, 0);
            if (pid == 0) {
                g_vm_control = empty_child_authority() ? 1 : -1;
                sys3(SYS_exit, g_vm_control == 1 ? 0 : 98, 0, 0);
            }
            int st = 0;
            ok &= pid > 0 && g_vm_control == 1;
            ok &= pid > 0 && sys6(SYS_wait4, pid, (long)&st, 0, 0, 0, 0) == pid && st == 0;
            sys3(SYS_munmap, stk, 65536, 0);
        }
        if (ok) { pass++; out("[KTEST] PASS vfork shared VM control and empty authority\n"); }
        else out("[KTEST] FAIL vfork shared VM control\n");
    }

#ifndef __aarch64__
    total++;
    {
        unsigned long flags;
        /* Timer interrupts occur while user DF is set. The kernel must clear
         * its own DF before C, while preserving the interrupted user's flag. */
        __asm__ volatile("std; mov $50000000, %%ecx; 1: dec %%ecx; jnz 1b; pushfq; pop %0; cld"
                         : "=r"(flags) : : "rcx", "cc", "memory");
        if (flags & (1UL << 10)) { pass++; out("[KTEST] PASS interrupt user DF preserved\n"); }
        else out("[KTEST] FAIL interrupt user DF\n");
    }
#endif

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
        if (pid > 0 && status == (42 << 8)) { pass++; out("[KTEST] PASS exec (+procfs cap gate)\n"); }
        else if (cs == 43) out("[KTEST] FAIL svc-tier-DISK_ADMIN-granted (privesc!)\n");
        else if (cs == 44) out("[KTEST] FAIL procfs-unreachable (gate untestable)\n");
        else if (cs == 45) out("[KTEST] FAIL proc-stackshot-ungated (freeze+leak!)\n");
        else if (cs == 47) out("[KTEST] FAIL exec AT_SECURE\n");
        else if (cs == 48) out("[KTEST] FAIL exec fresh-policy cap table\n");
        else if (cs >= 49 && cs <= 51) out("[KTEST] FAIL spawn/exec authority regression\n");
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

    /* 8b'. mmap page-work ceiling: an absurd length must be REFUSED, not walked.
     *      sys_mmap scans the requested range a page at a time to pick a gap,
     *      with IF=0 — so a multi-TiB anonymous request was ~10^9 uninterruptible
     *      page-table walks, wedging the core from an unprivileged process. The
     *      other range syscalls already enforced MM_MAX_RANGE_PAGES (4 GiB); mmap
     *      did not. If this test HANGS rather than fails, the guard is gone. */
    total++;
    {
        long huge = sys6(SYS_mmap, 0, 0x100000000000L /* 16 TiB */,
                         PROT_RW, MAP_ANON_PRIV, -1, 0);
        /* Kernel returns -errno; a "success" here would be a bogus mapping. */
        if (huge < 0) { pass++; out("[KTEST] PASS mmap ceiling (huge len refused)\n"); }
        else out("[KTEST] FAIL mmap-huge-len-not-refused\n");
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

        /* Keep a guard before the test page so mmap cannot merge it into a
         * neighbor's VMA; reserve then free its growth page explicitly. */
        long reserve = sys6(SYS_mmap, 0, 12288, 0, MAP_ANON_PRIV, -1, 0);
        long q = reserve > 0 ? reserve + 4096 : -1;
        if (q > 0 && sys3(SYS_mprotect, q, 4096, PROT_RW) == 0 &&
            sys3(SYS_munmap, q + 4096, 4096, 0) == 0) {
            *(volatile unsigned *)q = 0x13579;
            /* Wraps the address space when unchecked. */
            if (sys6(SYS_mremap, q, 4096, -8192L, MREMAP_MAYMOVE, 0, 0) > 0)
                ok = 0;
            /* Huge but non-wrapping: the unpreemptible-scan wedge. */
            if (sys6(SYS_mremap, q, 4096, 0x7FFFFFFFFFFF0000L,
                     MREMAP_MAYMOVE, 0, 0) > 0)
                ok = 0;
            if (*(volatile unsigned *)q != 0x13579 ||
                sys6(SYS_mremap, q, 4096, 8192, MREMAP_MAYMOVE, 0, 0) != q ||
                *(volatile unsigned *)q != 0x13579)
                ok = 0;
        } else ok = 0;
        if (reserve > 0) sys3(SYS_munmap, reserve, 12288, 0);

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

    /* 8e. poll/select/epoll must hold a REFERENCE on each polled object for as
     *     long as their (stack-allocated) waitq entry is linked into that
     *     object's queue — see kernel/syscall/fd_waitq.h.
     *
     *     The pin calls ops->dup on register and ops->close on unregister, so an
     *     UNBALANCED pair corrupts the refcount: too many closes frees the pipe
     *     early (the very UAF the pin prevents), too few leaks it. Either
     *     bankrupts the pipe pool within a few dozen cycles.
     *
     *     A NON-ZERO timeout is essential: sys_poll returns at
     *     `if (ready > 0 || timeout_ms == 0)` BEFORE the registration block, so a
     *     zero-timeout poll never reaches the pinned path at all. Poll a pipe
     *     with nothing to read so the call actually blocks and registers.
     *
     *     Honest scope: proves the refcounting is balanced and the path runs. It
     *     does NOT reproduce the cross-thread free — that needs a CLONE_FILES
     *     sibling closing mid-block, and the resulting UAF is silent without
     *     heap poisoning (KASAN's shadow covers the kernel image, not kva). */
    total++;
    {
        int ok = 1, step = 0;
        struct { int fd; short events; short revents; } pfds[2];
        struct { long tv_sec; long tv_nsec; } ts = { 0, 20000000L };  /* 20 ms */

        for (int iter = 0; iter < 40 && ok; iter++) {
            /* pipe2 writes int fd[2] — NOT long[2]. Declaring it long packs
             * both fds into pf[0] and leaves pf[1] as stack garbage, which
             * polls as POLLNVAL: nonzero (so it counts as "ready") but not the
             * event asked for. That cost me two debug cycles; keep it int. */
            int pf[2];
            if (sys3(SYS_pipe2, (long)pf, 0, 0) != 0) { step = 1; ok = 0; break; }

            /* Read end has no data -> POLLIN not ready -> the call BLOCKS and
             * therefore registers (and pins) on the pipe's read waitq, then
             * times out after 20 ms and unregisters (and unpins). */
            pfds[0].fd = pf[0]; pfds[0].events = 0x001; pfds[0].revents = 0;
            long r = sys6(SYS_ppoll, (long)pfds, 1, (long)&ts, 0, 0, 0);
            if (r < 0) { step = 2; ok = 0; break; }

            /* Zero-timeout probe on the same pipe: sys_poll returns at the
             * `ready > 0 || timeout_ms == 0` early exit, which must still have
             * written revents back. The write end of an empty pipe is always
             * POLLOUT-ready, so a 0 here means the non-blocking path reported a
             * count without populating the array. */
            pfds[0].fd = pf[1]; pfds[0].events = 0x004; pfds[0].revents = 0;
            struct { long tv_sec; long tv_nsec; } z = { 0, 0 };
            long r0 = sys6(SYS_ppoll, (long)pfds, 1, (long)&z, 0, 0, 0);
            if (r0 < 0)                        { step = 3; ok = 0; break; }
            if (!(pfds[0].revents & 0x004))    { step = 4; ok = 0; break; }

            sys3(SYS_close, pf[0], 0, 0);
            sys3(SYS_close, pf[1], 0, 0);
        }

        if (ok) { pass++; out("[KTEST] PASS poll pin/unpin balance (40 blocking cycles)\n"); }
        else if (step == 1) out("[KTEST] FAIL poll pin/unpin: pipe2 failed (pool exhausted?)\n");
        else if (step == 3) out("[KTEST] FAIL poll pin/unpin: zero-timeout ppoll errored\n");
        else if (step == 4) out("[KTEST] FAIL poll: zero-timeout returned a count but no revents\n");
        else out("[KTEST] FAIL poll pin/unpin: ppoll returned an error\n");
    }

    /* 8f. PTY pool slots must be released exactly once, and only after the
     *     close path has finished touching the pair.
     *
     *     in_use was cleared under pair->lock while ptmx_open scans it and
     *     memsets the whole pair under pty_pool_lock — two different locks
     *     guarding one word. The slot is now released under pty_pool_lock and
     *     only AFTER the wakes, so a new owner cannot re-init pair->lock and
     *     both waitqueues under a thread that is still closing.
     *
     *     What this catches: the release is now conditional on `release`, so
     *     getting that wrong leaks the slot. The pool is PTY_MAX_PAIRS (16), so
     *     a leak fails within 17 iterations; 48 gives margin. It does NOT
     *     reproduce the cross-CPU re-init — that needs two threads racing
     *     open and close, and the corruption is silent without poisoning. */
    total++;
    {
        int ok = 1;
        for (int i = 0; i < 48 && ok; i++) {
            long fd = sys6(SYS_openat, AT_FDCWD, (long)"/dev/ptmx", 2 /*O_RDWR*/, 0, 0, 0);
            if (fd < 0) { ok = 0; break; }
            sys3(SYS_close, fd, 0, 0);
        }
        if (ok) { pass++; out("[KTEST] PASS ptmx slot release (48 cycles)\n"); }
        else out("[KTEST] FAIL ptmx slot release — pool exhausted (leak)\n");
    }

    /* 8g. getdents64 caps the ENTRIES it returns per call (GETDENTS_MAX_ENTRIES,
     *     512) so one syscall cannot run unbounded at IF=0 over a huge
     *     directory. That cap is only safe if it is transparent — getdents64 is
     *     specified to return short and callers loop — so build a directory
     *     LARGER than the cap and prove a full listing still enumerates every
     *     entry across multiple calls.
     *
     *     This is the regression that matters: a cap that silently truncated a
     *     listing would break every directory read on the system, and no
     *     existing test has a directory anywhere near 512 entries. */
    total++;
    {
        int ok = 1;
        const int NFILES = 600;          /* > GETDENTS_MAX_ENTRIES */
        char nm[32];
        if (k_mkdir("/gd") != 0) ok = 0;
        for (int i = 0; i < NFILES && ok; i++) {
            int p2 = 0;
            nm[p2++]='/'; nm[p2++]='g'; nm[p2++]='d'; nm[p2++]='/'; nm[p2++]='f';
            int v = i, d[4], nd = 0;
            do { d[nd++] = v % 10; v /= 10; } while (v && nd < 4);
            while (nd > 0) nm[p2++] = (char)('0' + d[--nd]);
            nm[p2] = '\0';
            long fd = sys6(SYS_openat, AT_FDCWD, (long)nm, 0x40 /*O_CREAT*/ | 1, 0644, 0, 0);
            if (fd < 0) ok = 0; else sys3(SYS_close, fd, 0, 0);
        }

        long seen = 0, calls = 0;
        if (ok) {
            long dfd = sys6(SYS_openat, AT_FDCWD, (long)"/gd", 0, 0, 0, 0);
            if (dfd < 0) ok = 0;
            else {
                static char dbuf[8192];
                for (;;) {
                    long n = sys3(SYS_getdents64, dfd, (long)dbuf, sizeof(dbuf));
                    if (n <= 0) break;
                    calls++;
                    /* Walk the returned records: d_reclen is at offset 16. */
                    for (long off = 0; off + 19 <= n; ) {
                        unsigned short rl = *(unsigned short *)(dbuf + off + 16);
                        if (rl == 0) break;
                        seen++;
                        off += rl;
                    }
                    if (calls > 20) break;   /* runaway guard */
                }
                sys3(SYS_close, dfd, 0, 0);
            }
        }
        /* Every file must be enumerated, and it must have taken more than one
         * call — otherwise the cap did not actually engage and proves nothing. */
        if (ok && seen < NFILES) ok = 0;
        if (ok && calls < 2)     ok = 0;

        for (int i = 0; i < NFILES; i++) {
            int p2 = 0;
            nm[p2++]='/'; nm[p2++]='g'; nm[p2++]='d'; nm[p2++]='/'; nm[p2++]='f';
            int v = i, d[4], nd = 0;
            do { d[nd++] = v % 10; v /= 10; } while (v && nd < 4);
            while (nd > 0) nm[p2++] = (char)('0' + d[--nd]);
            nm[p2] = '\0';
            k_unlink(nm);
        }
        k_rmdir("/gd");

        if (ok) { pass++; out("[KTEST] PASS getdents64 cap is transparent (600 entries)\n"); }
        else out("[KTEST] FAIL getdents64 cap truncated a listing\n");
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

        /* ext2 i_blocks counts allocated 512-byte sectors, not file bytes. */
        ok = 1;
        long bfd = sys6(SYS_openat, AT_FDCWD, (long)"/kt-blocks",
                        0x40 /*O_CREAT*/ | 1 /*O_WRONLY*/, 0644, 0, 0);
        ok &= (bfd >= 0);
        if (bfd >= 0) {
            ok &= (sys3(SYS_write, bfd, (long)"x", 1) == 1);
            ok &= (sys3(SYS_close, bfd, 0, 0) == 0);
        }
        ok &= (k_stat_at("/kt-blocks", st, 0) == 0);
        ok &= (k_stat_blocks(st) == 8); /* one 4 KiB block */
        ok &= (k_unlink("/kt-blocks") == 0);
        total++;
        if (ok) { pass++; out("[KTEST] PASS ext2 block accounting\n"); }
        else out("[KTEST] FAIL ext2 block accounting\n");

        /* A directory fd is a real inode-relative root. Once confined its
         * rights only shrink and neither .. nor writes can escape that root. */
        ok = 1;
        ok &= (k_mkdir("/ktcap") == 0);
        long cfd = sys6(SYS_openat, AT_FDCWD, (long)"/ktcap/file",
                        0x40 | 1, 0644, 0, 0);
        ok &= (cfd >= 0);
        if (cfd >= 0) {
            ok &= (sys3(SYS_write, cfd, (long)"x", 1) == 1);
            sys3(SYS_close, cfd, 0, 0);
        }
        long dfd = sys6(SYS_openat, AT_FDCWD, (long)"/ktcap", 0, 0, 0, 0);
        ok &= (dfd >= 0);
        long rfd = dfd >= 0
                 ? sys6(SYS_openat, dfd, (long)"file", 0, 0, 0, 0) : -1;
        ok &= (rfd >= 0);
        if (rfd >= 0) sys3(SYS_close, rfd, 0, 0);
        ok &= (dfd >= 0 && sys3(SYS_cap_rights_limit, dfd,
                                 1 /*READ*/ | 4 /*EXEC*/, 0) == 0);
        ok &= (sys6(SYS_openat, dfd, (long)"file", 1 /*O_WRONLY*/, 0, 0, 0) < 0);
        ok &= (sys3(SYS_cap_rights_limit, dfd,
                    1 /*READ*/ | 4 /*EXEC*/, 1) == 0);
        ok &= (sys6(SYS_openat, dfd, (long)"../bin/sh", 0, 0, 0, 0) < 0);
        ok &= (sys3(SYS_cap_rights_limit, dfd, 1 /*READ*/, 0) == 0);
        ok &= (sys6(SYS_openat, dfd, (long)"file", 0, 0, 0, 0) < 0);
        if (dfd >= 0) sys3(SYS_close, dfd, 0, 0);
        ok &= (k_unlink("/ktcap/file") == 0);
        ok &= (k_rmdir("/ktcap") == 0);
        total++;
        if (ok) { pass++; out("[KTEST] PASS confined directory openat\n"); }
        else out("[KTEST] FAIL confined directory openat\n");

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
     *     Shape: child execs this image for fresh baseline caps, then clones a
     *     thread that blocks reading an empty pipe, then
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
            if (pid == 0) exec_lifecycle(1, pfd[0]);
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
            if (pid == 0) exec_lifecycle(2, pfd[0]);
            /* THE PROBE: a BLOCKING wait4. WNOHANG would poll its own way out
             * of the bug and prove nothing — the defect is precisely that the
             * blocked parent is never woken again. */
            int status = 0;
            long w = sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
            /* Non-leader exit_group kills the leader with SIGKILL; wait4
             * reports that leader's signal death, not the caller's code 88. */
            if (pid <= 0 || w != pid || status != 9) ok = 0;
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
     *     and one failure fails the case. Each child execs for fresh policy
     *     before creating threads; fork itself deliberately grants none.
     *     At three leaked slots per iteration
     *     that ceiling is reached around iteration 83, so 100 iterations clear
     *     it with margin while staying well inside the harness timeout. */
    total++;
    {
        int ok = 1;
        for (int i = 0; i < 100 && ok; i++) {
            long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
            if (pid < 0) { ok = 0; break; }
            if (pid == 0) exec_lifecycle(3, 0);
            int st = 0;
            if (sys6(SYS_wait4, pid, (long)&st, 0, 0, 0, 0) != pid) { ok = 0; break; }
            /* Non-zero == the child could not create its threads, i.e. the slots
             * from earlier iterations were never returned. */
            if (st != 0) { ok = 0; break; }
        }
        if (ok) { pass++; out("[KTEST] PASS thread-zombie reap (slots returned)\n"); }
        else out("[KTEST] FAIL thread-zombie reap\n");
    }

    /* ── Hostile-syscall robustness battery ────────────────────────────────
     * Hammer the syscall boundary with pointers no libc ever passes — kernel
     * higher-half, non-canonical, huge/negative lengths — focused on the
     * Aegis-specific syscalls (500-519, cap/auth) and structured-buffer calls.
     * The in-tree loricaos `sysfuzz` covers this for the generic Linux syscalls
     * but is never run under a kernel test harness AND never touches the custom
     * Aegis numbers — the newest, least-exercised copy_from_user sites. Property:
     * memory safety at the uaccess boundary — every probe must return an errno,
     * NEVER dereference the bad pointer, panic, or corrupt memory. If any does,
     * the kernel dies before the marker below and captest fails. init holds
     * POWER but not DISK_ADMIN/INSTALL/AUTH, so the cap-gated calls must reject
     * at the cap check BEFORE any copy — that ordering is what this tests. The
     * cap_query(pid=0) probe needs no cap and copies TO the user buffer, so a
     * kernel-pointer output arg exercises its user_ptr_valid directly. (Added
     * during a 2026-08-09 memory-safety pass.) */
    total++;
    {
        const long KPTR   = (long)0xFFFFFFFF80000000UL; /* kernel higher-half  */
        const long NONCAN = (long)0x0000800000000000UL; /* first non-canonical */
        const long HUGE   = (long)0x7FFFFFFFFFFFFFFFUL;
        const long NEG1   = (long)0xFFFFFFFFFFFFFFFFUL;

        /* Aegis raw-disk (511 io, 510 list): hostile buffer + lba/count. */
        sys6(511, 0, 0, KPTR, HUGE, 0, 0);
        sys6(511, 1, NEG1, NONCAN, HUGE, 0, 0);
        sys3(510, KPTR, HUGE, 0);
        /* Aegis netcfg (500) + adminconf (501 autologin, 502 ntp). */
        sys6(500, KPTR, HUGE, 0, 0, 0, 0);
        sys3(501, NEG1, 0, 0);
        sys3(502, HUGE, 0, 0);
        /* Aegis install/session gates (516 commit, 517 elevate, 519 query). */
        sys3(516, 0, 0, 0);
        sys3(517, NEG1, 0, 0);
        sys3(519, 0, 0, 0);
        /* Cap/auth: 362 cap_query copies TO the user buffer; 364 auth_session. */
        sys6(362, 0, KPTR, HUGE, 0, 0, 0);
        sys6(362, NEG1, NONCAN, HUGE, 0, 0, 0);
        sys3(364, NEG1, NEG1, 0);
        /* Retired vfs_confine (518) must ignore hostile path pointers safely. */
        sys3(518, KPTR, 0, 0);
        sys3(518, NONCAN, 0, 0);
        /* Structured buffers: ppoll (huge nfds + kernel fds), getdents64. */
        sys6(SYS_ppoll, KPTR, HUGE, 0, 0, 0, 0);
        sys6(SYS_ppoll, NONCAN, 16, KPTR, 0, 0, 0);
        sys6(SYS_getdents64, NEG1, KPTR, HUGE, 0, 0, 0);

        /* Reached here → the kernel survived every hostile probe. */
        pass++;
        out("[KTEST] PASS hostile-syscall battery (kernel survived)\n");
    }

    if (pass == total) out("[KTEST] DONE all-pass\n");
    else                out("[KTEST] DONE FAIL\n");

    sys3(SYS_exit, 0, 0, 0);
    for (;;) { }
}
