/* exectgt — a second freestanding program the test-init execs to validate
 * the execve path (ELF load of a NEW image + the ring-3/EL0 entry
 * trampoline). It writes a marker and exits 42; the parent checks that
 * exit status to confirm exec succeeded (execve only returns on failure,
 * in which case the child exits 99). Built with the kernel toolchain, no
 * libc — raw syscalls, per-arch numbers matching test/init.c. */

#include "../kernel/cap/cap.h"

#ifdef __aarch64__
static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}
#else
static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}
#endif

static long sys3(long n, long a, long b, long c) { return sys6(n, a, b, c, 0, 0, 0); }

#define SYS_write        1
#define SYS_exit         60
#define SYS_blkdev_list  510   /* gated on CAP_KIND_DISK_ADMIN */
#define SYS_spawn        514
#define SYS_cap_query    362
#ifdef __aarch64__
#define SYS_openat       56
#define SYS_close        57
#define SYS_clone        220
#define SYS_wait4        260
#define SYS_execve       221
#else
#define SYS_openat       257
#define SYS_close        3
#define SYS_clone        56
#define SYS_wait4        61
#define SYS_execve       59
#endif
#define AT_FDCWD         -100

static long k_open(const char *p)
{
    return sys3(SYS_openat, AT_FDCWD, (long)p, 0 /* O_RDONLY */);
}

static void finish(int status)
{
    sys3(SYS_exit, status, 0, 0);
    for (;;) { }
}

static void reexec(const char *mode)
{
    const char *argv[] = { "/bin/exectest", mode, 0 };
    const char *envp[] = { 0 };
    sys3(SYS_execve, (long)argv[0], (long)argv, (long)envp);
    finish(99);
}

static int waited(long pid)
{
    int st = 0;
    return pid > 0 && sys6(SYS_wait4, pid, (long)&st, 0, 0, 0, 0) == pid &&
           st == (42 << 8);
}

static int spawned(const char *mode, const cap_slot_t *mask)
{
    const char *argv[] = { "/bin/exectest", mode, 0 };
    return waited(sys6(SYS_spawn, (long)argv[0], (long)argv, 0, 2, (long)mask, 0));
}

/* Check exact tables: masked descendants may not regain ANY excluded grant. */
static int policy_table(int confined)
{
    cap_slot_t caps[CAP_TABLE_SIZE];
    if (sys3(SYS_cap_query, 0, (long)caps, sizeof(caps)) != CAP_TABLE_SIZE)
        return 0;
    unsigned seen = 0;
    for (unsigned i = 0; i < CAP_TABLE_SIZE; i++) {
        unsigned kind = caps[i].kind, rights = caps[i].rights, expected;
        if (!kind) { if (rights) return 0; continue; }
        if (kind == CAP_KIND_VFS_OPEN || kind == CAP_KIND_VFS_READ)
            expected = CAP_RIGHTS_READ;
        else if (kind == CAP_KIND_VFS_WRITE) expected = CAP_RIGHTS_WRITE;
        else if (kind == CAP_KIND_CAP_DELEGATE)
            expected = confined ? CAP_RIGHTS_READ :
                       CAP_RIGHTS_READ | CAP_RIGHTS_WRITE | CAP_RIGHTS_EXEC;
        else if (!confined && (kind == CAP_KIND_IPC || kind == CAP_KIND_THREAD_CREATE))
            expected = CAP_RIGHTS_READ;
        else if (!confined && kind == CAP_KIND_NET_SOCKET)
            expected = CAP_RIGHTS_READ | CAP_RIGHTS_WRITE | CAP_RIGHTS_EXEC;
        else return 0;
        if (rights != expected || (seen & (1u << kind))) return 0;
        seen |= 1u << kind;
    }
    unsigned wanted = (1u << CAP_KIND_VFS_OPEN) | (1u << CAP_KIND_VFS_READ) |
                      (1u << CAP_KIND_VFS_WRITE) | (1u << CAP_KIND_CAP_DELEGATE);
    if (!confined) wanted |= (1u << CAP_KIND_IPC) | (1u << CAP_KIND_THREAD_CREATE) |
                            (1u << CAP_KIND_NET_SOCKET);
    return seen == wanted;
}

/* Capture the ABI stack before a C prologue changes SP. */
#ifdef __aarch64__
__asm__(".global _start\n_start:\nmov x0, sp\nbl test_main\n1: b 1b\n");
#else
__asm__(".global _start\n_start:\nmov %rsp, %rdi\nand $-16, %rsp\ncall test_main\n1: jmp 1b\n");
#endif

__attribute__((used)) static void test_main(const unsigned long *stack)
{
    unsigned long argc = *stack++;
    if (!argc || argc > 64) finish(46);
    const char *mode = argc > 1 ? (const char *)stack[1] : "";
    stack += argc + 1;
    unsigned envc = 0;
    while (*stack && envc < 32) { stack++; envc++; }
    if (*stack) finish(46);
    stack++;
    int secure = -1;
    for (unsigned i = 0; i < 32 && stack[0]; i++, stack += 2)
        if (stack[0] == 23) secure = (int)stack[1];

    /* f/F: fresh spawn then same-policy exec are unconfined, ALWAYS secure.
     * m/r/l: masked spawn, same-policy exec and unmasked spawn under a ceiling
     * add no authority (secure=0). Confined fork->exec gains from an empty
     * table (g, secure=1), without escaping its inherited ceiling. */
    int confined = mode[0] == 'm' || mode[0] == 'r' || mode[0] == 'l' || mode[0] == 'g';
    int expected_secure = !confined || mode[0] == 'g';
    if (secure != expected_secure) finish(47);
    if (!policy_table(confined)) finish(48);
    if (mode[0] == 'f') reexec("F");
    if (mode[0] == 'F' || mode[0] == 'r' || mode[0] == 'l' || mode[0] == 'g')
        finish(42);
    if (mode[0] == 'm') {
        if (!spawned("l", 0)) finish(49);
        long pid = sys6(SYS_clone, 17 /* SIGCHLD */, 0, 0, 0, 0, 0);
        if (pid == 0) reexec("g");
        if (!waited(pid)) finish(50);
        reexec("r");
    }
    if (mode[0]) finish(46);

    const char *m = "[KTEST] exec-target running\n";
    unsigned n = 0; while (m[n]) n++;
    sys3(SYS_write, 2, (long)m, n);

    static const cap_slot_t mask[CAP_TABLE_SIZE] = {
        { CAP_KIND_VFS_OPEN, CAP_RIGHTS_READ },
        { CAP_KIND_VFS_READ, CAP_RIGHTS_READ },
        { CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE },
        { CAP_KIND_CAP_DELEGATE, CAP_RIGHTS_READ },
    };
    if (!spawned("f", 0) || !spawned("m", mask)) finish(51);
    m = "[KTEST] PASS fresh exec policy and persistent spawn ceilings + AT_SECURE\n";
    n = 0; while (m[n]) n++;
    sys3(SYS_write, 2, (long)m, n);

    /* Service-tier privilege-laundering guard: this binary ships a policy of
     * `service DISK_ADMIN` (test rootfs /etc/aegis/caps.d/exectest). DISK_ADMIN
     * is admin_session-gated, so the kernel must REFUSE to grant it through the
     * unconditional SERVICE tier — otherwise the tier word forges elevation.
     * blkdev_list needs DISK_ADMIN: refused (<0) = fix holds → exit 42; granted
     * (>=0) = the laundering hole is open → exit 43 so the parent FAILs. */
    long r = sys3(SYS_blkdev_list, 0, 0, 0);
    if (r >= 0)
        sys3(SYS_exit, 43, 0, 0);

    /* procfs cap gate (audit H10). /proc/stackshot dumps every task's identity
     * and kernel backtrace to the log, holding sched_lock across kilobytes of
     * serial output; ungated it was an unprivileged system-wide freeze and a
     * kernel-address leak. It now needs PROC_READ, which this service-tier
     * binary does not have (PROC_READ is deliberately not baseline).
     *
     * Check a PUBLIC procfs file opens first — otherwise a /proc that isn't
     * reachable at all would make the denial below pass for the wrong reason. */
    long pub = k_open("/proc/uptime");
    if (pub < 0)
        sys3(SYS_exit, 44, 0, 0);          /* procfs broken — gate untestable */
    sys3(SYS_close, pub, 0, 0);

    long ss = k_open("/proc/stackshot");
    if (ss >= 0)
        sys3(SYS_exit, 45, 0, 0);          /* not gated → parent FAILs */

    sys3(SYS_exit, 42, 0, 0);
    for (;;) { }
}
