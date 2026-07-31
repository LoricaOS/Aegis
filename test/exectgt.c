/* exectgt — a second freestanding program the test-init execs to validate
 * the execve path (ELF load of a NEW image + the ring-3/EL0 entry
 * trampoline). It writes a marker and exits 42; the parent checks that
 * exit status to confirm exec succeeded (execve only returns on failure,
 * in which case the child exits 99). Built with the kernel toolchain, no
 * libc — raw syscalls, per-arch numbers matching test/init.c. */

#ifdef __aarch64__
static long sys3(long n, long a, long b, long c)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
#else
static long sys3(long n, long a, long b, long c)
{
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return ret;
}
#endif

#define SYS_write        1
#define SYS_exit         60
#define SYS_blkdev_list  510   /* gated on CAP_KIND_DISK_ADMIN */
#define SYS_openat       257
#define SYS_close        3
#define AT_FDCWD         -100

static long k_open(const char *p)
{
    return sys3(SYS_openat, AT_FDCWD, (long)p, 0 /* O_RDONLY */);
}

void _start(void)
{
    const char *m = "[KTEST] exec-target running\n";
    unsigned n = 0; while (m[n]) n++;
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
