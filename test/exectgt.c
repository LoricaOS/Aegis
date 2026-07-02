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

#define SYS_write 1
#define SYS_exit  60

void _start(void)
{
    const char *m = "[KTEST] exec-target running\n";
    unsigned n = 0; while (m[n]) n++;
    sys3(SYS_write, 2, (long)m, n);
    sys3(SYS_exit, 42, 0, 0);
    for (;;) { }
}
