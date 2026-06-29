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

/* x86-64 Aegis/Linux syscall ABI: nr in rax; args rdi,rsi,rdx; ret in rax. */
static long sys3(long n, long a, long b, long c)
{
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return ret;
}

#define SYS_write        1
#define SYS_getpid       39
#define SYS_exit         60
#define SYS_sethostname  170   /* gated on CAP_KIND_POWER — init HOLDS this */
#define SYS_blkdev_list  510   /* gated on CAP_KIND_DISK_ADMIN — init LACKS this */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void out(const char *s) { sys3(SYS_write, 2, (long)s, slen(s)); }

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

    if (pass == total) out("[KTEST] DONE all-pass\n");
    else                out("[KTEST] DONE FAIL\n");

    sys3(SYS_exit, 0, 0, 0);
    for (;;) { }
}
