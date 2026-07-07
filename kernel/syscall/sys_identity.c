/* sys_identity.c — Identity, info, session, and resource syscalls */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "arch.h"
#include "ext2.h"
#include "printk.h"
#include "acpi.h"
#include "nvme.h"
#include "thermal.h"

/* Build-time version from the Makefile (git describe); see sys_uname. */
#ifndef AEGIS_VERSION
#define AEGIS_VERSION "untracked"
#endif

/* sched_lock protects the global circular task list — defined in sched.c.
 * Task-list walks below must hold it: sched_add (fork/clone/spawn) and the
 * sys_waitpid zombie unlink mutate the chain concurrently on SMP. */
extern spinlock_t sched_lock;

uint64_t
sys_getpid(void)
{
    aegis_task_t *task = sched_current();
    if (!task->is_user) return 0;
    return (uint64_t)((aegis_process_t *)task)->tgid;
}

uint64_t
sys_gettid(void)
{
    aegis_task_t *task = sched_current();
    if (!task->is_user) return 0;
    return (uint64_t)((aegis_process_t *)task)->pid;
}

/*
 * sys_getppid — syscall 110
 *
 * Returns the parent PID of the calling process.
 * No capability gate — a process may always query its own parent.
 */
uint64_t
sys_getppid(void)
{
    aegis_process_t *proc = current_proc();
    return (uint64_t)proc->ppid;
}

uint64_t
sys_set_tid_address(uint64_t arg1)
{
    aegis_task_t *task = sched_current();
    if (arg1 && arg1 >= 0xFFFF800000000000ULL)
        return SYS_ERR(EFAULT);  /* EFAULT — reject kernel addresses */
    task->clear_child_tid = arg1;
    if (!task->is_user) return 1;
    return (uint64_t)((aegis_process_t *)task)->pid;
}

uint64_t sys_set_robust_list(uint64_t a, uint64_t b)
{
    (void)a; (void)b;
    return 0;
}

/*
 * sys_hwmon — syscall 506
 *
 * arg1 = user pointer to struct aegis_hwmon. Fills CPU die temperature and,
 * when a platform battery driver exists, battery state. Read-only telemetry:
 * no capability gate — querying temperature/charge confers no authority.
 */
struct aegis_hwmon {
    int32_t  cpu_temp_c;        /* CPU die temp °C, -1 = unavailable        */
    int32_t  cpu_temp_max_c;    /* nominal throttle ceiling °C, -1 = unknown */
    uint8_t  battery_present;   /* 0 / 1                                     */
    uint8_t  battery_percent;   /* 0 - 100                                   */
    uint8_t  battery_charging;  /* 0 / 1                                     */
    uint8_t  ac_online;         /* 0 / 1                                     */
    uint8_t  reserved[4];
};

uint64_t
sys_hwmon(uint64_t ubuf)
{
    struct aegis_hwmon hw;
    __builtin_memset(&hw, 0, sizeof(hw));

    int tjmax = -1;
    int t = cpu_temp_read(&tjmax);
    hw.cpu_temp_c     = t;
    hw.cpu_temp_max_c = (t >= 0) ? tjmax : -1;

    /* Battery: no ACPI/EC path yet — reported absent until a platform driver
     * (ACPI _BST via the embedded controller, or Smart Battery over SMBus) lands. */

    if (!user_ptr_valid(ubuf, sizeof(hw)))
        return SYS_ERR(EFAULT);
    copy_to_user((void *)(uintptr_t)ubuf, &hw, sizeof(hw));
    return 0;
}

/*
 * sys_arch_prctl — syscall 158
 *
 * arg1 = code
 * arg2 = addr
 *
 * ARCH_SET_FS (0x1002): set FS.base to addr. Writes IA32_FS_BASE MSR
 *   and saves to proc->fs_base.
 * ARCH_GET_FS (0x1003): write current fs_base to *addr.
 * All other codes: return -EINVAL.
 */
uint64_t
sys_arch_prctl(uint64_t arg1, uint64_t arg2)
{
    if (arg1 == ARCH_SET_FS) {
        /* Reject kernel addresses — user process must not set FS base to
         * kernel space. Corrupts musl TLS → cascading garbage syscalls. */
        if (arg2 >= 0xFFFF800000000000ULL)
            return SYS_ERR(EFAULT);
        sched_current()->fs_base = arg2;
        arch_set_fs_base(arg2);
        return 0;
    }
    if (arg1 == ARCH_GET_FS) {
        COPY_TO_USER(arg2, &sched_current()->fs_base);
        return 0;
    }
    return SYS_ERR(EINVAL);
}

/* sys_setpgid — syscall 109: set pgid of process pid to pgid.
 * pid=0 means current process. pgid=0 means use target's pid.
 * Allows creating own group (pgid == pid) or joining existing group in same session. */
uint64_t
sys_setpgid(uint64_t pid_arg, uint64_t pgid_arg)
{
    aegis_process_t *caller = current_proc();
    uint32_t pid  = (uint32_t)pid_arg;
    uint32_t pgid = (uint32_t)pgid_arg;

    aegis_process_t *target = caller;
    if (pid != 0 && pid != caller->pid) {
        target = proc_find_by_pid(pid);
        if (!target)
            return SYS_ERR(ESRCH);
        /* Can only setpgid on self or direct child */
        if (target->ppid != caller->pid)
            return SYS_ERR(EPERM);
    }

    if (pgid == 0)
        pgid = target->pid;

    /* Always allow: pgid == target->pid (create own group) */
    if (pgid != target->pid) {
        /* Verify pgid belongs to a process in the same session.
         * Walk under sched_lock — the list mutates concurrently on SMP. */
        int found = 0;
        irqflags_t fl = spin_lock_irqsave(&sched_lock);
        aegis_task_t *t = sched_current();
        aegis_task_t *start = t;
        do {
            if (t->is_user) {
                aegis_process_t *p = (aegis_process_t *)t;
                if (p->pgid == pgid && p->sid == target->sid) {
                    found = 1;
                    break;
                }
            }
            t = t->next;
        } while (t != start);
        spin_unlock_irqrestore(&sched_lock, fl);
        if (!found)
            return SYS_ERR(EPERM);
    }

    target->pgid = pgid;
    return 0;
}

/* sys_getpgrp — syscall 111: return current->pgid */
uint64_t
sys_getpgrp(void)
{
    aegis_process_t *proc = current_proc();
    return (uint64_t)proc->pgid;
}

/* sys_setsid — syscall 112: create new session.
 * Fails with EPERM if caller is already a process group leader. */
uint64_t
sys_setsid(void)
{
    aegis_process_t *proc = current_proc();
    /* POSIX: EPERM if already a process group leader */
    if (proc->pgid == proc->pid)
        return SYS_ERR(EPERM);
    proc->sid  = proc->pid;
    proc->pgid = proc->pid;
    return (uint64_t)proc->pid;
}

/* sys_getpgid — syscall 121: return pgid of process pid (0 = self). */
uint64_t
sys_getpgid(uint64_t pid_arg)
{
    aegis_process_t *caller = current_proc();
    uint32_t pid = (uint32_t)pid_arg;
    if (pid == 0)
        return (uint64_t)caller->pgid;

    /* Walk under sched_lock — the list mutates concurrently on SMP. */
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    aegis_task_t *t = sched_current()->next;
    while (t != sched_current()) {
        if (t->is_user) {
            aegis_process_t *p = (aegis_process_t *)t;
            if (p->pid == pid) {
                uint64_t found_pgid = (uint64_t)p->pgid;
                spin_unlock_irqrestore(&sched_lock, fl);
                return found_pgid;
            }
        }
        t = t->next;
    }
    spin_unlock_irqrestore(&sched_lock, fl);
    return SYS_ERR(ESRCH);
}

/* sys_umask — syscall 95: set file creation mask; return previous value.
 * Not yet wired to ext2 create. */
uint64_t
sys_umask(uint64_t mask)
{
    aegis_process_t *proc = current_proc();
    uint32_t old = proc->umask;
    proc->umask  = (uint32_t)(mask & 0777U);
    return (uint64_t)old;
}

/* sys_getrlimit — syscall 97: return {RLIM_INFINITY, RLIM_INFINITY}.
 * struct rlimit = {uint64_t rlim_cur, rlim_max} = 16 bytes. */
uint64_t
sys_getrlimit(uint64_t resource, uint64_t rlim_ptr)
{
    (void)resource;
    if (!user_ptr_valid(rlim_ptr, 16))
        return SYS_ERR(EFAULT);
    uint64_t inf[2] = { ~0ULL, ~0ULL };
    copy_to_user((void *)(uintptr_t)rlim_ptr, inf, 16);
    return 0;
}

/*
 * sys_uname — syscall 63
 * arg1 = user pointer to struct utsname (6 x 65-byte char arrays).
 * Returns kernel identity strings; oksh uses these for $HOSTNAME and PS1.
 */
uint64_t
sys_uname(uint64_t buf_uptr)
{
    /* struct utsname: sysname[65] nodename[65] release[65]
     *                 version[65] machine[65] domainname[65] */
    char uts[6 * 65];
    if (!user_ptr_valid(buf_uptr, sizeof(uts)))
        return SYS_ERR(EFAULT);
    __builtin_memset(uts, 0, sizeof(uts));
    __builtin_memcpy(uts + 0*65,  "Aegis",   5); /* sysname    */
    hostname_get(uts + 1*65, 65);                 /* nodename — live, settable */
    {
        /* release — injected by the Makefile from git: the exact tag on
         * release builds ("1.1.1"), dev-<hash> otherwise.  The fallback
         * covers trees built outside git. */
        const char *rel = AEGIS_VERSION;
        uint32_t rlen = 0;
        while (rel[rlen] && rlen < 64) rlen++;
        __builtin_memcpy(uts + 2*65, rel, rlen);
    }
    __builtin_memcpy(uts + 3*65,  "#1",      2); /* version    */
#ifdef __aarch64__
    __builtin_memcpy(uts + 4*65,  "aarch64", 7); /* machine    */
#else
    __builtin_memcpy(uts + 4*65,  "x86_64",  6); /* machine    */
#endif
    __builtin_memcpy(uts + 5*65,  "(none)",  6); /* domainname */
    copy_to_user((void *)(uintptr_t)buf_uptr, uts, sizeof(uts));
    return 0;
}

/*
 * sys_setuid — syscall 105
 *
 * uid is cosmetic in Aegis (capabilities are the real authority), but it still
 * drives ext2 DAC checks, so an arbitrary "setuid(0)" would let a SETUID holder
 * gain DAC authority over root-owned files — ambient authority by the back
 * door. The rule:
 *   - target == current uid: always allowed (no-op; never an escalation).
 *   - otherwise: require CAP_KIND_SETUID AND target == the identity bound at
 *     sys_auth_session (proc->auth_uid). A process that never authenticated
 *     (auth_uid == AUTH_ID_NONE) cannot change its uid at all.
 * This binds a SETUID holder to the single identity whose credentials were
 * actually verified, instead of letting it become any uid including 0.
 */
uint64_t
sys_setuid(uint64_t uid_arg)
{
    aegis_process_t *proc = current_proc();
    uint32_t target = (uint32_t)uid_arg;
    if (target == proc->uid)
        return 0;  /* no-op */
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_SETUID, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(EACCES);
    if (target != proc->auth_uid)
        return SYS_ERR(EPERM);  /* EPERM — not the bound identity */
    proc->uid = target;
    return 0;
}

/*
 * sys_setgid — syscall 106
 * Same bound-identity rule as sys_setuid, against proc->auth_gid.
 */
uint64_t
sys_setgid(uint64_t gid_arg)
{
    aegis_process_t *proc = current_proc();
    uint32_t target = (uint32_t)gid_arg;
    if (target == proc->gid)
        return 0;  /* no-op */
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_SETUID, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(EACCES);
    if (target != proc->auth_gid)
        return SYS_ERR(EPERM);  /* EPERM — not the bound identity */
    proc->gid = target;
    return 0;
}

/* Identity syscalls — moved from sys_file.c. */
uint64_t sys_getuid(void) {
    aegis_process_t *p = current_proc();
    return p ? (uint64_t)p->uid : 0;
}
uint64_t sys_geteuid(void) { return sys_getuid(); }
uint64_t sys_getgid(void) {
    aegis_process_t *p = current_proc();
    return p ? (uint64_t)p->gid : 0;
}
uint64_t sys_getegid(void) { return sys_getgid(); }

/*
 * sys_reboot — syscall 169
 *
 * cmd=0: ACPI S5 power off
 * cmd=1: keyboard controller reset (reboot)
 *
 * Requires CAP_KIND_POWER — granted via kernel cap policy.
 */
uint64_t
sys_reboot(uint64_t cmd)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_POWER, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    extern volatile uint32_t g_bc_kernel, g_bc_user, g_bc_full;
    printk("[TLBSTAT] broadcasts kernel=%u user=%u full=%u\n",
           (unsigned)g_bc_kernel, (unsigned)g_bc_user, (unsigned)g_bc_full);

    if (cmd == 0) {
        /* Power off.  Flush fs + the drive's volatile write cache first —
         * raw callers (no vigil teardown) must not lose dirty data. */
        ext2_sync();
        ext2_mark_clean();     /* orderly shutdown → next mount won't warn dirty */
#ifdef __x86_64__
        nvme_flush();
        acpi_do_poweroff();
#else
        arch_debug_exit(0);    /* QEMU virt: write to power device */
#endif
        arch_disable_irq();
        for (;;) arch_halt();
    } else if (cmd == 1) {
        /* Reboot */
        ext2_sync();
        ext2_mark_clean();     /* orderly shutdown → next mount won't warn dirty */
#ifdef __x86_64__
        nvme_flush();          /* commit volatile write cache before reset */
#endif
        printk("[AEGIS] Rebooting...\n");
#ifdef __x86_64__
        /* 8042 keyboard-controller pulse reset (QEMU / legacy firmware). */
        __asm__ volatile ("outb %0, %1" : : "a"((uint8_t)0xFE), "Nd"((uint16_t)0x64));
        /* Hyper-V Gen 2 and other modern VMs have no 8042, so the pulse above
         * is ignored.  Fall back to a triple fault: load a null IDT and raise an
         * exception → no handler → double fault → no handler → triple fault →
         * the CPU/VM resets.  Works on Hyper-V, QEMU q35, and bare metal. */
        {
            struct __attribute__((packed)) { uint16_t limit; uint64_t base; }
                null_idtr = { 0, 0 };
            __asm__ volatile ("lidt %0; int3" : : "m"(null_idtr));
        }
#else
        /* ARM64: PSCI SYSTEM_RESET would go here; for now fall through to halt */
        arch_debug_exit(1);
#endif
        arch_disable_irq();
        for (;;) arch_halt();
    }
    return SYS_ERR(EINVAL);
}

/* ── ladybird/musl compat shims (multi-process browser needs these) ─────── */

/* sysinfo(99): report plausible memory so allocators don't divide by zero. */
uint64_t sys_sysinfo(uint64_t buf)
{
    struct si { long uptime; unsigned long loads[3];
                unsigned long totalram, freeram, sharedram, bufferram,
                              totalswap, freeswap;
                unsigned short procs, pad;
                unsigned long totalhigh, freehigh;
                unsigned int mem_unit; char _f[20]; } k;
    if (!user_ptr_valid(buf, sizeof(k))) return SYS_ERR(EFAULT);
    __builtin_memset(&k, 0, sizeof(k));
    k.uptime   = (long)(arch_get_ticks() / 100);
    k.totalram = 2UL * 1024 * 1024 * 1024;   /* 2 GiB */
    k.freeram  = 1UL * 1024 * 1024 * 1024;
    k.procs    = 16;
    k.mem_unit = 1;
    copy_to_user((void *)(uintptr_t)buf, &k, sizeof(k));
    return 0;
}

/* sched_getaffinity(204): single online CPU; mask byte 0 = bit 0. Returns the
 * number of bytes written (glibc/musl use it to popcount the CPU count). */
uint64_t sys_sched_getaffinity(uint64_t pid, uint64_t len, uint64_t mask)
{
    (void)pid;
    unsigned long n = len;
    if (n > 128) n = 128;
    if (n < 8) return SYS_ERR(EINVAL);
    if (!user_ptr_valid(mask, n)) return SYS_ERR(EFAULT);
    unsigned char buf[128];
    __builtin_memset(buf, 0, sizeof(buf));
    buf[0] = 0x01;                            /* CPU 0 online */
    copy_to_user((void *)(uintptr_t)mask, buf, n);
    return 8;                                 /* kernel cpumask size */
}

/* prlimit64(302): query/set resource limits. We only honour the query (old)
 * side with generous limits; sets are accepted as no-ops. */
uint64_t sys_prlimit64(uint64_t pid, uint64_t res, uint64_t newp, uint64_t oldp)
{
    (void)pid; (void)newp;
    if (oldp) {
        struct rl { unsigned long cur, max; } k;
        if (!user_ptr_valid(oldp, sizeof(k))) return SYS_ERR(EFAULT);
        unsigned long INF = ~0UL;
        if (res == 7) { k.cur = 1024; k.max = 1024; }            /* RLIMIT_NOFILE */
        else if (res == 3) { k.cur = 8UL*1024*1024; k.max = INF; } /* RLIMIT_STACK */
        else { k.cur = INF; k.max = INF; }
        copy_to_user((void *)(uintptr_t)oldp, &k, sizeof(k));
    }
    return 0;
}

/* inotify_init1(294): return a benign, never-firing fd (eventfd-backed). File
 * watchers poll it and simply never see events. */
extern uint64_t sys_eventfd2(uint64_t initval, uint64_t flags);
uint64_t sys_inotify_init1(uint64_t flags)
{
    /* eventfd flags share the same EFD_NONBLOCK/EFD_CLOEXEC bit values. */
    return sys_eventfd2(0, flags);
}

/* inotify_add_watch(254): inotify is an inert stub (init1 hands back a
 * never-firing eventfd). Return a positive watch descriptor so file watchers
 * believe the watch was registered; no events are ever delivered. */
uint64_t sys_inotify_add_watch(uint64_t fd, uint64_t path, uint64_t mask)
{
    (void)fd; (void)path; (void)mask;
    static int wd = 0;
    return (uint64_t)(++wd);
}

