/* syscall.c — Syscall dispatch table.
 * Implementation split into sys_io.c, sys_memory.c, sys_process.c,
 * sys_file.c, sys_signal.c. */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "signal.h"
#include "printk.h"
#include "eventfd.h"

uint64_t
syscall_dispatch(syscall_frame_t *frame, uint64_t num,
                 uint64_t arg1, uint64_t arg2, uint64_t arg3,
                 uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
#ifdef __aarch64__
    /* ARM64 Linux uses different syscall numbers than x86-64.
     * musl compiled for aarch64 emits ARM64 numbers. Translate the
     * most common ones to x86-64 numbers used by the dispatch table.
     * This avoids duplicating the entire switch table. */
    switch (num) {
    /* File I/O */
    case  17: num = 79;  break;  /* getcwd */
    case  23: num = 33;  break;  /* dup */
    case  24: num = 33;  break;  /* dup3 → dup (approx) */
    case  25: num = 72;  break;  /* fcntl */
    case  29: num = 16;  break;  /* ioctl */
    case  35: num = 87; arg1 = arg2; break;  /* unlinkat → unlink (skip dirfd) */
    case  46: num = 77;  break;  /* ftruncate — real (was stubbed to fstat, so
                                  * memfds never got sized: Lumen's client surface
                                  * mmap then failed → GUI clients got EIO) */
    case  48: num = 21; arg1 = arg2; arg2 = arg3; break; /* faccessat → access (skip dirfd) */
    case  49: num = 80;  break;  /* chdir */
    case  56: num = 257; break;  /* openat */
    case  57: num = 3;   break;  /* close */
    case  61: num = 217; break;  /* getdents64 */
    case  62: num = 8;   break;  /* lseek */
    case  63: num = 0;   break;  /* read */
    case  64: num = 1;   break;  /* write */
    case  66: num = 20;  break;  /* writev */
    case  73: num = 271; break;  /* ppoll (aarch64 has no poll; musl poll()→ppoll) */
    case  36: num = 88; arg1 = arg2; arg2 = arg3; break;  /* symlinkat → symlink (skip dirfd) */
    case  78: num = 89; arg1 = arg2; arg2 = arg3; arg3 = arg4; break;  /* readlinkat → readlink (skip dirfd) */
    case  53: num = 90; arg1 = arg2; arg2 = arg3; break;  /* fchmodat → chmod (skip dirfd+flags) */
    case  54: num = 92; arg1 = arg2; arg2 = arg3; arg3 = arg4; break;  /* fchownat → chown (skip dirfd+flags) */
    case  79: num = 4; arg1 = arg2; arg2 = arg3; break;
                                 /* newfstatat(dirfd,path,statbuf,flags) → stat(path,statbuf).
                                  * musl's stat family (fstatat_kstat) uses this for path-based
                                  * stat on aarch64 (no legacy stat/lstat there). dirfd assumed
                                  * AT_FDCWD/absolute; flags (incl SYMLINK_NOFOLLOW) dropped —
                                  * lstat thus follows, acceptable v1. Was wrongly num=5 (fstat)
                                  * with unshifted args, so ls -l/stat returned garbage/EBADF. */
    case  80: num = 5;   break;  /* fstat */
    case  82: num = 162; break;  /* fsync → sync */
    /* Process */
    case  93: num = 60;  break;  /* exit */
    case  94: num = 231; break;  /* exit_group */
    case  96: num = 218; break;  /* set_tid_address */
    case  99: num = 273; break;  /* set_robust_list */
    case 101: num = 35;  break;  /* nanosleep */
    case 112: num = 227; break;  /* clock_settime */
    case 113: num = 228; break;  /* clock_gettime */
    case 115: num = 35; arg1 = arg3; arg2 = arg4; break; /* clock_nanosleep → nanosleep (skip clk_id+flags) */
    case 124: num = 35;  break;  /* sched_yield → nanosleep(0) */
    case 129: num = 62;  break;  /* kill */
    case 130: num = 130; break;  /* rt_sigsuspend */
    case 131: num = 13;  break;  /* sigaltstack → rt_sigaction (stub) */
    case 134: num = 13;  break;  /* rt_sigaction */
    case 135: num = 14;  break;  /* rt_sigprocmask */
    case 139: num = 15;  break;  /* rt_sigreturn */
    case 160: num = 63;  break;  /* uname */
    case 172: num = 39;  break;  /* getpid */
    case 173: num = 110; break;  /* getppid */
    case 174: num = 102; break;  /* getuid */
    case 175: num = 107; break;  /* geteuid */
    case 176: num = 104; break;  /* getgid */
    case 177: num = 108; break;  /* getegid */
    case 178: num = 39;  break;  /* gettid → getpid */
    case 214: num = 12;  break;  /* brk */
    case 215: num = 11;  break;  /* munmap */
    case 220: num = 56;  break;  /* clone */
    case 221: num = 59;  break;  /* execve */
    case 222: num = 9;   break;  /* mmap */
    case 226: num = 10;  break;  /* mprotect */
    case 233: num = 95;  break;  /* umask */
    case 260: num = 61;  break;  /* wait4 → waitpid */
    case 261: num = 62;  break;  /* kill */
    case  59: num = 293; break;  /* pipe2 (aarch64 __NR_pipe2 == 59; was wrongly
                                  * 281 — so real pipe2 calls fell through to
                                  * internal 59 = execve and returned EFAULT,
                                  * breaking every shell pipeline) */
    case 291: num = 0x7fffffff; break;
                                 /* statx: aarch64 __NR_statx == 291 (NOT arch_prctl, which
                                  * doesn't exist on aarch64). Force an unhandled number so
                                  * dispatch returns ENOSYS and musl falls back to
                                  * newfstatat/fstat above. Was wrongly → arch_prctl(158). */
    /* Directory */
    case  34: num = 83; arg1 = arg2; arg2 = arg3; break; /* mkdirat → mkdir (skip dirfd) */
    case  38: num = 82; arg1 = arg2; arg2 = arg4; break; /* renameat2 → rename (skip dirfds) */
    /* Networking */
    case 198: num = 41;  break;  /* socket */
    case 200: num = 49;  break;  /* bind */
    case 201: num = 50;  break;  /* listen */
    case 202: num = 43;  break;  /* accept (was wrongly mapped to 42=connect) */
    case 203: num = 42;  break;  /* connect */
    case 204: num = 51;  break;  /* getsockname */
    case 206: num = 44;  break;  /* sendto */
    case 207: num = 45;  break;  /* recvfrom */
    case 208: num = 54;  break;  /* setsockopt */
    case 209: num = 55;  break;  /* getsockopt */
    case 210: num = 48;  break;  /* shutdown */
    case 211: num = 46;  break;  /* sendmsg — SCM_RIGHTS fd passing (Lumen surfaces) */
    case 212: num = 47;  break;  /* recvmsg — SCM_RIGHTS fd passing (Lumen surfaces) */
    case 278: num = 318; break;  /* getrandom */
    case 279: num = 319; break;  /* memfd_create — GUI client surfaces (Lumen) */
    case  98: num = 202; break;  /* futex */
    /* Unrecognized numbers fall through — dispatch returns ENOSYS */
    }
#endif
    /* DIAG: record the syscall this task is entering so /proc/tasks can show
     * what a hung/blocked task is stuck in. */
    {
        aegis_task_t *sc_cur = sched_current();
        if (sc_cur) sc_cur->last_syscall = (uint32_t)num;
    }
    switch (num) {
    case  0: return sys_read(arg1, arg2, arg3);
    case 19: return sys_readv(arg1, arg2, arg3);
    case  1: return sys_write(arg1, arg2, arg3);
    case  2: return sys_open(arg1, arg2, arg3);
    case  3: return sys_close(arg1);
    case  4: return sys_stat(arg1, arg2);
    case  5: return sys_fstat(arg1, arg2);
    case  6: return sys_lstat(arg1, arg2);
    case  8: return sys_lseek(arg1, arg2, arg3);
    case 21: return sys_access(arg1, arg2);
    case 35: return sys_nanosleep(arg1, arg2);
    case 10: return sys_mprotect(arg1, arg2, arg3);
    case 16: return sys_ioctl(arg1, arg2, arg3);
    case 22: return sys_pipe2(arg1, 0); /* pipe(2) = pipe2(pipefd, 0) */
    case 32: return sys_dup(arg1);
    case 33: return sys_dup2(arg1, arg2);
    case  9: return sys_mmap(arg1, arg2, arg3, arg4, arg5, arg6);
    case 11: return sys_munmap(arg1, arg2);
    /* madvise(28): advisory only — accept as a no-op success. Aegis has no
     * page-cache RSS to release, so MADV_DONTNEED/FREE/WILLNEED are all benign.
     * Returning ENOSYS (the default) crashes apps that VERIFY the result — e.g.
     * Ladybird's LibGC BlockAllocator decommits heap blocks via
     * madvise(MADV_DONTNEED) and VERIFY_NOT_REACHEs on failure (SIGILL in
     * WebContent, killing the render before it can paint). The GC placement-news
     * reused blocks, so not actually freeing/zeroing the pages is correct. */
    case 28: (void)arg1; (void)arg2; (void)arg3; return 0;
    case 12: return sys_brk(arg1);
    case 72: return sys_fcntl(arg1, arg2, arg3);
    case 13: return sys_rt_sigaction(arg1, arg2, arg3, arg4);
    case 14: return sys_rt_sigprocmask(arg1, arg2, arg3, arg4);
    case 15: return sys_rt_sigreturn(frame);
    case 130: return sys_rt_sigsuspend(arg1, arg2);
    case 20: return sys_writev(arg1, arg2, arg3);
    case 39: return sys_getpid();
    case 56: return sys_clone(frame, arg1, arg2, arg3, arg4, arg5, arg1, arg2, arg3);
    case 57: return sys_fork(frame, arg1, arg2, arg3);
    /* vfork (58): implemented as fork. POSIX permits this — a conforming vfork
     * child only execs or _exits, which a plain fork satisfies. musl's vfork()
     * issues the raw syscall (it does NOT go through clone), so without this
     * case fork-heavy tools that vfork+exec (gcc spawning cc1/as, shells) get
     * ENOSYS. No shared-address-space semantics are provided; none are required
     * by conforming callers. */
    case 58: return sys_vfork(frame, arg1, arg2, arg3);  /* true vfork (CLONE_VM|VFORK) */
    case 59: return sys_execve(frame, arg1, arg2, arg3);
    case 60: return sys_exit(arg1);
    case 61: return sys_waitpid(arg1, arg2, arg3);
    case 62: return sys_kill(arg1, arg2);
    case 360: return sys_setfg(arg1);
    case 364: return sys_auth_session(arg1, arg2);
    case  79: return sys_getcwd(arg1, arg2);
    case  80: return sys_chdir(arg1);
    case 217: return sys_getdents64(arg1, arg2, arg3);
    case 102: return sys_getuid();
    case 104: return sys_getgid();
    case 105: return sys_setuid(arg1);
    case 106: return sys_setgid(arg1);
    /* setgroups(116): Aegis has no supplementary groups — accept as a no-op so
     * initgroups()-based privilege drops (e.g. tinysshd's dropuidgid) succeed. */
    case 116: return 0;
    case 107: return sys_geteuid();
    case 108: return sys_getegid();
    case 110: return sys_getppid();
    case  95: return sys_umask(arg1);
    case  97: return sys_getrlimit(arg1, arg2);
    case 109: return sys_setpgid(arg1, arg2);
    case 111: return sys_getpgrp();
    case 112: return sys_setsid();
    case 121: return sys_getpgid(arg1);
    case  63: return sys_uname(arg1);
    case 170: return sys_sethostname(arg1, arg2);
    case 158: return sys_arch_prctl(arg1, arg2);
    case 186: return sys_gettid();
    case 218: return sys_set_tid_address(arg1);
    case 231: return sys_exit_group(arg1);
    case 273: return sys_set_robust_list(arg1, arg2);
    case 293: return sys_pipe2(arg1, arg2);
    case 290: return sys_eventfd2(arg1, arg2); /* eventfd2 */
    case 284: return sys_eventfd2(arg1, 0);    /* eventfd */
    case  82: return sys_rename(arg1, arg2);
    case  83: return sys_mkdir(arg1, arg2);
    case  84: return sys_rmdir(arg1);
    case  87: return sys_unlink(arg1);
    case  88: return sys_symlink(arg1, arg2);
    case  89: return sys_readlink(arg1, arg2, arg3);
    case  90: return sys_chmod(arg1, arg2);
    case  91: return sys_fchmod(arg1, arg2);
    case  92: return sys_chown(arg1, arg2, arg3);
    case  93: return sys_fchown(arg1, arg2, arg3);
    case  94: return sys_lchown(arg1, arg2, arg3);
    case 257: return sys_openat(arg1, arg2, arg3, arg4);
    case 162: return sys_sync();
    /* fsync(74)/fdatasync(75): flush via the global sync. Per-file flush would
     * be tighter, but sync() is correct (it commits this file too) and matches
     * the aarch64 fsync→sync mapping above. Needed by tinysshd-makekey. */
    case  74: return sys_sync();
    case  75: return sys_sync();
    case 227: return sys_clock_settime(arg1, arg2);
    case 228: return sys_clock_gettime(arg1, arg2);
    case  41: return sys_socket(arg1, arg2, arg3);
    case  42: return sys_connect(arg1, arg2, arg3);
    case  43: return sys_accept(arg1, arg2, arg3);
    /* accept4(fd, addr, addrlen, flags): musl's accept() wrapper issues this on
     * x86_64. sys_accept4 applies SOCK_NONBLOCK/SOCK_CLOEXEC (arg4) to the
     * accepted fd — without it a close-on-exec accepted fd leaked across execve. */
    case 288: return sys_accept4(arg1, arg2, arg3, arg4);
    case  44: return sys_sendto(arg1, arg2, arg3, arg4, arg5, arg6);
    case  45: return sys_recvfrom(arg1, arg2, arg3, arg4, arg5, arg6);
    case  46: return sys_sendmsg(arg1, arg2, arg3);
    case  47: return sys_recvmsg(arg1, arg2, arg3);
    case  48: return sys_shutdown(arg1, arg2);
    case  49: return sys_bind(arg1, arg2, arg3);
    case  50: return sys_listen(arg1, arg2);
    case  51: return sys_getsockname(arg1, arg2, arg3);
    case  52: return sys_getpeername(arg1, arg2, arg3);
    case  53: return sys_socketpair(arg1, arg2, arg3, arg4);
    case  54: return sys_setsockopt(arg1, arg2, arg3, arg4, arg5);
    case  55: return sys_getsockopt(arg1, arg2, arg3, arg4, arg5);
    case   7: return sys_poll(arg1, arg2, arg3);
    case 271: return sys_ppoll(arg1, arg2, arg3, arg4, arg5);
    case  23: return sys_select(arg1, arg2, arg3, arg4, arg5);
    case 291: return sys_epoll_create1(arg1);
    case 233: return sys_epoll_ctl(arg1, arg2, arg3, arg4);
    case 232: return sys_epoll_wait(arg1, arg2, arg3, arg4);
    case 500: return sys_netcfg(arg1, arg2, arg3, arg4);
    case 501: return sys_set_autologin(arg1);
    case 502: return sys_set_ntp(arg1);
    case 503: return sys_audio_volume(arg1);
    case 504: return sys_audio_stop();
    case 505: return sys_audio_position();
    case 318: return sys_getrandom(arg1, arg2, arg3);
    case 202: return sys_futex(arg1, arg2, arg3, arg4, arg5, arg6);
    case 510: return sys_blkdev_list(arg1, arg2);
    case 511: return sys_blkdev_io(arg1, arg2, arg3, arg4, arg5);
    case 512: return sys_gpt_rescan(arg1);
    case 513: return sys_fb_map(arg1);
    case 514: return sys_spawn(arg1, arg2, arg3, arg4, arg5);
    case 515: return sys_fb_flush();
    case 516: return sys_install_commit();
    case 517: return sys_admin_session(arg1);
    case 362: return sys_cap_query(arg1, arg2, arg3);
    /* 363 (sys_cap_grant_runtime) removed: retired in Phase 46c, zero callers,
     * and a live "inject a cap into any PID" primitive is attack surface. */
    case  77: return sys_ftruncate(arg1, arg2);
    case 319: return sys_memfd_create(arg1, arg2);
    case 169: return sys_reboot(arg1);
    /* mlock family (149-152): no-op success. Aegis has no swap — all mapped
     * memory is already resident, so locking/unlocking is meaningless. Returning
     * ENOSYS broke Ladybird's RequestServer spawn (musl posix_spawn/startup
     * calls munlock → ENOSYS → "Could not launch RequestServer"). */
    case 149: return 0;  /* mlock */
    case 150: return 0;  /* munlock */
    case 151: return 0;  /* mlockall */
    case 152: return 0;  /* munlockall */
    case 157: return 0;                       /* prctl — no-op */
    case 160: return 0;                       /* setrlimit — no-op */
    case 239: return 0;                       /* get_mempolicy — no NUMA */
    case  99: return sys_sysinfo(arg1);
    case 204: return sys_sched_getaffinity(arg1, arg2, arg3);
    case 302: return sys_prlimit64(arg1, arg2, arg3, arg4);
    case 294: return sys_inotify_init1(arg1);
    case 254: return sys_inotify_add_watch(arg1, arg2, arg3);
    case  17: return sys_pread64(arg1, arg2, arg3, arg4);
    case 324: return 0;                       /* membarrier — no-op (UP-ish) */
    default:
        return SYS_ERR(ENOSYS);
    }
}
