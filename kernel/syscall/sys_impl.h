/* sys_impl.h — internal header for syscall TU communication.
 * Not exported beyond kernel/syscall/. Each sys_*.c includes this. */
#pragma once

#include "syscall.h"
#include "syscall_util.h"
#include "uaccess.h"
#include "../mm/uaccess_user.h"   /* COPY_FROM_USER / COPY_TO_USER (+ _checked) */
#include "../limits.h"
#include "../include/aegis_errno.h"
#include <stdint.h>
#include <stddef.h>

/* Arch-specific asm labels used by fork/proc stack frame construction.
 * x86-64: isr_post_dispatch (ISR return path after ctx_switch).
 * ARM64: fork_child_return (restores EL0 frame and ERETs). */
#ifdef __aarch64__
extern void fork_child_return(void);
#else
extern void isr_post_dispatch(void);
#endif

/* ── Common defines ─────────────────────────────────────────────────────── */

#ifndef MAP_SHARED
#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define PROT_READ       0x01
#define PROT_WRITE      0x02
#define PROT_EXEC       0x04
#endif

#define WNOHANG  1
#define WUNTRACED 2

#ifndef ARCH_SET_FS
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#endif

/* errno names (ERANGE/EBADF/ENOTDIR/EISDIR/…) come from aegis_errno.h,
 * included above — the single source of truth. */

/* ── Shared types ───────────────────────────────────────────────────────── */

typedef struct {
    uint64_t iov_base;   /* user pointer */
    uint64_t iov_len;
} aegis_iovec_t;

/* linux_dirent64 matches the Linux kernel structure exactly. */
typedef struct {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[1];  /* flexible — actual size determined by d_reclen */
} __attribute__((packed)) linux_dirent64_t;

/* Canonical values live in limits.h (AEGIS_USER_STACK_*); these are the
 * exec/spawn-path aliases. Single-sourced — see proc.c for the init-path ones. */
#define USER_STACK_TOP_EXEC   AEGIS_USER_STACK_TOP
#define USER_STACK_NPAGES     AEGIS_USER_STACK_PAGES
#define USER_STACK_BASE_EXEC  AEGIS_USER_STACK_BASE

/* execve_argbuf_t — argv+envp working storage allocated from kva.
 *
 * FLAT string buffers (not [N][256]): a single argv string can be large — a
 * shell run as a `make` recipe interpreter gets the WHOLE recipe as one arg
 * (`stsh -c "<400-char gcc line>"`), and a link step passes ~150 object args.
 * A [N][256] layout truncated the recipe at 255 bytes (dropping the trailing
 * source file → "gcc: input from standard input") and capped argv at 64. The
 * flat buffer bounds the TOTAL bytes instead, POSIX ARG_MAX style, so it serves
 * both few-long-args and many-short-args. Overflow → copy fails (E2BIG-ish),
 * never silent truncation. kva-allocated: too large for a 4-page kernel stack. */
#define EXECVE_MAX_ARGV      1024
#define EXECVE_MAX_ENV       256
#define EXECVE_ARGV_STRBYTES (128 * 1024)
#define EXECVE_ENV_STRBYTES  (64 * 1024)
typedef struct {
    char     argv_strs[EXECVE_ARGV_STRBYTES];
    char    *argv_ptrs[EXECVE_MAX_ARGV + 1];
    uint64_t str_ptrs[EXECVE_MAX_ARGV];
    char     env_strs[EXECVE_ENV_STRBYTES];
    char    *env_ptrs[EXECVE_MAX_ENV + 1];
    uint64_t env_str_ptrs[EXECVE_MAX_ENV];
} execve_argbuf_t;

/* ceil(sizeof(execve_argbuf_t) / 4096): 131072 + 8200 + 8192 + 65536 + 2056
 * + 2048 = 217104 → 54 pages. */
#define EXECVE_ARGBUF_PAGES 54

/* Value single-sourced in limits.h (AEGIS_MAX_PROCESSES). */
#define MAX_PROCESSES AEGIS_MAX_PROCESSES

/* ── Fork count accessors (sys_process.c owns the state) ─────────────── */
uint32_t proc_fork_count(void);
void     proc_inc_fork_count(void);

/* ── Path helpers (sys_file.c) ──────────────────────────────────────────── */
int copy_path_from_user(char *kpath, uint64_t user_ptr, uint32_t bufsz);
/* Like copy_path_from_user but resolves a relative result against proc->cwd. */
int copy_path_resolved(char *kpath, uint64_t user_ptr, uint32_t bufsz);
int stat_copy_path(uint64_t user_ptr, char *out, uint32_t bufsz);

/* ── sys_io.c ───────────────────────────────────────────────────────────── */
uint64_t sys_write(uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_writev(uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_read(uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_readv(uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_close(uint64_t a1);

/* ── sys_memory.c ───────────────────────────────────────────────────────── */
uint64_t sys_brk(uint64_t a1);
uint64_t sys_mmap(uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5, uint64_t a6);
uint64_t sys_munmap(uint64_t a1, uint64_t a2);
uint64_t sys_mprotect(uint64_t a1, uint64_t a2, uint64_t a3);

/* ── sys_process.c ──────────────────────────────────────────────────────── */
uint64_t sys_exit(uint64_t a1);
uint64_t sys_exit_group(uint64_t a1);
uint64_t sys_clone(syscall_frame_t *frame, uint64_t flags, uint64_t child_stack,
                   uint64_t ptid, uint64_t ctid, uint64_t tls,
                   uint64_t u_rdi, uint64_t u_rsi, uint64_t u_rdx);
uint64_t sys_fork(syscall_frame_t *frame, uint64_t u_rdi, uint64_t u_rsi, uint64_t u_rdx);
uint64_t sys_vfork(syscall_frame_t *frame, uint64_t u_rdi, uint64_t u_rsi, uint64_t u_rdx);
uint64_t sys_waitpid(uint64_t a1, uint64_t a2, uint64_t a3);

/* ── sys_exec.c ────────────────────────────────────────────────────────── */
uint64_t sys_execve(syscall_frame_t *frame,
                    uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_spawn(uint64_t path, uint64_t argv, uint64_t envp, uint64_t stdio_fd, uint64_t cap_mask);

/* ── sys_identity.c ────────────────────────────────────────────────────── */
uint64_t sys_getpid(void);
uint64_t sys_gettid(void);
uint64_t sys_getppid(void);
uint64_t sys_set_tid_address(uint64_t a1);
uint64_t sys_set_robust_list(uint64_t a1, uint64_t a2);
uint64_t sys_arch_prctl(uint64_t a1, uint64_t a2);
uint64_t sys_setuid(uint64_t uid_arg);
uint64_t sys_setgid(uint64_t gid_arg);
uint64_t sys_getuid(void);
uint64_t sys_geteuid(void);
uint64_t sys_getgid(void);
uint64_t sys_getegid(void);
uint64_t sys_reboot(uint64_t cmd);
uint64_t sys_sysinfo(uint64_t buf);
uint64_t sys_sched_getaffinity(uint64_t pid, uint64_t len, uint64_t mask);
uint64_t sys_prlimit64(uint64_t pid, uint64_t res, uint64_t newp, uint64_t oldp);
uint64_t sys_inotify_init1(uint64_t flags);
uint64_t sys_inotify_add_watch(uint64_t fd, uint64_t path, uint64_t mask);
uint64_t sys_pread64(uint64_t fd, uint64_t buf, uint64_t count, uint64_t off);


/* ── sys_adminconf.c ───────────────────────────────────────────────────── */
uint64_t sys_set_autologin(uint64_t enable);
uint64_t sys_set_ntp(uint64_t enable);

/* ── sys_io.c ──────────────────────────────────────────────────────────── */
uint64_t sys_audio_volume(uint64_t pct);
uint64_t sys_audio_stop(void);
uint64_t sys_audio_position(void);

/* ── sys_hostname.c ────────────────────────────────────────────────────── */
uint64_t sys_sethostname(uint64_t name_uptr, uint64_t len);
void     hostname_get(char *out, uint32_t n);
/* hostname_set — kernel-internal setter (no cap check). For boot-time config
 * sources such as fw_cfg opt/aegis.hostname. len clamped to HOSTNAME_MAX. */
void     hostname_set(const char *name, uint32_t len);

/* ── sys_cap.c ─────────────────────────────────────────────────────────── */
uint64_t sys_auth_session(uint64_t uid_arg, uint64_t gid_arg);
/* sys_cap_grant_runtime (363) removed — see kernel/syscall/sys_cap.c. */
uint64_t sys_cap_query(uint64_t pid_arg, uint64_t buf_uptr, uint64_t buflen);

/* ── sys_file.c ─────────────────────────────────────────────────────────── */
uint64_t sys_open(uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_openat(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
uint64_t sys_getcwd(uint64_t a1, uint64_t a2);
uint64_t sys_chdir(uint64_t a1);
uint64_t sys_stat(uint64_t a1, uint64_t a2);
uint64_t sys_fstat(uint64_t a1, uint64_t a2);
uint64_t sys_access(uint64_t a1, uint64_t a2);
uint64_t sys_ioctl(uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_fcntl(uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_lseek(uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_pipe2(uint64_t a1, uint64_t a2);
uint64_t sys_dup(uint64_t a1);
uint64_t sys_dup2(uint64_t a1, uint64_t a2);
uint64_t sys_sync(void);

/* ── sys_time.c ────────────────────────────────────────────────────────── */
uint64_t sys_nanosleep(uint64_t a1, uint64_t a2);
uint64_t sys_clock_gettime(uint64_t clk_id, uint64_t timespec_uptr);
uint64_t sys_clock_settime(uint64_t clk_id, uint64_t timespec_uptr);

/* ── sys_dir.c ─────────────────────────────────────────────────────────── */
uint64_t sys_getdents64(uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t sys_mkdir(uint64_t a1, uint64_t a2);
uint64_t sys_rmdir(uint64_t a1);
uint64_t sys_unlink(uint64_t a1);
uint64_t sys_rename(uint64_t a1, uint64_t a2);

/* ── sys_meta.c ────────────────────────────────────────────────────────── */
uint64_t sys_lstat(uint64_t arg1, uint64_t arg2);
uint64_t sys_symlink(uint64_t arg1, uint64_t arg2);
uint64_t sys_readlink(uint64_t arg1, uint64_t arg2, uint64_t arg3);
uint64_t sys_chmod(uint64_t arg1, uint64_t arg2);
uint64_t sys_fchmod(uint64_t arg1, uint64_t arg2);
uint64_t sys_chown(uint64_t arg1, uint64_t arg2, uint64_t arg3);
uint64_t sys_fchown(uint64_t arg1, uint64_t arg2, uint64_t arg3);
uint64_t sys_lchown(uint64_t arg1, uint64_t arg2, uint64_t arg3);

/* ── sys_signal.c ───────────────────────────────────────────────────────── */
uint64_t sys_rt_sigaction(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
uint64_t sys_rt_sigprocmask(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
uint64_t sys_rt_sigreturn(syscall_frame_t *frame);
uint64_t sys_rt_sigsuspend(uint64_t a1, uint64_t a2);
uint64_t sys_kill(uint64_t a1, uint64_t a2);
uint64_t sys_setfg(uint64_t a1);

/* ── sys_socket.c ───────────────────────────────────────────────────────── */
uint64_t sys_socket(uint64_t domain, uint64_t type, uint64_t proto);
uint64_t sys_bind(uint64_t fd, uint64_t addr, uint64_t addrlen);
uint64_t sys_listen(uint64_t fd, uint64_t backlog);
uint64_t sys_accept(uint64_t fd, uint64_t addr, uint64_t addrlen);
uint64_t sys_accept4(uint64_t fd, uint64_t addr, uint64_t addrlen, uint64_t flags);
uint64_t sys_connect(uint64_t fd, uint64_t addr, uint64_t addrlen);
uint64_t sys_sendto(uint64_t fd, uint64_t buf, uint64_t len,
                    uint64_t flags, uint64_t addr, uint64_t addrlen);
uint64_t sys_recvfrom(uint64_t fd, uint64_t buf, uint64_t len,
                      uint64_t flags, uint64_t addr, uint64_t addrlen);
uint64_t sys_sendmsg(uint64_t fd, uint64_t msg, uint64_t flags);
uint64_t sys_recvmsg(uint64_t fd, uint64_t msg, uint64_t flags);
uint64_t sys_shutdown(uint64_t fd, uint64_t how);
uint64_t sys_getsockname(uint64_t fd, uint64_t addr, uint64_t addrlen);
uint64_t sys_getpeername(uint64_t fd, uint64_t addr, uint64_t addrlen);
uint64_t sys_socketpair(uint64_t domain, uint64_t type, uint64_t proto, uint64_t sv);
uint64_t sys_setsockopt(uint64_t fd, uint64_t level, uint64_t optname,
                        uint64_t optval, uint64_t optlen);
uint64_t sys_getsockopt(uint64_t fd, uint64_t level, uint64_t optname,
                        uint64_t optval, uint64_t optlen);
uint64_t sys_poll(uint64_t fds, uint64_t nfds, uint64_t timeout_ms);
uint64_t sys_ppoll(uint64_t fds, uint64_t nfds, uint64_t ts_ptr,
                   uint64_t sigmask, uint64_t sigsetsize);
uint64_t sys_select(uint64_t nfds, uint64_t rfds, uint64_t wfds,
                    uint64_t efds, uint64_t timeout);
uint64_t sys_pselect6(uint64_t nfds, uint64_t rfds, uint64_t wfds,
                      uint64_t efds, uint64_t ts_ptr, uint64_t sigmask);
uint64_t sys_epoll_create1(uint64_t flags);
uint64_t sys_epoll_ctl(uint64_t epfd, uint64_t op, uint64_t fd, uint64_t event);
uint64_t sys_epoll_wait(uint64_t epfd, uint64_t events,
                        uint64_t maxevents, uint64_t timeout_ms);
uint64_t sys_netcfg(uint64_t op, uint64_t arg1, uint64_t arg2, uint64_t arg3);

/* ── Process group / session / resource syscalls (sys_identity.c) ───────── */
uint64_t sys_setpgid(uint64_t pid_arg, uint64_t pgid_arg);
uint64_t sys_getpgrp(void);
uint64_t sys_setsid(void);
uint64_t sys_getpgid(uint64_t pid_arg);
uint64_t sys_umask(uint64_t mask);
uint64_t sys_getrlimit(uint64_t resource, uint64_t rlim_ptr);
uint64_t sys_uname(uint64_t buf_uptr);

/* ── sys_random.c ──────────────────────────────────────────────────────── */
uint64_t sys_getrandom(uint64_t buf, uint64_t buflen, uint64_t flags);

/* ── sys_disk.c ────────────────────────────────────────────────────────── */
uint64_t sys_blkdev_list(uint64_t arg1, uint64_t arg2);
uint64_t sys_blkdev_io(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                        uint64_t arg4, uint64_t arg5);
uint64_t sys_gpt_rescan(uint64_t arg1);
uint64_t sys_fb_map(uint64_t arg1);
uint64_t sys_fb_flush(void);
uint64_t sys_install_commit(void);
uint64_t sys_admin_session(uint64_t on);

/* ── memfd / ftruncate (sys_memory.c) ──────────────────────────────────── */
uint64_t sys_memfd_create(uint64_t name, uint64_t flags);
uint64_t sys_ftruncate(uint64_t fd, uint64_t length);

/* ── futex.c ───────────────────────────────────────────────────────────── */
uint64_t sys_futex(uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5, uint64_t a6);
