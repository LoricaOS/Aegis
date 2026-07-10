/* sys_file.c — File and filesystem syscalls */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
#include "ext2.h"
#include "pipe.h"
#include "kbd_vfs.h"
#include "tty.h"
#include "kva.h"
#include "socket.h"
#include "unix_socket.h"
#include "pty.h"
#include "nvme.h"

/*
 * sys_open — syscall 2
 *
 * arg1 = user pointer to null-terminated path string
 * arg2 = flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND, etc.)
 * arg3 = mode (applied only when O_CREAT actually creates the file)
 *
 * Returns fd on success, negative errno on failure.
 */
uint64_t
sys_open(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_OPEN, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    /* arg3 = mode: applied only when O_CREAT actually creates the file.
     * Threaded through so e.g. herald-installed executables land 0755. */
    if (!user_ptr_valid(arg1, 1))
        return SYS_ERR(EFAULT);
    /* Copy byte-by-byte until null terminator — never read past the string.
     * A bulk 256-byte copy can cross a page boundary if the path string is
     * placed near the end of the mapped user stack (e.g. argv[1] from execve
     * is placed within 256 bytes of USER_STACK_TOP), causing a kernel #PF.
     * Stopping at the null avoids reading into the unmapped page above the stack. */
    char kpath[256];
    {
        uint64_t i;
        for (i = 0; i < 255; i++) {
            if (!user_ptr_valid(arg1 + i, 1))
                return SYS_ERR(EFAULT);
            char c;
            copy_from_user(&c, (const void *)(uintptr_t)(arg1 + i), 1);
            kpath[i] = c;
            if (c == '\0') break;
        }
        kpath[255] = '\0';
    }
    /* Resolve relative paths against proc->cwd.
     * "."       → cwd itself (e.g. "/")
     * "bin"     → cwd + "/" + "bin" (e.g. "/bin")
     * Absolute paths (start with '/') pass through unchanged. */
    if (kpath[0] != '/') {
        char resolved[256];
        uint64_t cwdlen = 0;
        while (proc->cwd[cwdlen]) cwdlen++;
        if (kpath[0] == '.' && kpath[1] == '\0') {
            /* "." — use cwd directly */
            __builtin_memcpy(resolved, proc->cwd, cwdlen + 1);
        } else {
            uint64_t pathlen = 0;
            while (kpath[pathlen]) pathlen++;
            /* Insert separator unless cwd already ends with '/' */
            uint64_t sep = (cwdlen > 0 && proc->cwd[cwdlen - 1] == '/') ? 0u : 1u;
            if (cwdlen + sep + pathlen >= 256)
                return SYS_ERR(ENAMETOOLONG);
            __builtin_memcpy(resolved, proc->cwd, cwdlen);
            if (sep) resolved[cwdlen] = '/';
            __builtin_memcpy(resolved + cwdlen + sep, kpath, pathlen + 1);
        }
        __builtin_memcpy(kpath, resolved, sizeof(kpath));
    }
    /* Normalize absolute path: collapse "//", ".", ".." so that path
     * traversal (e.g. "/etc/../etc/shadow") cannot bypass the shadow
     * capability gate below.  Defense-in-depth — the primary check is
     * inode-based in vfs_open (catches symlinks too). */
    {
        char norm[256];
        uint64_t ni = 0;
        const char *p = kpath;
        if (*p == '/') {
            norm[ni++] = '/';
            p++;
        }
        while (*p) {
            while (*p == '/') p++;   /* collapse multiple slashes */
            if (*p == '\0') break;
            const char *seg = p;
            uint64_t slen = 0;
            while (*p && *p != '/') { p++; slen++; }
            if (slen == 1 && seg[0] == '.') {
                continue;  /* "." — skip */
            }
            if (slen == 2 && seg[0] == '.' && seg[1] == '.') {
                /* ".." — pop last component */
                if (ni > 1) {
                    ni--;  /* remove trailing char */
                    while (ni > 0 && norm[ni - 1] != '/') ni--;
                }
                continue;
            }
            if (ni > 1) norm[ni++] = '/';
            for (uint64_t k = 0; k < slen && ni < 254; k++)
                norm[ni++] = seg[k];
        }
        if (ni == 0) norm[ni++] = '/';
        norm[ni] = '\0';
        for (uint64_t k = 0; k <= ni; k++) kpath[k] = norm[k];
    }

    uint64_t fd;
    for (fd = 0; fd < PROC_MAX_FDS; fd++)
        if (!proc->fd_table->fds[fd].ops) break;
    if (fd == PROC_MAX_FDS)
        return SYS_ERR(EMFILE);

    /* /etc/shadow and /etc/aegis/admin read gate: both require CAP_KIND_AUTH
     * regardless of uid.  There is no ambient root authority on Aegis — uid=0
     * is cosmetic.  /etc/aegis/admin holds the admin-elevation credential hash
     * (the sole gate on admin_session / CAP_KIND_INSTALL), so it is at least as
     * sensitive as a shadow entry and must not be world-readable.  Only the
     * single admin credential file is gated here — the rest of /etc/aegis
     * (caps.d/, anchors) stays readable.  This pre-resolution check catches
     * direct path access and normalized traversals (../etc/shadow); symlink
     * bypasses are caught by the post-resolution inode check in vfs_open. */
    {
        static const char shadow_path[] = "/etc/shadow";
        static const char admin_path[]  = "/etc/aegis/admin";
        int shadow_match = 1, admin_match = 1;
        for (uint64_t si = 0; si < sizeof(shadow_path); si++) {
            if (kpath[si] != shadow_path[si]) { shadow_match = 0; break; }
        }
        for (uint64_t si = 0; si < sizeof(admin_path); si++) {
            if (kpath[si] != admin_path[si]) { admin_match = 0; break; }
        }
        if (shadow_match || admin_match) {
            if (cap_check(proc->caps, CAP_TABLE_SIZE,
                          CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
                return SYS_ERR(EACCES);
        }
    }

    /* Install-tree mutation gate: a ring-3 process that creates or writes a
     * file under /apps or /etc/aegis must hold CAP_KIND_INSTALL. Read-only
     * opens are exempt. (Syscall handlers run only in user context; boot-time
     * fs work goes through vfs_open directly, not this path.) */
    {
        int mutating = (arg2 & 1) /* O_WRONLY */ || (arg2 & 2) /* O_RDWR */ ||
                       (arg2 & VFS_O_CREAT) || (arg2 & VFS_O_TRUNC) ||
                       (arg2 & VFS_O_APPEND);
        if (mutating && cap_path_is_protected(kpath) &&
            cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                      CAP_RIGHTS_READ) != 0)
            return SYS_ERR(EPERM); /* EPERM — installing into the system tree needs CAP_KIND_INSTALL */
    }

    int r = vfs_open(kpath, (int)arg2, (uint16_t)(arg3 & 0xFFF),
                     &proc->fd_table->fds[fd]);
    if (r < 0)
        return (uint64_t)(int64_t)r;
    /* Store open flags in the fd slot for F_GETFL */
    proc->fd_table->fds[fd].flags = (uint32_t)arg2;
    /* Propagate O_CLOEXEC from open flags to fd flags */
    if (arg2 & VFS_O_CLOEXEC)
        proc->fd_table->fds[fd].flags |= VFS_FD_CLOEXEC;
    return fd;
}

/*
 * sys_openat — syscall 257
 *
 * arg1 = dirfd (AT_FDCWD = -100 means resolve relative to CWD)
 * arg2 = user pointer to path
 * arg3 = flags
 * arg4 = mode
 *
 * We only support AT_FDCWD (absolute paths and CWD-relative).  Paths starting
 * with '/' are absolute and dirfd is irrelevant.  For now we forward to
 * sys_open unconditionally — the shell only calls openat with AT_FDCWD.
 */
uint64_t
sys_openat(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    (void)arg1;  /* dirfd — only AT_FDCWD (-100) or absolute paths handled */
    return sys_open(arg2, arg3, arg4);
}

/* ── stat / access / nanosleep ────────────────────────────────────────── */

int
stat_copy_path(uint64_t user_ptr, char *out, uint32_t bufsz)
{
    uint32_t i;
    /* user_ptr_valid walks page tables; cache the validated page so a
     * path costs at most two walks, not one per byte. */
    uint64_t valid_pg = ~0ULL;
    for (i = 0; i < bufsz - 1; i++) {
        uint8_t c;
        uint64_t pg = (user_ptr + i) & ~0xFFFULL;
        if (pg != valid_pg) {
            if (!user_ptr_valid(user_ptr + i, 1))
                return -EFAULT;
            valid_pg = pg;
        }
        copy_from_user(&c, (const void *)(uintptr_t)(user_ptr + i), 1);
        out[i] = (char)c;
        if (c == 0) {
            /* Resolve relative paths against proc->cwd, matching sys_open, so
             * stat/access/lstat work after chdir (tinysshd stats a relative
             * "authorized_keys"). */
            if (out[0] != '/' && out[0] != '\0') {
                aegis_process_t *proc = current_proc();
                char tmp[256];
                uint32_t n = 0, k;
                for (k = 0; proc->cwd[k] && n < sizeof(tmp) - 1; k++)
                    tmp[n++] = proc->cwd[k];
                if (n == 0)                          tmp[n++] = '/';
                if (tmp[n - 1] != '/' && n < sizeof(tmp) - 1) tmp[n++] = '/';
                for (k = 0; out[k] && n < sizeof(tmp) - 1; k++)
                    tmp[n++] = out[k];
                tmp[n] = '\0';
                for (k = 0; k <= n && k < bufsz; k++) out[k] = tmp[k];
                out[bufsz - 1] = '\0';
            }
            return 0;
        }
    }
    out[bufsz - 1] = '\0';
    /* Loop completed without finding null — path was truncated */
    return -ENAMETOOLONG;
}

/*
 * sys_getcwd — syscall 79
 *
 * arg1 = user buffer pointer
 * arg2 = buffer size in bytes
 *
 * Copies proc->cwd (including null terminator) into the user buffer.
 * Returns the byte count (including null terminator) on success — Linux
 * sys_getcwd ABI (the libc wrapper returns the pointer, the raw syscall
 * returns the length).  -ERANGE if the buffer is too small, -EFAULT if
 * the pointer is invalid.
 */
uint64_t
sys_getcwd(uint64_t buf_ptr, uint64_t size)
{
    aegis_process_t *proc = current_proc();
    uint64_t len = 0;
    while (proc->cwd[len]) len++;
    len++;  /* include null terminator */
    if (size < len) return SYS_ERR(ERANGE);
    if (!user_ptr_valid(buf_ptr, len)) return SYS_ERR(EFAULT);
    copy_to_user((void *)(uintptr_t)buf_ptr, proc->cwd, len);
    return len;  /* raw syscall returns byte count, not pointer */
}

/*
 * sys_chdir — syscall 80
 *
 * arg1 = user pointer to null-terminated path
 *
 * Copies path to kernel buffer, validates it exists and is a directory
 * via vfs_stat_path, then updates proc->cwd.
 * Returns 0 on success, -EFAULT if pointer invalid, -ENOENT if not found,
 * -ENOTDIR if path exists but is not a directory.
 */
uint64_t
sys_chdir(uint64_t path_ptr)
{
    aegis_process_t *proc = current_proc();
    if (!user_ptr_valid(path_ptr, 1)) return SYS_ERR(EFAULT);

    char kpath[256];
    uint64_t i;
    for (i = 0; i < 255; i++) {
        if (!user_ptr_valid(path_ptr + i, 1))
            return SYS_ERR(EFAULT);
        char c;
        copy_from_user(&c, (const void *)(uintptr_t)(path_ptr + i), 1);
        kpath[i] = c;
        if (c == '\0') break;
    }
    kpath[255] = '\0';

    /* Resolve a relative path against proc->cwd. sys_chdir previously stat'd
     * the raw path and stored it verbatim — so chdir(".ssh") stat'd ".ssh"
     * relative to nothing and failed. tinysshd does exactly that. (No "."/".."
     * normalization yet — not needed by current callers.) */
    char apath[256];
    if (kpath[0] != '/') {
        uint64_t n = 0;
        for (i = 0; proc->cwd[i] && n < 255; i++) apath[n++] = proc->cwd[i];
        if (n == 0)                       apath[n++] = '/';
        if (apath[n - 1] != '/' && n < 255) apath[n++] = '/';
        for (i = 0; kpath[i] && n < 255; i++) apath[n++] = kpath[i];
        apath[n] = '\0';
    } else {
        for (i = 0; i < 256; i++) { apath[i] = kpath[i]; if (!kpath[i]) break; }
        apath[255] = '\0';
    }

    /* Validate path exists and is a directory */
    k_stat_t st;
    if (vfs_stat_path(apath, &st) != 0) return SYS_ERR(ENOENT);
    if ((st.st_mode & S_IFMT) != S_IFDIR) return SYS_ERR(ENOTDIR);

    for (i = 0; i < 256; i++) {
        proc->cwd[i] = apath[i];
        if (apath[i] == '\0') break;
    }
    return 0;
}

/* On aarch64 musl's `struct kstat` (arch/aarch64/kstat.h) orders the header
 * fields differently from x86-64: st_mode(16)/st_nlink(20) instead of
 * st_nlink(16)/st_mode(24), no 32-bit __pad0, and uid/gid/rdev shifted up.
 * k_stat_t matches the x86-64 layout (what x86 musl reads directly), so the
 * stat syscalls must repack into the aarch64 layout before copying out —
 * otherwise ls -l shows shuffled fields and stat/find deref the garbage and
 * crash. Fields from st_size onward are identical in both layouts. */
#ifdef __aarch64__
struct kstat_arm64 {
    uint64_t st_dev, st_ino;
    uint32_t st_mode, st_nlink, st_uid, st_gid;
    uint64_t st_rdev, __pad;
    int64_t  st_size;
    int32_t  st_blksize, __pad2;
    int64_t  st_blocks;
    int64_t  st_atime, st_atime_nsec, st_mtime, st_mtime_nsec, st_ctime, st_ctime_nsec;
    uint32_t __unused[2];
};
#endif

/* emit_stat — copy k_stat_t out to the user's struct stat, repacked to the
 * per-arch layout musl expects. Returns 0 or SYS_ERR(EFAULT). */
static uint64_t
emit_stat(uint64_t uptr, const k_stat_t *ks)
{
#ifdef __aarch64__
    struct kstat_arm64 a;
    __builtin_memset(&a, 0, sizeof(a));
    a.st_dev = ks->st_dev; a.st_ino = ks->st_ino;
    a.st_mode = ks->st_mode; a.st_nlink = (uint32_t)ks->st_nlink;
    a.st_uid = ks->st_uid; a.st_gid = ks->st_gid; a.st_rdev = ks->st_rdev;
    a.st_size = ks->st_size; a.st_blksize = (int32_t)ks->st_blksize;
    a.st_blocks = ks->st_blocks;
    a.st_atime = ks->st_atime; a.st_atime_nsec = ks->st_atime_nsec;
    a.st_mtime = ks->st_mtime; a.st_mtime_nsec = ks->st_mtime_nsec;
    a.st_ctime = ks->st_ctime; a.st_ctime_nsec = ks->st_ctime_nsec;
    if (copy_to_user((void *)(uintptr_t)uptr, &a, sizeof(a)) != 0)
        return SYS_ERR(EFAULT);
    return 0;
#else
    if (copy_to_user((void *)(uintptr_t)uptr, ks, sizeof(*ks)) != 0)
        return SYS_ERR(EFAULT);
    return 0;
#endif
}

/*
 * sys_stat — syscall 4
 * arg1 = user pointer to path string (null-terminated, max 256 bytes)
 * arg2 = user pointer to struct stat output buffer
 */
uint64_t
sys_stat(uint64_t arg1, uint64_t arg2)
{
    char path[256];
    if (stat_copy_path(arg1, path, sizeof(path)) != 0)
        return SYS_ERR(EFAULT);

    k_stat_t ks;
    int rc = vfs_stat_path(path, &ks);
    if (rc != 0) return SYS_ERR(ENOENT);

    return emit_stat(arg2, &ks);
}

/*
 * sys_fstat — syscall 5
 * arg1 = fd, arg2 = user pointer to struct stat output buffer
 */
uint64_t
sys_fstat(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    if (arg1 >= PROC_MAX_FDS) return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[arg1];
    if (!f->ops) return SYS_ERR(EBADF);

    k_stat_t ks;
    __builtin_memset(&ks, 0, sizeof(ks));

    if (f->ops->stat) {
        int rc = f->ops->stat(f->priv, &ks);
        if (rc != 0) return SYS_ERR(EIO);
    } else {
        /* Synthesize minimal stat for drivers without a stat hook. */
        ks.st_mode  = S_IFREG | 0444;
        ks.st_size  = (int64_t)f->size;
        ks.st_dev   = 1;
        ks.st_nlink = 1;
    }

    return emit_stat(arg2, &ks);
}

/*
 * sys_access — syscall 21
 * arg1 = user pointer to path string, arg2 = mode (F_OK=0, R_OK=4, W_OK=2, X_OK=1)
 * Returns 0 if accessible, -ENOENT if not found, -EACCES if permission denied.
 */
uint64_t
sys_access(uint64_t arg1, uint64_t arg2)
{
    char path[256];
    if (stat_copy_path(arg1, path, sizeof(path)) != 0)
        return SYS_ERR(EFAULT);
    k_stat_t ks;
    if (vfs_stat_path(path, &ks) != 0)
        return SYS_ERR(ENOENT);

    /* F_OK (mode==0): existence check only */
    if (arg2 == 0) return 0;

    /* For ext2 files, check permission bits via ext2_check_perm.
     * Non-ext2 files (procfs, /dev, initrd): just check existence. */
    uint32_t ino = 0;
    if (ext2_open(path, &ino) == 0) {
        aegis_process_t *proc = current_proc();
        int want = 0;
        if (arg2 & 4) want |= 4; /* R_OK */
        if (arg2 & 2) want |= 2; /* W_OK */
        if (arg2 & 1) want |= 1; /* X_OK */
        int r = ext2_check_perm(ino, (uint16_t)proc->uid, (uint16_t)proc->gid, want);
        if (r != 0) return SYS_ERR(EACCES);
    }
    return 0;
}

/*
 * sys_ioctl — syscall 16
 *
 * arg1 = fd, arg2 = request, arg3 = arg (user pointer or value)
 *
 * TIOCGWINSZ (0x5413): return {rows=25, cols=80, 0, 0}
 * TIOCGPGRP  (0x540F): return foreground PID
 * FIONREAD   (0x541B): for pipes, return bytes available; others return 0
 * All others: return -ENOTTY
 */
uint64_t
sys_ioctl(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();
    if (arg1 >= PROC_MAX_FDS) return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[arg1];
    if (!f->ops) return SYS_ERR(EBADF);

    /* Determine if this fd has an associated tty_t */
    tty_t *tty = (tty_t *)0;
    if (kbd_vfs_is_tty(f))
        tty = tty_console();
    else if (pty_is_slave(f))
        tty = pty_get_tty(f);

    switch ((uint32_t)arg2) {
    case TIOCGWINSZ: {
        if (tty)
            return (uint64_t)(int64_t)tty_ioctl(tty, (uint32_t)arg2, arg3);
        uint16_t ws[4] = { 25, 80, 0, 0 };
        if (!user_ptr_valid(arg3, sizeof(ws)))
            return SYS_ERR(EFAULT);
        copy_to_user((void *)(uintptr_t)arg3, ws, sizeof(ws));
        return 0;
    }
    case TIOCGPGRP:
        if (!tty) return SYS_ERR(ENOTTY);
        return (uint64_t)(int64_t)tty_ioctl(tty, (uint32_t)arg2, arg3);
    case TCGETS:
        if (!tty) return SYS_ERR(ENOTTY);
        return (uint64_t)(int64_t)tty_ioctl(tty, (uint32_t)arg2, arg3);
    case TCSETS:
    case TCSETSW:
    case TCSETSF:
        if (!tty) return SYS_ERR(ENOTTY);
        return (uint64_t)(int64_t)tty_ioctl(tty, (uint32_t)arg2, arg3);
    case TIOCSPGRP:
        if (!tty) return SYS_ERR(ENOTTY);
        return (uint64_t)(int64_t)tty_ioctl(tty, (uint32_t)arg2, arg3);
    case TIOCSCTTY:
        if (!tty) return SYS_ERR(ENOTTY);
        return (uint64_t)(int64_t)tty_ioctl(tty, (uint32_t)arg2, arg3);
    case TIOCSWINSZ: { /* 0x5414 */
        tty_t *ws_tty = tty;
        if (pty_is_master(f))
            ws_tty = &((pty_pair_t *)f->priv)->tty;
        if (!ws_tty) return SYS_ERR(ENOTTY);
        return (uint64_t)(int64_t)tty_ioctl(ws_tty, (uint32_t)arg2, arg3);
    }
    case 0x541BU: { /* FIONREAD — bytes available in pipe */
        int32_t avail = 0;
        if (f->ops == &g_pipe_read_ops) {
            pipe_t *p = (pipe_t *)f->priv;
            avail = (int32_t)p->count;
        }
        COPY_TO_USER(arg3, &avail);
        return 0;
    }
    case 0x5421U: { /* FIONBIO — set/clear O_NONBLOCK from *(int *)arg3.
                     * Equivalent to fcntl(F_SETFL, O_NONBLOCK); musl/glibc
                     * apps (e.g. Ladybird's LocalSocket::set_blocking) use this
                     * instead of fcntl. Returning ENOTTY here aborted every
                     * such socket setup. Mirror sys_fcntl's F_SETFL path so the
                     * fd flag AND the per-socket nonblocking flag both update. */
        int on = 0;
        COPY_FROM_USER(&on, arg3);
        if (on)
            f->flags |= 0x800U;
        else
            f->flags &= ~0x800U;
        {
            uint32_t sid2 = sock_id_from_fd((int)arg1, proc);
            if (sid2 != SOCK_NONE) {
                sock_t *sk = sock_get(sid2);
                if (sk) sk->nonblocking = on ? 1 : 0;
            }
            uint32_t uid2 = unix_sock_id_from_fd((int)arg1, proc);
            if (uid2 != UNIX_NONE) {
                unix_sock_t *us = unix_sock_get(uid2);
                if (us) us->nonblocking = on ? 1 : 0;
            }
        }
        return 0;
    }
    case 0x80045430U: { /* TIOCGPTN — get PTY number */
        if (!pty_is_master(f))
            return SYS_ERR(ENOTTY);
        pty_pair_t *pair = (pty_pair_t *)f->priv;
        uint32_t n = (uint32_t)pair->index;
        COPY_TO_USER(arg3, &n);
        return 0;
    }
    case 0x40045431U: { /* TIOCSPTLCK — lock/unlock PTY */
        if (!pty_is_master(f))
            return SYS_ERR(ENOTTY);
        pty_pair_t *pair = (pty_pair_t *)f->priv;
        uint32_t val;
        COPY_FROM_USER(&val, arg3);
        pair->locked = val ? 1 : 0;
        return 0;
    }
    default:
        return SYS_ERR(ENOTTY);
    }
}

/*
 * sys_fcntl — syscall 72
 *
 * arg1 = fd, arg2 = cmd, arg3 = arg
 *
 * F_GETFL (3): return f->flags
 * F_SETFL (4): store arg & O_NONBLOCK into f->flags (O_NONBLOCK=0x800)
 * F_GETFD (1): return FD_CLOEXEC (1) if set, 0 otherwise
 * F_SETFD (2): set or clear FD_CLOEXEC based on arg3 bit 0
 * F_DUPFD (0): find lowest fd >= arg, dup into it
 * All others: return -EINVAL
 */
uint64_t
sys_fcntl(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();
    if (arg1 >= PROC_MAX_FDS) return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[arg1];
    if (!f->ops) return SYS_ERR(EBADF);

    switch (arg2) {
    case 1: /* F_GETFD — return FD_CLOEXEC (1) if set, 0 otherwise */
        return (proc->fd_table->fds[arg1].flags & VFS_FD_CLOEXEC) ? 1 : 0;
    case 2: /* F_SETFD — set or clear FD_CLOEXEC based on arg3 bit 0 (FD_CLOEXEC=1) */
        if (arg3 & 1)
            proc->fd_table->fds[arg1].flags |= VFS_FD_CLOEXEC;
        else
            proc->fd_table->fds[arg1].flags &= ~VFS_FD_CLOEXEC;
        return 0;
    case 3: /* F_GETFL */ return (uint64_t)f->flags;
    case 4: /* F_SETFL */
        f->flags = (f->flags & ~0x800U) | ((uint32_t)arg3 & 0x800U);
        /* Also update socket nonblocking flag if fd is a socket */
        {
            uint32_t sid2 = sock_id_from_fd((int)arg1, proc);
            if (sid2 != SOCK_NONE) {
                sock_t *sk = sock_get(sid2);
                if (sk)
                    sk->nonblocking = (arg3 & 0x800U) ? 1 : 0;
            }
            uint32_t uid2 = unix_sock_id_from_fd((int)arg1, proc);
            if (uid2 != UNIX_NONE) {
                unix_sock_t *us = unix_sock_get(uid2);
                if (us)
                    us->nonblocking = (arg3 & 0x800U) ? 1 : 0;
            }
        }
        return 0;
    case 0:   /* F_DUPFD */
    case 1030: { /* F_DUPFD_CLOEXEC (0x406) — same as F_DUPFD + set FD_CLOEXEC */
        uint32_t new_fd;
        for (new_fd = (uint32_t)arg3; new_fd < PROC_MAX_FDS; new_fd++) {
            if (!proc->fd_table->fds[new_fd].ops) break;
        }
        if (new_fd >= PROC_MAX_FDS) return SYS_ERR(EMFILE);
        proc->fd_table->fds[new_fd] = *f; /* struct copy */
        proc->fd_table->fds[new_fd].flags &= ~VFS_FD_CLOEXEC;   /* clear first */
        if (arg2 == 1030) proc->fd_table->fds[new_fd].flags |= VFS_FD_CLOEXEC;
        if (f->ops->dup) f->ops->dup(f->priv);
        return (uint64_t)new_fd;
    }
    /* Advisory record locking. Aegis has no multi-process file locking, but
     * SQLite (Ladybird's cookie/storage store) locks its DB with fcntl and
     * reports "disk I/O error" if the call returns EINVAL. Grant locks as
     * no-ops and report GETLK as unlocked — correct for the only pattern here,
     * a single writer owning its own database.
     * ponytail: no-op locks; add real record locking only if concurrent
     * writers ever contend on one file. */
    case 6:   /* F_SETLK  — pretend the lock was acquired */
    case 7:   /* F_SETLKW */
    case 37:  /* F_OFD_SETLK  — open-file-description lock (SQLite WAL); same no-op */
    case 38:  /* F_OFD_SETLKW */
        return 0;
    case 5:   /* F_GETLK  — report no conflicting lock (l_type = F_UNLCK) */
    case 36: { /* F_OFD_GETLK */
        short unlck = 2; /* F_UNLCK */
        if (arg3) {
            if (!user_ptr_valid(arg3, sizeof(unlck)))
                return SYS_ERR(EFAULT);
            copy_to_user((void *)(uintptr_t)arg3, &unlck, sizeof(unlck));
        }
        return 0;
    }
    default:
        return SYS_ERR(EINVAL);
    }
}

/*
 * sys_lseek — syscall 8
 *
 * arg1 = fd, arg2 = offset, arg3 = whence (SEEK_SET=0, SEEK_CUR=1, SEEK_END=2)
 *
 * For non-seekable fds (pipes, console, kbd): return -ESPIPE (-29).
 * For initrd files: update f->offset accordingly and return new offset.
 * Kernel uses f->offset for position tracking; lseek must keep it consistent.
 */
uint64_t
sys_lseek(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();
    if (arg1 >= PROC_MAX_FDS || !proc->fd_table->fds[arg1].ops)
        return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[arg1];

    /* Stream fds (pipe/console/kbd/char devices) are non-seekable: ESPIPE.
     * We only need to disambiguate at size==0 — a non-empty fd is already a
     * real file. A size-0 fd is a stream UNLESS its driver marks itself
     * seekable (a freshly-created regular file, e.g. an .o `as` is about to
     * seek around while writing the ELF). */
    if (f->size == 0 && !(f->ops && f->ops->seekable))
        return SYS_ERR(ESPIPE);   /* -ESPIPE */

    int64_t new_off;
    int64_t off = (int64_t)arg2;
    if (arg3 == 0)        /* SEEK_SET */
        new_off = off;
    else if (arg3 == 1) { /* SEEK_CUR */
        /* S3: Safe signed overflow checks for SEEK_CUR.
         * The old guards used 0x8000000000000000LL which is UB. */
        int64_t cur = (int64_t)f->offset;
        if (off > 0 && cur > (int64_t)0x7FFFFFFFFFFFFFFFLL - off)
            return (uint64_t)(int64_t)-22;  /* -EINVAL */
        if (off < 0 && cur < (int64_t)(-0x7FFFFFFFFFFFFFFFLL - 1) - off)
            return (uint64_t)(int64_t)-22;  /* -EINVAL */
        new_off = (int64_t)f->offset + off;
    } else if (arg3 == 2) { /* SEEK_END */
        /* Guard against signed overflow: f->size is uint64_t.
         * Reject if f->size itself exceeds INT64_MAX, or if adding a positive
         * off would push the result past INT64_MAX. */
        if (f->size > (uint64_t)0x7FFFFFFFFFFFFFFFLL ||
            (off > 0 && (int64_t)f->size > (int64_t)0x7FFFFFFFFFFFFFFFLL - off))
            return SYS_ERR(EINVAL);
        new_off = (int64_t)f->size + off;
    } else
        return SYS_ERR(EINVAL);

    if (new_off < 0)
        return SYS_ERR(EINVAL);
    f->offset = (uint64_t)new_off;
    /* Sync the driver's internal write cursor: ops->write takes no offset, so a
     * seek-then-write (e.g. `as` patching an ELF header) would otherwise write
     * at the stale position and corrupt the file. */
    if (f->ops->seek)
        f->ops->seek(f->priv, (uint64_t)new_off);
    return (uint64_t)new_off;
}

/*
 * sys_pipe2 — syscall 293
 *
 * arg1 = user pointer to int[2] — receives [read_fd, write_fd]
 * arg2 = flags (O_CLOEXEC = 0x80000 supported; stored in fd flags via VFS_FD_CLOEXEC)
 *
 * Allocates a pipe_t from kva, installs read and write ends into two free
 * fd slots, writes the fd numbers to user pipefd.
 */
uint64_t
sys_pipe2(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    uint32_t pipe_flags = (uint32_t)arg2;

    if (!user_ptr_valid(arg1, 2 * sizeof(int)))
        return SYS_ERR(EFAULT);

    /* Find two free fd slots */
    int rfd = -1, wfd = -1;
    int i;
    for (i = 0; i < PROC_MAX_FDS; i++) {
        if (!proc->fd_table->fds[i].ops) {
            if (rfd < 0) { rfd = i; }
            else         { wfd = i; break; }
        }
    }
    if (wfd < 0)
        return SYS_ERR(EMFILE);

    /* Allocate and zero-initialize pipe_t (exactly one kva page) */
    pipe_t *p = kva_alloc_pages(1);
    if (!p)
        return SYS_ERR(ENOMEM);
    __builtin_memset(p, 0, sizeof(pipe_t));
    refcount_init(&p->read_refs, 1);
    refcount_init(&p->write_refs, 1);

    /* Install read end */
    proc->fd_table->fds[rfd].ops    = &g_pipe_read_ops;
    proc->fd_table->fds[rfd].priv   = p;
    proc->fd_table->fds[rfd].offset = 0;
    proc->fd_table->fds[rfd].size   = 0;
    proc->fd_table->fds[rfd].flags  = 0;

    /* Install write end */
    proc->fd_table->fds[wfd].ops    = &g_pipe_write_ops;
    proc->fd_table->fds[wfd].priv   = p;
    proc->fd_table->fds[wfd].offset = 0;
    proc->fd_table->fds[wfd].size   = 0;
    proc->fd_table->fds[wfd].flags  = VFS_O_WRONLY;

    /* Propagate O_CLOEXEC to both pipe ends */
    if (pipe_flags & VFS_O_CLOEXEC) {
        proc->fd_table->fds[rfd].flags |= VFS_FD_CLOEXEC;
        proc->fd_table->fds[wfd].flags |= VFS_FD_CLOEXEC;
    }

    /* Write [rfd, wfd] to user pipefd array */
    int out[2] = { rfd, wfd };
    copy_to_user((void *)(uintptr_t)arg1, out, sizeof(out));

    return 0;
}

/*
 * sys_dup — syscall 32
 *
 * arg1 = oldfd
 *
 * Duplicates oldfd into the lowest free fd slot. Calls the dup hook
 * to increment any driver-side reference counts (e.g., pipe_t refs).
 */
uint64_t
sys_dup(uint64_t arg1)
{
    aegis_process_t *proc = current_proc();
    if (arg1 >= PROC_MAX_FDS || !proc->fd_table->fds[arg1].ops)
        return SYS_ERR(EBADF);

    int newfd = -1;
    int i;
    for (i = 0; i < PROC_MAX_FDS; i++) {
        if (!proc->fd_table->fds[i].ops) { newfd = i; break; }
    }
    if (newfd < 0)
        return SYS_ERR(EMFILE);

    /* Copy fd struct by value, then bump refcount via dup hook. */
    proc->fd_table->fds[newfd] = proc->fd_table->fds[arg1];
    proc->fd_table->fds[newfd].flags &= ~VFS_FD_CLOEXEC;  /* POSIX: dup clears FD_CLOEXEC */
    if (proc->fd_table->fds[newfd].ops->dup)
        proc->fd_table->fds[newfd].ops->dup(proc->fd_table->fds[newfd].priv);

    return (uint64_t)newfd;
}

/*
 * sys_dup2 — syscall 33
 *
 * arg1 = oldfd, arg2 = newfd
 *
 * Duplicates oldfd into newfd. Closes newfd first if it is open.
 * If oldfd == newfd, returns newfd with no changes.
 */
uint64_t
sys_dup2(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    if (arg1 >= PROC_MAX_FDS || !proc->fd_table->fds[arg1].ops)
        return SYS_ERR(EBADF);
    if (arg2 >= PROC_MAX_FDS)
        return SYS_ERR(EBADF);
    if (arg1 == arg2)
        return arg2;            /* no-op per POSIX */

    /* Close existing target fd */
    if (proc->fd_table->fds[arg2].ops) {
        proc->fd_table->fds[arg2].ops->close(proc->fd_table->fds[arg2].priv);
        __builtin_memset(&proc->fd_table->fds[arg2], 0, sizeof(vfs_file_t));
    }

    /* Copy fd struct by value, then bump refcount via dup hook. */
    proc->fd_table->fds[arg2] = proc->fd_table->fds[arg1];
    proc->fd_table->fds[arg2].flags &= ~VFS_FD_CLOEXEC;  /* POSIX: dup2 clears FD_CLOEXEC */
    if (proc->fd_table->fds[arg2].ops->dup)
        proc->fd_table->fds[arg2].ops->dup(proc->fd_table->fds[arg2].priv);

    return arg2;
}

/* sys_dup3 — syscall 292 (x86_64) / 24 (arm64): like dup2 but rejects oldfd==newfd
 * with EINVAL, and O_CLOEXEC (0x80000) in flags sets FD_CLOEXEC on newfd (dup2
 * clears it). Was previously aliased to plain dup2, dropping the flag + on x86_64
 * unwired entirely (ENOSYS). musl's fd machinery + posix_spawn rely on it. */
uint64_t
sys_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags)
{
    if (oldfd == newfd)
        return SYS_ERR(EINVAL);
    uint64_t r = sys_dup2(oldfd, newfd);
    if (r != newfd)
        return r;                       /* dup2 errored (SYS_ERR band) */
    if (flags & 0x80000u) {             /* O_CLOEXEC */
        aegis_process_t *proc = current_proc();
        proc->fd_table->fds[newfd].flags |= VFS_FD_CLOEXEC;
    }
    return newfd;
}

/* sys_getrusage — syscall 98: resource usage. Aegis keeps no per-process rusage
 * yet, so zero the struct and succeed — make/configure/shells call it and only
 * need it not to fail. ponytail: fill ru_utime/ru_stime/ru_maxrss if a real
 * consumer ever needs the numbers. struct rusage = 144 bytes on x86-64/arm64. */
uint64_t
sys_getrusage(uint64_t who, uint64_t ubuf)
{
    (void)who;
    if (ubuf == 0)
        return 0;
    if (!user_ptr_valid(ubuf, 144))
        return SYS_ERR(EFAULT);
    char zero[144];
    __builtin_memset(zero, 0, sizeof(zero));
    copy_to_user((void *)(uintptr_t)ubuf, zero, sizeof(zero));
    return 0;
}

/*
 * copy_path_from_user — copy a null-terminated path string from user space.
 *
 * Uses the same byte-by-byte pattern as sys_open to avoid crossing unmapped
 * pages near the top of the user stack.  Returns 0 on success, -14 (EFAULT)
 * if any byte is in kernel space.
 */
int
copy_path_from_user(char *kpath, uint64_t user_ptr, uint32_t bufsz)
{
    uint32_t i;
    /* user_ptr_valid walks page tables; cache the validated page so a
     * path costs at most two walks, not one per byte. */
    uint64_t valid_pg = ~0ULL;
    for (i = 0; i < bufsz - 1; i++) {
        uint64_t pg = (user_ptr + i) & ~0xFFFULL;
        if (pg != valid_pg) {
            if (!user_ptr_valid(user_ptr + i, 1))
                return -EFAULT;
            valid_pg = pg;
        }
        char c;
        copy_from_user(&c, (const void *)(uintptr_t)(user_ptr + i), 1);
        kpath[i] = c;
        if (c == '\0') return 0;
    }
    kpath[bufsz - 1] = '\0';
    /* Loop completed without finding null — path was truncated */
    return -ENAMETOOLONG;
}

/* copy_path_from_user + resolve a relative result against proc->cwd (as sys_open
 * does). The dir-mutating syscalls (mkdir/rmdir/unlink/rename/link) historically
 * passed the raw user path straight to ext2, which walks from the fs ROOT — so a
 * RELATIVE path from a process with cwd != "/" (e.g. a parallel build's atomic
 * temp+rename of build/foo.o with cwd=/aegis) failed "parent dir open". Absolute
 * paths pass through unchanged. */
int
copy_path_resolved(char *kpath, uint64_t user_ptr, uint32_t bufsz)
{
    int r = copy_path_from_user(kpath, user_ptr, bufsz);
    if (r != 0)
        return r;
    if (kpath[0] == '/' || kpath[0] == '\0')
        return 0;                       /* absolute or empty — nothing to do */

    aegis_process_t *proc = current_proc();
    char tmp[256];
    uint32_t cwdlen = 0;
    while (proc->cwd[cwdlen]) cwdlen++;
    uint32_t plen = 0;
    while (kpath[plen]) plen++;
    uint32_t sep = (cwdlen > 0 && proc->cwd[cwdlen - 1] == '/') ? 0u : 1u;
    if (cwdlen + sep + plen >= sizeof(tmp) || cwdlen + sep + plen >= bufsz)
        return -ENAMETOOLONG;
    __builtin_memcpy(tmp, proc->cwd, cwdlen);
    if (sep) tmp[cwdlen] = '/';
    __builtin_memcpy(tmp + cwdlen + sep, kpath, plen + 1);
    __builtin_memcpy(kpath, tmp, cwdlen + sep + plen + 1);
    return 0;
}

/*
 * sys_sync — syscall 162
 *
 * Flush all dirty ext2 blocks to disk, then commit the drive's volatile
 * write cache (NVMe FLUSH).  Without the device flush, "synced" data sits
 * in the drive's volatile cache and is not guaranteed to survive the
 * controller reset at reboot — QEMU never loses it, real drives can.
 * Matches POSIX sync(2): no arguments, no return value besides 0.
 */
uint64_t
sys_sync(void)
{
    ext2_sync();
#ifdef __x86_64__
    nvme_flush();   /* no NVMe driver on arm64 yet */
#endif
    return 0;
}
