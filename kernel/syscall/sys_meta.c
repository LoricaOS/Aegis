/* sys_meta.c — File metadata syscalls: lstat, symlink, readlink, chmod, chown */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
#include "ext2.h"
#include "arch.h"
#include "../lib/string.h"

/* ── Helper: resolve relative path against cwd ──────────────────────── */

int
resolve_path(const char *kpath, const char *cwd, char *out, uint32_t outsz)
{
    if (kpath[0] == '/') {
        uint32_t i;
        for (i = 0; i < outsz - 1 && kpath[i]; i++)
            out[i] = kpath[i];
        out[i] = '\0';
        return 0;
    }
    uint32_t cwdlen = 0;
    while (cwd[cwdlen]) cwdlen++;
    uint32_t pathlen = 0;
    while (kpath[pathlen]) pathlen++;
    uint32_t sep = (cwdlen > 0 && cwd[cwdlen - 1] == '/') ? 0u : 1u;
    if (cwdlen + sep + pathlen >= outsz)
        return -ENAMETOOLONG;
    __builtin_memcpy(out, cwd, cwdlen);
    if (sep) out[cwdlen] = '/';
    __builtin_memcpy(out + cwdlen + sep, kpath, pathlen + 1);
    return 0;
}

/* ── Sensitive-inode mutation gate ──────────────────────────────────────
 *
 * The kernel protects a handful of security-critical files by INODE (recorded
 * at ext2 mount), so symlink / ".." aliases cannot bypass the check:
 *
 *   /etc/shadow, /etc/aegis/admin  — the login + admin-elevation credentials.
 *       READ is already AUTH-gated in vfs_open/sys_open.  But the ext2 MUTATORS
 *       (rename/unlink/link/chmod/chown/…) enforced only baseline VFS_WRITE +
 *       the install-protected-tree check — and /etc/shadow is under neither, so
 *       an unprivileged `rename()` could clobber it with attacker hashes (no
 *       CAP_KIND_AUTH).  Gate every mutator on CAP_KIND_AUTH, mirroring the read
 *       gate, so the write side is as strong as the read side.
 *
 *   /etc/passwd, /etc/group  — the account/group identity DB.  World-readable
 *       but admin-managed; the live user is cosmetic uid 0 and OWNS these uid-0
 *       files, so ext2 DAC alone grants owner-write.  Gate mutation on an
 *       admin_session (the same authority useradd/adminpw hold), so a baseline
 *       session cannot append a uid-0 account or clobber the DB.
 *
 * Fail-closed: unknown/zero inode → allowed (nothing sensitive resolved); a
 * sensitive inode without the required authority → negative errno.  Only user
 * processes are gated (kernel-internal fs setup passes through). */
int
sensitive_write_gate(uint32_t ino)
{
    if (ino == 0)
        return 0;
    if (!sched_current()->is_user)
        return 0;

    aegis_process_t *proc = current_proc();

    uint32_t shadow_ino = ext2_get_shadow_ino();
    uint32_t admin_ino  = ext2_get_admin_ino();
    if ((shadow_ino != 0 && ino == shadow_ino) ||
        (admin_ino  != 0 && ino == admin_ino)) {
        if (cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
            return -EACCES;
    }

    uint32_t passwd_ino = ext2_get_passwd_ino();
    uint32_t group_ino  = ext2_get_group_ino();
    if ((passwd_ino != 0 && ino == passwd_ino) ||
        (group_ino  != 0 && ino == group_ino)) {
        if (proc->admin_session == 0)
            return -EPERM;
    }

    return 0;
}

/*
 * sys_lstat — syscall 6
 * Like sys_stat but does not follow symlinks on the final component.
 */
uint64_t
sys_lstat(uint64_t arg1, uint64_t arg2)
{
    char path[256];
    if (stat_copy_path(arg1, path, sizeof(path)) != 0)
        return SYS_ERR(EFAULT);

    /* Defensive zero-init: padding inside k_stat_t and any field a VFS
     * backend forgets to populate must not leak kernel-stack bytes to
     * userspace via the copy below. sys_stat/sys_fstat already do this;
     * keep the three stat syscalls consistent. */
    k_stat_t ks;
    __builtin_memset(&ks, 0, sizeof(ks));
    int rc = vfs_stat_path_ex(path, &ks, 0);
    if (rc != 0) return SYS_ERR(ENOENT);

    COPY_TO_USER(arg2, &ks);
    return 0;
}

/*
 * sys_symlink — syscall 88
 * arg1 = user pointer to target string (stored as-is)
 * arg2 = user pointer to linkpath string (resolved against cwd)
 */
uint64_t
sys_symlink(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    char target[256], linkpath[256], resolved[256];
    if (copy_path_from_user(target, arg1, sizeof(target)) != 0)
        return SYS_ERR(EFAULT);
    if (copy_path_from_user(linkpath, arg2, sizeof(linkpath)) != 0)
        return SYS_ERR(EFAULT);

    /* Resolve linkpath against cwd (target is stored as-is) */
    if (resolve_path(linkpath, proc->cwd, resolved, sizeof(resolved)) != 0)
        return SYS_ERR(ENAMETOOLONG);

    /* Install-tree gate is now enforced ATOMICALLY inside ext2_symlink (under
     * the fs lock it holds across resolve+create), closing the symlink-swap
     * TOCTOU the old separate cap_path_is_protected check had. We just tell it
     * whether this caller is INSTALL-authorized. */
    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_READ) == 0);
    /* Sensitive-inode mutation gate (shadow/admin → AUTH, passwd/group → admin
     * session). Keyed on the resolved inode so a symlink alias cannot bypass. */
    {
        uint32_t sino;
        if (ext2_open(resolved, &sino) == 0) {
            int g = sensitive_write_gate(sino);
            if (g != 0) return (uint64_t)(int64_t)g;
        }
    }
    int r = ext2_symlink(resolved, target, has_install);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}

/*
 * sys_link — syscall 86 (hard link)
 * arg1 = user pointer to oldpath, arg2 = user pointer to newpath.
 * Both resolved against cwd. newpath must not exist; oldpath's inode gains
 * a second name and its link count is bumped.
 */
uint64_t
sys_link(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    char oldp[256], newp[256], rold[256], rnew[256];
    if (copy_path_from_user(oldp, arg1, sizeof(oldp)) != 0)
        return SYS_ERR(EFAULT);
    if (copy_path_from_user(newp, arg2, sizeof(newp)) != 0)
        return SYS_ERR(EFAULT);
    if (resolve_path(oldp, proc->cwd, rold, sizeof(rold)) != 0 ||
        resolve_path(newp, proc->cwd, rnew, sizeof(rnew)) != 0)
        return SYS_ERR(ENAMETOOLONG);

    /* Install-tree gate enforced atomically inside ext2_link (both paths). */
    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_READ) == 0);
    /* Sensitive-inode gate on BOTH ends: hard-linking /etc/shadow to an alias
     * (source) or clobbering a sensitive target both require the authority. */
    {
        uint32_t sino;
        if (ext2_open(rold, &sino) == 0) {
            int g = sensitive_write_gate(sino);
            if (g != 0) return (uint64_t)(int64_t)g;
        }
        if (ext2_open(rnew, &sino) == 0) {
            int g = sensitive_write_gate(sino);
            if (g != 0) return (uint64_t)(int64_t)g;
        }
    }
    int r = ext2_link(rold, rnew, has_install);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}

/*
 * sys_readlink — syscall 89
 * arg1 = user pointer to path string
 * arg2 = user pointer to output buffer
 * arg3 = buffer size
 */
uint64_t
sys_readlink(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_READ, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(ENOCAP);

    char path[256], resolved[256];
    if (copy_path_from_user(path, arg1, sizeof(path)) != 0)
        return SYS_ERR(EFAULT);

    if (resolve_path(path, proc->cwd, resolved, sizeof(resolved)) != 0)
        return SYS_ERR(ENAMETOOLONG);

    uint32_t bufsiz = (uint32_t)arg3;

    /* /proc/self/exe → the calling process's binary path (set at execve).
     * procfs is not ext2-backed, so handle this readlink here before
     * ext2_readlink (which would fail). Many programs readlink /proc/self/exe
     * to locate their install prefix — e.g. Ladybird's resource-root lookup. */
    {
        static const char self_exe[] = "/proc/self/exe";
        if (kmemcmp(resolved, self_exe, sizeof(self_exe)) == 0) {  /* incl NUL */
            uint32_t len = 0;
            while (len < sizeof(proc->exe_path) && proc->exe_path[len])
                len++;
            if (len > bufsiz) len = bufsiz;
            if (!user_ptr_valid(arg2, (uint64_t)len))
                return SYS_ERR(EFAULT);
            copy_to_user((void *)(uintptr_t)arg2, proc->exe_path, len);
            return (uint64_t)len;
        }
    }

    char kbuf[256];
    if (bufsiz > sizeof(kbuf)) bufsiz = sizeof(kbuf);

    int n = ext2_readlink(resolved, kbuf, bufsiz);
    if (n < 0) return (uint64_t)(int64_t)n;

    if (!user_ptr_valid(arg2, (uint64_t)n))
        return SYS_ERR(EFAULT);
    copy_to_user((void *)(uintptr_t)arg2, kbuf, (uint32_t)n);
    return (uint64_t)n;
}

/*
 * sys_chmod — syscall 90
 * arg1 = user pointer to path string
 * arg2 = mode (permission bits)
 */
uint64_t
sys_chmod(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    char path[256], resolved[256];
    if (copy_path_from_user(path, arg1, sizeof(path)) != 0)
        return SYS_ERR(EFAULT);

    if (resolve_path(path, proc->cwd, resolved, sizeof(resolved)) != 0)
        return SYS_ERR(ENAMETOOLONG);

    /* Install-tree mutation gate enforced atomically inside ext2_chmod. */
    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_READ) == 0);

    /* Ownership check: only file owner (or uid 0) may chmod */
    {
        uint32_t ino;
        if (ext2_open(resolved, &ino) == 0) {
            ext2_inode_t inode;
            if (ext2_read_inode(ino, &inode) == 0) {
                /* No uid=0 bypass — uid 0 is cosmetic in Aegis; only the file
                 * owner may chmod/chown (authority comes from capabilities, not
                 * ambient root). The installer owns the files it creates+chowns. */
                if (proc->uid != inode.i_uid)
                    return SYS_ERR(EACCES);
            }
        }
    }

    /* Sensitive-inode gate: chmod'ing /etc/shadow or the account DB needs the
     * same authority as any other mutation of it (owner-uid-0 DAC is not it). */
    {
        uint32_t sino;
        if (ext2_open(resolved, &sino) == 0) {
            int g = sensitive_write_gate(sino);
            if (g != 0) return (uint64_t)(int64_t)g;
        }
    }
    int r = ext2_chmod(resolved, (uint16_t)arg2, has_install);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}

/*
 * sys_fchmod — syscall 91
 * arg1 = fd, arg2 = mode (permission bits)
 */
uint64_t
sys_fchmod(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    if (arg1 >= PROC_MAX_FDS) return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[arg1];
    if (!f->ops) return SYS_ERR(EBADF);

    /* fd-based install gate (parity with path-based sys_chmod): an fd onto a
     * file under the install-protected trees can't mutate it without
     * CAP_KIND_INSTALL, even if it was opened O_RDONLY. */
    if ((f->kflags & VFS_KF_PROTECTED) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EPERM);

    /* Ownership check via stat: only file owner (or uid 0) may fchmod */
    if (f->ops->stat) {
        k_stat_t ks;
        if (f->ops->stat(f->priv, &ks) == 0) {
            /* Sensitive-inode gate (parity with path-based sys_chmod): fchmod'ing
             * an fd onto /etc/shadow, /etc/passwd, … needs the same authority a
             * path chmod would — owner-uid-0 DAC is not it. Keyed on the fd's
             * resolved inode, so it can't be bypassed via an fd opened O_RDONLY. */
            int g = sensitive_write_gate((uint32_t)ks.st_ino);
            if (g != 0) return (uint64_t)(int64_t)g;
            /* No uid=0 bypass (see sys_chmod): only the owner may fchmod/fchown. */
            if (proc->uid != ks.st_uid)
                return SYS_ERR(EACCES);
        }
    }

    int r = vfs_fchmod(f, (uint16_t)arg2);
    if (r < 0) return SYS_ERR(EINVAL); /* EINVAL — not an ext2 fd */
    return 0;
}

/*
 * sys_chown — syscall 92
 * arg1 = user pointer to path, arg2 = uid, arg3 = gid
 * Follows symlinks.
 */
uint64_t
sys_chown(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_SETUID, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    char path[256], resolved[256];
    if (copy_path_from_user(path, arg1, sizeof(path)) != 0)
        return SYS_ERR(EFAULT);

    if (resolve_path(path, proc->cwd, resolved, sizeof(resolved)) != 0)
        return SYS_ERR(ENAMETOOLONG);

    /* Ownership check: only file owner (or uid 0) may chown */
    {
        uint32_t ino;
        if (ext2_open(resolved, &ino) == 0) {
            ext2_inode_t inode;
            if (ext2_read_inode(ino, &inode) == 0) {
                /* No uid=0 bypass — uid 0 is cosmetic in Aegis; only the file
                 * owner may chmod/chown (authority comes from capabilities, not
                 * ambient root). The installer owns the files it creates+chowns. */
                if (proc->uid != inode.i_uid)
                    return SYS_ERR(EACCES);
            }
        }
    }

    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_READ) == 0);
    {
        uint32_t sino;
        if (ext2_open(resolved, &sino) == 0) {
            int g = sensitive_write_gate(sino);
            if (g != 0) return (uint64_t)(int64_t)g;
        }
    }
    int r = ext2_chown(resolved, (uint16_t)arg2, (uint16_t)arg3, 1, has_install);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}

/*
 * sys_fchown — syscall 93
 * arg1 = fd, arg2 = uid, arg3 = gid
 */
uint64_t
sys_fchown(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_SETUID, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    if (arg1 >= PROC_MAX_FDS) return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[arg1];
    if (!f->ops) return SYS_ERR(EBADF);

    /* fd-based install gate (parity with path-based sys_chown): see sys_fchmod. */
    if ((f->kflags & VFS_KF_PROTECTED) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL, CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EPERM);

    /* Ownership check via stat: only file owner (or uid 0) may fchown */
    if (f->ops->stat) {
        k_stat_t ks;
        if (f->ops->stat(f->priv, &ks) == 0) {
            /* Sensitive-inode gate (parity with path-based sys_chown): fchown'ing
             * an fd onto /etc/shadow, /etc/passwd, … needs the same authority a
             * path chown would. Keyed on the fd's resolved inode. */
            int g = sensitive_write_gate((uint32_t)ks.st_ino);
            if (g != 0) return (uint64_t)(int64_t)g;
            /* No uid=0 bypass (see sys_chmod): only the owner may fchmod/fchown. */
            if (proc->uid != ks.st_uid)
                return SYS_ERR(EACCES);
        }
    }

    int r = vfs_fchown(f, (uint16_t)arg2, (uint16_t)arg3);
    if (r < 0) return SYS_ERR(EINVAL); /* EINVAL — not an ext2 fd */
    return 0;
}

/*
 * sys_utimensat — syscall 280 (touch, make, git, tar)
 * arg1 = dirfd (only AT_FDCWD supported — CWD-relative / absolute paths)
 * arg2 = user pointer to pathname
 * arg3 = user pointer to struct timespec[2] {atime, mtime}, or NULL = both now
 * arg4 = flags (AT_SYMLINK_NOFOLLOW = 0x100)
 *
 * Each timespec's tv_nsec may be UTIME_NOW (use current time) or UTIME_OMIT
 * (leave that field untouched). Only the file owner may set times (parity with
 * chmod — metadata mutation is owner-gated; uid 0 is cosmetic in Aegis).
 */
#define UTIME_NOW  0x3fffffff
#define UTIME_OMIT 0x3ffffffe

uint64_t
sys_utimensat(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    (void)arg1;  /* dirfd — only AT_FDCWD (-100) or absolute paths handled */
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    char path[256], resolved[256];
    if (copy_path_from_user(path, arg2, sizeof(path)) != 0)
        return SYS_ERR(EFAULT);
    if (resolve_path(path, proc->cwd, resolved, sizeof(resolved)) != 0)
        return SYS_ERR(ENAMETOOLONG);

    /* Install-tree gate enforced atomically inside ext2_utimes. */
    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_READ) == 0);

    /* Ownership check: only the file owner may set times. */
    {
        uint32_t ino;
        if (ext2_open(resolved, &ino) == 0) {
            ext2_inode_t inode;
            if (ext2_read_inode(ino, &inode) == 0 && proc->uid != inode.i_uid)
                return SYS_ERR(EACCES);
        }
    }

    uint64_t now_sec = 0, now_nsec = 0;
    arch_clock_gettime(&now_sec, &now_nsec);

    uint32_t atime, mtime;
    if (arg3 == 0) {
        /* NULL times → set both to now */
        atime = mtime = (uint32_t)now_sec;
    } else {
        /* struct timespec[2]: two {int64 tv_sec; int64 tv_nsec} = 32 bytes */
        int64_t ts[4];
        if (copy_from_user(ts, (const void *)(uintptr_t)arg3, sizeof(ts)) != 0)
            return SYS_ERR(EFAULT);
        int64_t a_nsec = ts[1], m_nsec = ts[3];
        atime = (a_nsec == UTIME_OMIT) ? EXT2_UTIME_KEEP
              : (a_nsec == UTIME_NOW)  ? (uint32_t)now_sec
              :                          (uint32_t)ts[0];
        mtime = (m_nsec == UTIME_OMIT) ? EXT2_UTIME_KEEP
              : (m_nsec == UTIME_NOW)  ? (uint32_t)now_sec
              :                          (uint32_t)ts[2];
    }

    {
        uint32_t sino;
        if (ext2_open(resolved, &sino) == 0) {
            int g = sensitive_write_gate(sino);
            if (g != 0) return (uint64_t)(int64_t)g;
        }
    }

    int follow = (arg4 & 0x100) ? 0 : 1;  /* AT_SYMLINK_NOFOLLOW */
    int r = ext2_utimes(resolved, atime, mtime, follow, has_install);
    if (r == -EPERM) return SYS_ERR(EPERM);   /* protected-tree without INSTALL */
    return (r < 0) ? SYS_ERR(ENOENT) : 0;
}

/*
 * sys_lchown — syscall 94
 * Like sys_chown but does not follow symlinks.
 */
uint64_t
sys_lchown(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_SETUID, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(ENOCAP);

    char path[256], resolved[256];
    if (copy_path_from_user(path, arg1, sizeof(path)) != 0)
        return SYS_ERR(EFAULT);

    if (resolve_path(path, proc->cwd, resolved, sizeof(resolved)) != 0)
        return SYS_ERR(ENAMETOOLONG);

    /* Ownership check: only file owner (or uid 0) may lchown */
    {
        uint32_t ino;
        if (ext2_open(resolved, &ino) == 0) {
            ext2_inode_t inode;
            if (ext2_read_inode(ino, &inode) == 0) {
                /* No uid=0 bypass — uid 0 is cosmetic in Aegis; only the file
                 * owner may chmod/chown (authority comes from capabilities, not
                 * ambient root). The installer owns the files it creates+chowns. */
                if (proc->uid != inode.i_uid)
                    return SYS_ERR(EACCES);
            }
        }
    }

    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_READ) == 0);
    {
        uint32_t sino;
        if (ext2_open(resolved, &sino) == 0) {
            int g = sensitive_write_gate(sino);
            if (g != 0) return (uint64_t)(int64_t)g;
        }
    }
    int r = ext2_chown(resolved, (uint16_t)arg2, (uint16_t)arg3, 0, has_install);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}
