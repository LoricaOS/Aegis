/* sys_meta.c — File metadata syscalls: lstat, symlink, readlink, chmod, chown */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
#include "ext2.h"
#include "../lib/string.h"

/* ── Helper: resolve relative path against cwd ──────────────────────── */

static int
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

    /* Install-tree gate: creating a symlink AT a protected path (which could
     * alias a system binary/policy file) requires CAP_KIND_INSTALL. */
    if (cap_path_is_protected(resolved) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                  CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EPERM);

    int r = ext2_symlink(resolved, target);
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

    /* Install-tree mutation gate: a process mutating /apps or /etc/aegis must
     * hold CAP_KIND_INSTALL. (Syscall handlers run only in user context.) */
    if (cap_path_is_protected(resolved) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                  CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EPERM); /* EPERM — installing into the system tree needs CAP_KIND_INSTALL */

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

    int r = ext2_chmod(resolved, (uint16_t)arg2);
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

    int r = ext2_chown(resolved, (uint16_t)arg2, (uint16_t)arg3, 1);
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

    int r = ext2_chown(resolved, (uint16_t)arg2, (uint16_t)arg3, 0);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}
