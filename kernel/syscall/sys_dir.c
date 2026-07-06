/* sys_dir.c — Directory syscalls: getdents64, mkdir, unlink, rename */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
#include "ext2.h"

/*
 * sys_getdents64 — syscall 217
 *
 * fd_num = file descriptor for a directory
 * dirp   = user pointer to output buffer
 * count  = buffer size in bytes
 *
 * Returns number of bytes written on success, 0 at end, negative errno on failure.
 */
uint64_t
sys_getdents64(uint64_t fd_num, uint64_t dirp, uint64_t count)
{
    aegis_process_t *proc = current_proc();
    if (fd_num >= PROC_MAX_FDS) return SYS_ERR(EBADF);
    vfs_file_t *f = &proc->fd_table->fds[fd_num];
    if (!f->ops) return SYS_ERR(EBADF);
    if (!f->ops->readdir) return SYS_ERR(ENOTDIR);
    if (!user_ptr_valid(dirp, count)) return SYS_ERR(EFAULT);

    uint64_t written = 0;
    char name[256];
    uint8_t type;

    while (1) {
        if (f->ops->readdir(f->priv, f->offset, name, &type) != 0) break;

        /* Record size: fixed header (19 bytes) + name + null, rounded up to 8 */
        uint64_t namelen = 0;
        while (name[namelen] && namelen < 255) namelen++;
        uint16_t reclen = (uint16_t)(19 + namelen + 1);
        reclen = (uint16_t)((reclen + 7) & ~7);

        if (written + reclen > count) break;

        /* Build dirent in kernel buffer, then copy_to_user */
        uint8_t kbuf[300];
        linux_dirent64_t *d = (linux_dirent64_t *)kbuf;
        d->d_ino    = f->offset + 1;
        d->d_off    = (int64_t)(f->offset + 1);
        d->d_reclen = reclen;
        d->d_type   = type;
        uint64_t i;
        for (i = 0; i <= namelen; i++) d->d_name[i] = name[i];
        /* zero-pad trailing bytes to reach record boundary */
        for (i = 1 + namelen; i < (uint64_t)(reclen - 19); i++) d->d_name[i] = '\0';

        copy_to_user((void *)(uintptr_t)(dirp + written), kbuf, reclen);
        written += reclen;
        f->offset++;
    }
    return written;
}

/*
 * sys_mkdir — syscall 83
 *
 * arg1 = user pointer to null-terminated path string
 * arg2 = mode (ignored for now)
 *
 * Returns 0 on success, negative errno on failure.
 */
uint64_t
sys_mkdir(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(EPERM);
    char kpath[256];
    (void)arg2; /* mode ignored for now */
    if (copy_path_resolved(kpath, arg1, sizeof(kpath)) != 0)
        return SYS_ERR(EFAULT);
    /* Install-tree mutation gate: a ring-3 process mutating /apps or
     * /etc/aegis must hold CAP_KIND_INSTALL. Boot-time (is_user == 0) exempt. */
    if (cap_path_is_protected(kpath) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                  CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EPERM); /* EPERM — installing into the system tree needs CAP_KIND_INSTALL */
    /* Route ramfs (/tmp, /run) paths — these are not in ext2, so ext2_mkdir
     * would wrongly return EPERM. ramfs is a flat namespace; mkdir creates a
     * directory marker entry (needed by software that mkdir's cache/runtime
     * dirs under /tmp, e.g. Ladybird's XDG_RUNTIME_DIR). */
    {
        int rc;
        if (vfs_ramfs_mkdir(kpath, &rc))
            return (rc < 0) ? (uint64_t)(int64_t)rc : 0;
    }
    /* POSIX/Linux ordering: an EXISTING target is EEXIST regardless of parent
     * write permission — `mkdir -p` re-mkdirs every path component and relies
     * on EEXIST for the ones already present. Checking parent W+X first
     * returned EACCES for existing components whose parent the caller cannot
     * write (e.g. "/" during mkdir -p of a build tree), breaking mkdir -p.
     * (Masked historically by the unresolved-relative-path bug, which skipped
     * these checks entirely.) Creation below still requires parent W+X. */
    {
        uint32_t existing;
        if (ext2_open(kpath, &existing) == 0)
            return SYS_ERR(EEXIST);
    }
    /* Check W+X permission on parent directory */
    {
        uint32_t parent_ino;
        const char *bname;
        if (ext2_lookup_parent(kpath, &parent_ino, &bname) == 0) {
            int pperm = ext2_check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
    }
    int r = ext2_mkdir(kpath, 0755);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}

/*
 * sys_rmdir — syscall 84
 *
 * arg1 = user pointer to null-terminated path string
 *
 * Removes an empty directory. Returns 0 on success, negative errno on
 * failure (ENOTDIR if not a directory, ENOTEMPTY if not empty).
 */
uint64_t
sys_rmdir(uint64_t arg1)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(EPERM);
    char kpath[256];
    if (copy_path_resolved(kpath, arg1, sizeof(kpath)) != 0)
        return SYS_ERR(EFAULT);
    /* Check W+X permission on parent directory */
    {
        uint32_t parent_ino;
        const char *bname;
        if (ext2_lookup_parent(kpath, &parent_ino, &bname) == 0) {
            int pperm = ext2_check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
    }
    int r = ext2_rmdir(kpath);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}

/*
 * sys_unlink — syscall 87
 *
 * arg1 = user pointer to null-terminated path string
 *
 * Returns 0 on success, negative errno on failure.
 */
uint64_t
sys_unlink(uint64_t arg1)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(EPERM);
    char kpath[256];
    if (copy_path_resolved(kpath, arg1, sizeof(kpath)) != 0)
        return SYS_ERR(EFAULT);
    /* Install-tree mutation gate: a ring-3 process mutating /apps or
     * /etc/aegis must hold CAP_KIND_INSTALL. Boot-time (is_user == 0) exempt. */
    if (cap_path_is_protected(kpath) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                  CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EPERM); /* EPERM — installing into the system tree needs CAP_KIND_INSTALL */
    /* Route ramfs (/tmp, /run) paths — these are not in ext2, so calling
     * ext2_unlink would wrongly return EPERM. */
    {
        int rc;
        if (vfs_ramfs_unlink(kpath, &rc))
            return (rc < 0) ? (uint64_t)(int64_t)rc : 0;
    }
    /* Check W+X permission on parent directory */
    {
        uint32_t parent_ino;
        const char *bname;
        if (ext2_lookup_parent(kpath, &parent_ino, &bname) == 0) {
            int pperm = ext2_check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
    }
    int r = ext2_unlink(kpath);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}

/*
 * sys_rename — syscall 82
 *
 * arg1 = user pointer to null-terminated old path
 * arg2 = user pointer to null-terminated new path
 *
 * Returns 0 on success, negative errno on failure.
 */
uint64_t
sys_rename(uint64_t arg1, uint64_t arg2)
{
    aegis_process_t *proc = current_proc();
    if (cap_check(proc->caps, CAP_TABLE_SIZE,
                  CAP_KIND_VFS_WRITE, CAP_RIGHTS_WRITE) != 0)
        return SYS_ERR(EPERM);
    char kold[256], knew[256];
    if (copy_path_resolved(kold, arg1, sizeof(kold)) != 0)
        return SYS_ERR(EFAULT);
    if (copy_path_resolved(knew, arg2, sizeof(knew)) != 0)
        return SYS_ERR(EFAULT);
    /* Install-tree mutation gate: a ring-3 process mutating /apps or
     * /etc/aegis must hold CAP_KIND_INSTALL. Guard if EITHER the source or
     * destination is protected. Boot-time (is_user == 0) exempt. */
    if ((cap_path_is_protected(kold) || cap_path_is_protected(knew)) &&
        cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                  CAP_RIGHTS_READ) != 0)
        return SYS_ERR(EPERM); /* EPERM — installing into the system tree needs CAP_KIND_INSTALL */
    /* Route ramfs (/tmp, /run) renames before the ext2 path. */
    {
        int rc;
        if (vfs_ramfs_rename(kold, knew, &rc))
            return (rc < 0) ? (uint64_t)(int64_t)rc : 0;
    }
    /* Check W+X permission on both source and destination parent dirs */
    {
        uint32_t parent_ino;
        const char *bname;
        if (ext2_lookup_parent(kold, &parent_ino, &bname) == 0) {
            int pperm = ext2_check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
        if (ext2_lookup_parent(knew, &parent_ino, &bname) == 0) {
            int pperm = ext2_check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
    }
    int r = ext2_rename(kold, knew);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}
