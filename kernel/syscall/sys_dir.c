/* sys_dir.c — Directory syscalls: getdents64, mkdir, unlink, rename */
#include "sys_impl.h"
#include "fs_ops.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
#include "ext2.h"
#include "../fs/ext2_internal.h"   /* ext2_lock_acquire/release — TOCTOU gate */

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
    if (fd_num >= PROC_MAX_FDS)
        return SYS_ERR(EBADF);
    fd_table_pin_t pin;
    if (!fd_table_pin(proc->fd_table, (int)fd_num, &pin))
        return SYS_ERR(EBADF);
    vfs_file_t *f = &pin.file;
    if (!f->ops->readdir) {
        fd_table_unpin(&pin);
        return SYS_ERR(ENOTDIR);
    }
    if (!user_ptr_valid(dirp, count)) {
        fd_table_unpin(&pin);
        return SYS_ERR(EFAULT);
    }

    uint64_t written = 0;
    char name[256];
    uint8_t type;

    /* GETDENTS_MAX_ENTRIES — ceiling on the entries ONE getdents64 call will
     * produce, in the spirit of MM_MAX_RANGE_PAGES (sys_memory.c).
     *
     * ext2_readdir(index) restarts its walk from block 0 on every call, so
     * returning entry k costs O(k). `count` bounds the OUTPUT, not the WALK —
     * so one call with a large buffer over an N-entry directory was ~O(N^2)
     * inner iterations, and syscalls run with IF=0, so it could not be
     * preempted, interrupted or killed. A concurrent TLB shootdown from any
     * other core then spins for an ack the wedged core never sends, taking the
     * machine with it. Trigger needs only baseline caps: mkdir a directory you
     * own on the ext2 root, create ~30k files, one getdents64 with a 4 MiB
     * buffer. (/tmp is not a vector — ramfs caps dirents at 256.)
     *
     * Transparent to callers: getdents64 is already specified to return short,
     * and every libc loops until it returns 0. Bounding the entries per call
     * bounds the work per call, which is what stops the unpreemptible wedge —
     * interrupts are serviced between calls.
     *
     * RESIDUAL, stated honestly: this does not fix the underlying O(N^2) cost
     * of listing a large directory, only the unbounded single syscall. The
     * principled fix is a resumable cursor in ext2_readdir (carry the
     * block/offset position rather than re-deriving it from an entry index),
     * which changes the fs_ops readdir contract and every backend with it.
     * (audit 2026-08-01, A8.) */
    #define GETDENTS_MAX_ENTRIES 512u
    uint32_t produced = 0;
    uint64_t next_offset = f->offset;
    int copy_fault = 0;

    while (1) {
        if (produced >= GETDENTS_MAX_ENTRIES) break;
        if (f->ops->readdir(f->priv, next_offset, name, &type) != 0) break;

        /* Record size: fixed header (19 bytes) + name + null, rounded up to 8 */
        uint64_t namelen = 0;
        while (name[namelen] && namelen < 255) namelen++;
        uint16_t reclen = (uint16_t)(19 + namelen + 1);
        reclen = (uint16_t)((reclen + 7) & ~7);

        if (written + reclen > count) break;

        /* Build dirent in kernel buffer, then copy_to_user */
        uint8_t kbuf[300];
        linux_dirent64_t *d = (linux_dirent64_t *)kbuf;
        d->d_ino    = next_offset + 1;
        d->d_off    = (int64_t)(next_offset + 1);
        d->d_reclen = reclen;
        d->d_type   = type;
        uint64_t i;
        for (i = 0; i <= namelen; i++) d->d_name[i] = name[i];
        /* zero-pad trailing bytes to reach record boundary */
        for (i = 1 + namelen; i < (uint64_t)(reclen - 19); i++) d->d_name[i] = '\0';

        /* Consume the residual before committing this record. A fault may
         * occur after the range check (another thread can change mappings),
         * and advancing here would silently skip a directory entry on retry.
         * Linux-style short-I/O semantics apply: return completed records if
         * there are any, otherwise EFAULT. The faulting record is not counted
         * and its offset is not consumed. */
        if (copy_to_user((void *)(uintptr_t)(dirp + written),
                         kbuf, reclen) != 0) {
            copy_fault = 1;
            break;
        }
        written += reclen;
        next_offset++;
        produced++;
    }
    fd_table_advance_offset(proc->fd_table, (int)fd_num, &pin,
                            next_offset - f->offset);
    fd_table_unpin(&pin);
    if (copy_fault && written == 0)
        return SYS_ERR(EFAULT);
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
    /* Install-tree mutation gate is enforced ATOMICALLY inside ext2_mkdir now
     * (closing the symlink-swap TOCTOU); we just compute the caller's authority.
     * ramfs paths (below) never reach ext2_mkdir. */
    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_WRITE) == 0);
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
        if (g_rootfs->open(kpath, &existing) == 0)
            return SYS_ERR(EEXIST);
    }
    /* Check W+X permission on parent directory */
    {
        uint32_t parent_ino;
        const char *bname;
        if (g_rootfs->lookup_parent(kpath, &parent_ino, &bname) == 0) {
            int pperm = g_rootfs->check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
    }
    int r = g_rootfs->mkdir(kpath, 0755, has_install);
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
    /* Route ramfs (/tmp, /run) paths — as sys_mkdir and sys_unlink already do.
     * Without this, ext2_rmdir returned EPERM for every path it does not own,
     * so `mkdir /tmp/x` succeeded but `rmdir /tmp/x` could never undo it. */
    {
        int rc;
        if (vfs_ramfs_rmdir(kpath, &rc))
            return (rc < 0) ? (uint64_t)(int64_t)rc : 0;
    }
    /* Check W+X permission on parent directory */
    {
        uint32_t parent_ino;
        const char *bname;
        if (g_rootfs->lookup_parent(kpath, &parent_ino, &bname) == 0) {
            int pperm = g_rootfs->check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
    }
    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_WRITE) == 0);
    int r = g_rootfs->rmdir(kpath, has_install);
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
    /* Install-tree gate enforced atomically inside ext2_unlink now. */
    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_WRITE) == 0);
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
        if (g_rootfs->lookup_parent(kpath, &parent_ino, &bname) == 0) {
            int pperm = g_rootfs->check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
    }
    /* Sensitive-inode gate: unlinking /etc/shadow (→ recreate with attacker
     * hashes) or the account DB needs the mutation authority, not owner-uid-0. */
    /* Gate + mutate under ONE ext2_lock hold: the gate below and ext2_unlink
     * each resolved `kpath` independently, so a component swapped in between
     * meant the inode that was checked was not the inode that was unlinked
     * (see meta_gate_locked in sys_meta.c). ext2_lock is recursive, so the
     * nested ext2_* calls just bump its depth. */
    irqflags_t fl = g_rootfs->lock();
    int r = 0;
    {
        uint32_t sino;
        if (g_rootfs->open(kpath, &sino) == 0)
            r = sensitive_write_gate(sino);
    }
    if (r == 0)
        r = g_rootfs->unlink(kpath, has_install);
    g_rootfs->unlock(fl);
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
    /* Install-tree gate enforced atomically inside ext2_rename (both paths). */
    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_WRITE) == 0);
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
        if (g_rootfs->lookup_parent(kold, &parent_ino, &bname) == 0) {
            int pperm = g_rootfs->check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
        if (g_rootfs->lookup_parent(knew, &parent_ino, &bname) == 0) {
            int pperm = g_rootfs->check_perm(parent_ino,
                (uint16_t)proc->uid, (uint16_t)proc->gid, 2 | 1);
            if (pperm != 0)
                return SYS_ERR(EACCES);
        }
    }
    /* Sensitive-inode mutation gate on BOTH source and target: renaming a
     * crafted file OVER /etc/shadow (target) — the reported break — needs
     * CAP_KIND_AUTH; renaming the account DB away (source) needs an admin
     * session.  Keyed on the resolved inode so symlink/".." cannot bypass. */
    /* Gate BOTH ends and rename under ONE ext2_lock hold — the check-then-act
     * split is exactly the reported "rename a crafted file over /etc/shadow"
     * break. See the note in sys_unlink. */
    irqflags_t fl = g_rootfs->lock();
    int r = 0;
    {
        uint32_t sino;
        if (g_rootfs->open(kold, &sino) == 0)
            r = sensitive_write_gate(sino);
        if (r == 0 && g_rootfs->open(knew, &sino) == 0)
            r = sensitive_write_gate(sino);
    }
    if (r == 0)
        r = g_rootfs->rename(kold, knew, has_install);
    g_rootfs->unlock(fl);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}
