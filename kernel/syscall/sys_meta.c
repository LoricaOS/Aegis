/* sys_meta.c — File metadata syscalls: lstat, symlink, readlink, chmod, chown */
#include "sys_impl.h"
#include "fs_ops.h"
#include "sched.h"
#include "proc.h"
#include "vfs.h"
#include "ext2.h"
#include "../fs/ext2_internal.h"   /* ext2_lock_acquire/release — TOCTOU gate */
#include "arch.h"
#include "../lib/string.h"

/* ── Helper: resolve a user path to a canonical, in-scope absolute path ──
 *
 * Every path-taking syscall in this file routes through here, so this is the
 * one place the two confinement bugs had to be fixed:
 *
 *  1. It only prepended cwd — it never consulted the VFS scope. symlink, link,
 *     readlink, chmod, chown, lchown and utimensat therefore ignored
 *     sys_vfs_confine entirely: from a confined process,
 *     link("/etc/shadow", "/home/u/copy") simply worked. (Only sys_open was
 *     immune, because it pre-normalizes and calls vfs_scope_allows itself.)
 *
 *  2. It emitted the path with ".." still in it. path_canonicalize (what the
 *     scope check uses) pops ONE component per "..", but ext2_walk CLAMPED ".."
 *     to the filesystem root — so the string that was checked and the string
 *     that was walked could differ. A process confined to /home/u asking for
 *     "/home/u/x/../etc/shadow" got "/home/u/etc/shadow" approved by the
 *     checker while ext2 walked ".." to root and opened the real /etc/shadow.
 *     Canonicalizing HERE means the bytes checked are byte-for-byte the bytes
 *     walked, and no ".." ever reaches the filesystem. (ext2_walk's clamp is
 *     removed as well, so the two can no longer diverge.)
 *
 * Returns 0, or -ENAMETOOLONG / -EACCES (out of scope). Fails closed.
 */
int
resolve_path(const char *kpath, const char *cwd, char *out, uint32_t outsz)
{
    char abs[256];
    if (outsz > sizeof(abs))
        outsz = sizeof(abs);

    if (kpath[0] == '/') {
        uint32_t i;
        for (i = 0; i < outsz - 1 && kpath[i]; i++)
            abs[i] = kpath[i];
        if (kpath[i] != '\0')
            return -ENAMETOOLONG;
        abs[i] = '\0';
    } else {
        uint32_t cwdlen = 0;
        while (cwd[cwdlen]) cwdlen++;
        uint32_t pathlen = 0;
        while (kpath[pathlen]) pathlen++;
        uint32_t sep = (cwdlen > 0 && cwd[cwdlen - 1] == '/') ? 0u : 1u;
        if (cwdlen + sep + pathlen >= outsz)
            return -ENAMETOOLONG;
        __builtin_memcpy(abs, cwd, cwdlen);
        if (sep) abs[cwdlen] = '/';
        __builtin_memcpy(abs + cwdlen + sep, kpath, pathlen + 1);
    }

    /* Canonicalize BEFORE the scope check, and hand the caller the canonical
     * form — the filesystem must walk exactly what was approved. */
    path_canonicalize(abs, out, outsz);
    return vfs_scope_allows(out) ? 0 : -EACCES;
}

/* meta_gate_locked — owner + sensitive-inode authority for a path mutation.
 *
 * CALLER MUST ALREADY HOLD ext2_lock, and must perform the mutation before
 * releasing it. That is the whole point: these checks used to run as separate
 * ext2 walks that each took and dropped the lock, and then the mutator
 * (ext2_chmod / ext2_chown / …) re-walked the path under a FRESH lock. Three or
 * four independent resolutions of the same string is a textbook check-then-act:
 * swap a component in between — rename a directory, or repoint a symlink — and
 * the walk that gets validated is not the walk that gets mutated. `chmod 0666
 * /etc/shadow` was reachable that way. ext2_open_protected exists precisely to
 * fix this split for open(), and its own comment calls it "a genuine TOCTOU on
 * SMP"; it was never extended to the metadata mutators.
 *
 * ext2_lock is recursive, so the ext2_* calls here and the caller's mutator
 * just bump the depth counter — one hold covers resolve + validate + mutate.
 *
 * `follow` = 0 checks the link itself (lchown), 1 the target.
 * Returns 0 to proceed, or a negative errno. */
static int
meta_gate_locked(const char *resolved, aegis_process_t *proc, int follow)
{
    uint32_t ino;
    if (g_rootfs->open_ex(resolved, &ino, follow) != 0)
        return 0;   /* not an ext2 path (or absent) — mutator reports it */

    ext2_inode_t inode;
    if (g_rootfs->read_inode(ino, &inode) == 0) {
        /* No uid=0 bypass — uid 0 is cosmetic in Aegis; only the file owner may
         * chmod/chown (authority comes from capabilities, not ambient root).
         * The installer owns the files it creates+chowns. */
        if (proc->uid != inode.i_uid)
            return -EACCES;
    }
    /* Sensitive-inode gate: mutating /etc/shadow or the account DB needs the
     * same authority as any other mutation of it (owner-uid-0 DAC is not it). */
    return sensitive_write_gate(ino);
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

    uint32_t shadow_ino = g_rootfs->get_shadow_ino();
    uint32_t admin_ino  = g_rootfs->get_admin_ino();
    if ((shadow_ino != 0 && ino == shadow_ino) ||
        (admin_ino  != 0 && ino == admin_ino)) {
        if (cap_check(proc->caps, CAP_TABLE_SIZE,
                      CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
            return -EACCES;
    }

    uint32_t passwd_ino = g_rootfs->get_passwd_ino();
    uint32_t group_ino  = g_rootfs->get_group_ino();
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

    /* Must go through emit_stat like sys_stat/sys_fstat — see the note there.
     * A raw COPY_TO_USER wrote the x86-64 field order into an aarch64
     * struct stat, so S_ISLNK() was never true on arm64. */
    return emit_stat(arg2, &ks);
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
    irqflags_t fl = g_rootfs->lock();   /* gate + create in ONE hold */
    int r = 0;
    {
        uint32_t sino;
        if (g_rootfs->open(resolved, &sino) == 0)
            r = sensitive_write_gate(sino);
    }
    if (r == 0)
        r = g_rootfs->symlink(resolved, target, has_install);
    g_rootfs->unlock(fl);
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
    irqflags_t fl = g_rootfs->lock();   /* gate BOTH ends + link in ONE hold */
    int r = 0;
    {
        uint32_t sino;
        if (g_rootfs->open(rold, &sino) == 0)
            r = sensitive_write_gate(sino);
        if (r == 0 && g_rootfs->open(rnew, &sino) == 0)
            r = sensitive_write_gate(sino);
    }
    if (r == 0)
        r = g_rootfs->link(rold, rnew, has_install);
    g_rootfs->unlock(fl);
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

    char kbuf[256];

    /* Clamp in 64-bit BEFORE narrowing to uint32, and reject 0. A bufsiz of
     * exactly 2^32 would otherwise truncate to 0 here, and a 0 reaching the
     * backend underflows its `bufsiz - 1` into a ~4G-byte copy (the backend
     * rejects it too — this is the defence-in-depth half). */
    if (arg3 == 0)
        return SYS_ERR(EINVAL);
    uint32_t bufsiz = (arg3 > sizeof(kbuf)) ? (uint32_t)sizeof(kbuf)
                                            : (uint32_t)arg3;

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

    int n = g_rootfs->readlink(resolved, kbuf, bufsiz);
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

    /* Validate and mutate under ONE ext2_lock hold — see meta_gate_locked. */
    irqflags_t fl = g_rootfs->lock();
    int r = meta_gate_locked(resolved, proc, 1 /* follow */);
    if (r == 0)
        r = g_rootfs->chmod(resolved, (uint16_t)arg2, has_install);
    g_rootfs->unlock(fl);
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

    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_READ) == 0);

    /* No GIVE-AWAY chown. meta_gate_locked already requires the caller to own
     * the file, but owning it did not stop handing it to somebody else — and
     * "chown it to the account I want to attack, then let them run it" is the
     * classic setup. An unprivileged caller may only chown to itself (a no-op
     * on uid, useful for gid); anything else needs INSTALL, which is the
     * authority the installer legitimately uses to place files for a service.
     * (uint32_t)-1 means "unchanged", per POSIX. */
    if (!has_install && (uint32_t)arg2 != 0xFFFFFFFFu &&
        (uint32_t)arg2 != proc->uid)
        return SYS_ERR(EPERM);

    /* Validate and mutate under ONE ext2_lock hold — see meta_gate_locked. */
    irqflags_t fl = g_rootfs->lock();
    int r = meta_gate_locked(resolved, proc, 1 /* follow */);
    if (r == 0)
        r = g_rootfs->chown(resolved, (uint16_t)arg2, (uint16_t)arg3, 1, has_install);
    g_rootfs->unlock(fl);
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
        if (g_rootfs->open(resolved, &ino) == 0) {
            ext2_inode_t inode;
            if (g_rootfs->read_inode(ino, &inode) == 0 && proc->uid != inode.i_uid)
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
        /* struct timespec[2]: two {int64 tv_sec; int64 tv_nsec} = 32 bytes.
         * Validate first: copy_from_user does not range-check, and ts[0]/ts[2]
         * land in the inode where stat() reads them back — an unvalidated arg3
         * is a 4-byte-at-a-time arbitrary kernel read oracle. */
        int64_t ts[4];
        if (!user_ptr_valid(arg3, sizeof(ts)))
            return SYS_ERR(EFAULT);
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

    int follow = (arg4 & 0x100) ? 0 : 1;  /* AT_SYMLINK_NOFOLLOW */

    /* Validate and mutate under ONE ext2_lock hold — see meta_gate_locked. The
     * copy_from_user above deliberately happens BEFORE the acquire: it can
     * fault, and faulting under the lock is a needless hazard when the value is
     * not needed until now. */
    irqflags_t fl = g_rootfs->lock();
    int r = meta_gate_locked(resolved, proc, follow);
    if (r == 0)
        r = g_rootfs->utimes(resolved, atime, mtime, follow, has_install);
    g_rootfs->unlock(fl);
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

    int has_install = (cap_check(proc->caps, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                                 CAP_RIGHTS_READ) == 0);

    /* No give-away chown — see sys_chown. */
    if (!has_install && (uint32_t)arg2 != 0xFFFFFFFFu &&
        (uint32_t)arg2 != proc->uid)
        return SYS_ERR(EPERM);

    /* Validate and mutate under ONE ext2_lock hold — see meta_gate_locked.
     * follow = 0: lchown operates on the link itself. */
    irqflags_t fl = g_rootfs->lock();
    int r = meta_gate_locked(resolved, proc, 0 /* no follow */);
    if (r == 0)
        r = g_rootfs->chown(resolved, (uint16_t)arg2, (uint16_t)arg3, 0, has_install);
    g_rootfs->unlock(fl);
    return (r < 0) ? (uint64_t)(int64_t)r : 0;
}
