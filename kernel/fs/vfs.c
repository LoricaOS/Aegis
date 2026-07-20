#include "vfs.h"
#include "ext2_vfs.h"
#include "initrd.h"
#include "ext2.h"
#include "ramfs.h"
#include "mount.h"
#include "procfs.h"
#include "pty.h"
#include "printk.h"
#include "uaccess.h"
#include "cap.h"
#include "sched.h"
#include "proc.h"
#include "dev_table.h"
#include "../include/aegis_errno.h"
#include <stdint.h>

static ramfs_t s_run_ramfs;
static ramfs_t s_tmp_ramfs;

void
vfs_init(void)
{
    ramfs_init(&s_run_ramfs);
    ramfs_init(&s_tmp_ramfs);
    printk("[VFS] OK: initialized\n");
    initrd_register();
    procfs_init();
}

/* ── vfs_open ─────────────────────────────────────────────────────────── */

/*
 * vfs_open — resolve path to a vfs_file_t across all registered backends.
 *
 * Priority order:
 *   1. /dev/ptmx, /dev/pts/N -> PTY
 *   2. /proc/  -> procfs
 *   3. /dev/   -> initrd (device files: tty, urandom, random)
 *   4. /tmp/   -> tmp ramfs (volatile storage)
 *   5. /run/   -> run ramfs
 *   6. ext2 primary (writable root)
 *   7. initrd fallback (read-only boot files)
 *
 * flags: open flags forwarded from sys_open.  VFS_O_CREAT causes vfs_open
 *        to call ext2_create() if the file is not found on ext2.
 *
 * Returns 0 on success, -2 (ENOENT) if not found, -12 (ENOMEM) if the
 * ext2 fd pool is exhausted.
 */
/* is_ramfs_path — returns the ramfs instance backing a "/tmp/..." or
 * "/run/..." path (and sets *rel to the name within it), else NULL. */
static ramfs_t *
ramfs_for_path(const char *path, const char **rel)
{
    if (path[0]=='/' && path[1]=='t' && path[2]=='m' && path[3]=='p' && path[4]=='/') {
        *rel = path + 5;
        return &s_tmp_ramfs;
    }
    if (path[0]=='/' && path[1]=='r' && path[2]=='u' && path[3]=='n' && path[4]=='/') {
        *rel = path + 5;
        return &s_run_ramfs;
    }
    /* Dynamic tmpfs mounts (sys_mount) — routes unlink/mkdir/rmdir/rename too. */
    {
        void *ctx;
        if (mount_resolve(path, &ctx, rel) == MOUNT_FS_TMPFS)
            return (ramfs_t *)ctx;
    }
    return (ramfs_t *)0;
}

/* vfs_ramfs_unlink — if path is on a ramfs mount, unlink it there and set
 * *out_rc; returns 1 if handled, 0 if not a ramfs path (use ext2). */
int
vfs_ramfs_unlink(const char *path, int *out_rc)
{
    const char *rel;
    ramfs_t *r = ramfs_for_path(path, &rel);
    if (!r) return 0;
    *out_rc = ramfs_unlink(r, rel);
    return 1;
}

/* vfs_ramfs_mkdir — if path is on a ramfs mount, create a directory marker
 * there and set *out_rc; returns 1 if handled, 0 if not a ramfs path. */
int
vfs_ramfs_mkdir(const char *path, int *out_rc)
{
    const char *rel;
    /* The ramfs mount roots /tmp and /run always exist. A create-parents
     * mkdir (mkdir -p) walks each component and mkdir's the root first; it
     * must see EEXIST (which callers ignore), not fall through to ext2 which
     * returns EPERM and aborts the whole operation (broke Ladybird startup). */
    {
        const char *p = path;
        int is_root =
            ((p[0]=='/'&&p[1]=='t'&&p[2]=='m'&&p[3]=='p'&&(p[4]=='\0'||(p[4]=='/'&&p[5]=='\0'))) ||
             (p[0]=='/'&&p[1]=='r'&&p[2]=='u'&&p[3]=='n'&&(p[4]=='\0'||(p[4]=='/'&&p[5]=='\0'))));
        if (is_root) { *out_rc = -17; /* EEXIST */ return 1; }
    }
    ramfs_t *r = ramfs_for_path(path, &rel);
    if (!r) return 0;
    *out_rc = ramfs_mkdir(r, rel);
    return 1;
}

/* vfs_ramfs_rmdir — if path is on a ramfs mount, remove the directory there
 * and set *out_rc; returns 1 if handled, 0 if not a ramfs path. Without this
 * sys_rmdir fell through to ext2_rmdir, which returns EPERM for any path it
 * does not own — so mkdir /tmp/x worked (it routes) but rmdir /tmp/x did not. */
int
vfs_ramfs_rmdir(const char *path, int *out_rc)
{
    const char *rel;
    /* The mount roots themselves are not removable. */
    {
        const char *p = path;
        int is_root =
            ((p[0]=='/'&&p[1]=='t'&&p[2]=='m'&&p[3]=='p'&&(p[4]=='\0'||(p[4]=='/'&&p[5]=='\0'))) ||
             (p[0]=='/'&&p[1]=='r'&&p[2]=='u'&&p[3]=='n'&&(p[4]=='\0'||(p[4]=='/'&&p[5]=='\0'))));
        if (is_root) { *out_rc = -EBUSY; return 1; }
    }
    ramfs_t *r = ramfs_for_path(path, &rel);
    if (!r) return 0;
    *out_rc = ramfs_rmdir(r, rel);
    return 1;
}

/* vfs_ramfs_rename — same-mount rename on a ramfs. Cross-mount renames
 * return EXDEV. Returns 1 if handled, 0 if neither path is ramfs. */
int
vfs_ramfs_rename(const char *oldp, const char *newp, int *out_rc)
{
    const char *orel, *nrel;
    ramfs_t *ro = ramfs_for_path(oldp, &orel);
    ramfs_t *rn = ramfs_for_path(newp, &nrel);
    if (!ro && !rn) return 0;
    if (ro != rn) { *out_rc = -18; return 1; }   /* EXDEV: cross-device */
    *out_rc = ramfs_rename(ro, orel, nrel);
    return 1;
}

/* vfs_open — read-only / non-authorized wrapper. Callers that don't create
 * under install-protected trees use this (has_install=0 is safe because a
 * non-O_CREAT open never reaches the ext2 create path). Create-with-authority
 * callers (sys_open with the caller's INSTALL cap, sys_adminconf which is
 * POWER-authorized) use vfs_open_ex directly. */
int
vfs_open(const char *path, int flags, uint16_t create_mode, vfs_file_t *out)
{
    return vfs_open_ex(path, flags, create_mode, out, 0);
}

int
vfs_open_ex(const char *path, int flags, uint16_t create_mode, vfs_file_t *out,
            int has_install)
{
    /* Default: not protected. Non-ext2 backends below don't touch kflags, so
     * this prevents a stale VFS_KF_PROTECTED bit leaking from a reused slot. */
    out->kflags = 0;

    /* /dev/ptmx → allocate PTY master */
    if (path[0]=='/' && path[1]=='d' && path[2]=='e' && path[3]=='v' && path[4]=='/' &&
        path[5]=='p' && path[6]=='t' && path[7]=='m' && path[8]=='x' && path[9]=='\0')
        return ptmx_open(flags, out);

    /* /dev/pts/N → open PTY slave */
    if (path[0]=='/' && path[1]=='d' && path[2]=='e' && path[3]=='v' && path[4]=='/' &&
        path[5]=='p' && path[6]=='t' && path[7]=='s' && path[8]=='/') {
        uint32_t idx = 0;
        const char *s = path + 9;
        while (*s >= '0' && *s <= '9')
            idx = idx * 10 + (uint32_t)(*s++ - '0');
        if (*s != '\0') return -ENOENT;
        return pts_open(idx, flags, out);
    }

    /* /proc/ → procfs */
    if (path[0]=='/' && path[1]=='p' && path[2]=='r' && path[3]=='o' &&
        path[4]=='c' && (path[5]=='/' || path[5]=='\0'))
        return procfs_open(path[5]=='/' ? path + 6 : path + 5, flags, out);

    /* /dev/ -> initrd (device files: tty, urandom, random, directory) */
    if (path[0]=='/' && path[1]=='d' && path[2]=='e' && path[3]=='v' &&
        (path[4]=='/' || path[4]=='\0'))
        return initrd_open(path, out);

    /* /tmp or /tmp/ -> tmp ramfs */
    if (path[0]=='/' && path[1]=='t' && path[2]=='m' && path[3]=='p') {
        if (path[4] == '\0')
            return ramfs_opendir(&s_tmp_ramfs, out);
        if (path[4] == '/')
            return ramfs_open(&s_tmp_ramfs, path + 5, flags, out);
    }

    /* /run or /run/ -> run ramfs */
    if (path[0]=='/' && path[1]=='r' && path[2]=='u' && path[3]=='n') {
        if (path[4] == '\0')
            return ramfs_opendir(&s_run_ramfs, out);
        if (path[4] == '/')
            return ramfs_open(&s_run_ramfs, path + 5, flags, out);
    }

    /* Dynamic mounts (sys_mount): a tmpfs subtree, e.g. under /mnt. Checked
     * before ext2 so the mount shadows the (empty) mountpoint dir. */
    {
        void *ctx;
        const char *rel;
        if (mount_resolve(path, &ctx, &rel) == MOUNT_FS_TMPFS) {
            if (*rel == '\0')
                return ramfs_opendir((ramfs_t *)ctx, out);
            return ramfs_open((ramfs_t *)ctx, rel, flags, out);
        }
    }

    /* ext2 primary — writable root filesystem */
    {
        uint32_t ino = 0;
        int is_protected = 0;
        /* Resolve and classify-as-protected under ONE ext2_lock hold so an SMP
         * symlink-swap can't substitute a different target between the two — see
         * ext2_open_protected. This is the authoritative, atomic replacement for
         * sys_open's racy cap_path_is_protected() pre-check. */
        if (ext2_open_protected(path, &ino, &is_protected) >= 0) {
            /* O_CREAT|O_EXCL on an existing file: fail EEXIST (atomic create). */
            if ((flags & (int)VFS_O_CREAT) && (flags & (int)VFS_O_EXCL))
                return -EEXIST;
            /* DAC permission check */
            if (sched_current()->is_user) {
                aegis_process_t *pr = current_proc();
                int want = 4;  /* R_OK by default (O_RDONLY=0) */
                if (flags & 1) want = 2;       /* O_WRONLY */
                if (flags & 2) want = 4 | 2;   /* O_RDWR */
                int perm = ext2_check_perm(ino,
                    (uint16_t)pr->uid, (uint16_t)pr->gid, want);
                if (perm != 0)
                    return -EACCES;
            }
            /* Post-resolution capability gate: /etc/shadow and the admin
             * credential /etc/aegis/admin both require CAP_KIND_AUTH even for
             * uid=0.  This check runs AFTER ext2_open resolves symlinks, so
             * "ln -s /etc/shadow /tmp/x" + open("/tmp/x") cannot bypass it.
             * The resolved inode is compared against the shadow/admin inodes
             * recorded at mount time. */
            {
                uint32_t shadow_ino = ext2_get_shadow_ino();
                uint32_t admin_ino  = ext2_get_admin_ino();
                if (sched_current()->is_user &&
                    ((shadow_ino != 0 && ino == shadow_ino) ||
                     (admin_ino  != 0 && ino == admin_ino))) {
                    aegis_process_t *pr = current_proc();
                    if (cap_check(pr->caps, CAP_TABLE_SIZE,
                                  CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0)
                        return -EACCES;
                }
            }
            /* Account-DB write gate: /etc/passwd and /etc/group are world-
             * readable (login/id/ls -l read them) but admin-managed.  The live
             * user is cosmetic uid 0 and OWNS these uid-0 files, so ext2 DAC
             * alone would grant owner-write — letting a baseline session append
             * a uid-0 account or clobber the DB.  Require an admin_session for
             * any WRITE-intent open (O_WRONLY/O_RDWR/O_TRUNC/O_APPEND); reads are
             * untouched.  Keyed on the resolved inode (post symlink/".."), so a
             * symlink alias cannot bypass it.  Mirrors the shadow/admin gate
             * above; the same inodes are also gated in the sys_dir/sys_meta
             * mutators (rename-over/unlink/chmod/…). */
            {
                uint32_t passwd_ino = ext2_get_passwd_ino();
                uint32_t group_ino  = ext2_get_group_ino();
                if (sched_current()->is_user &&
                    ((passwd_ino != 0 && ino == passwd_ino) ||
                     (group_ino  != 0 && ino == group_ino))) {
                    int wr = (flags & 1) || (flags & 2) ||
                             (flags & (int)VFS_O_TRUNC) ||
                             (flags & (int)VFS_O_APPEND);
                    if (wr && current_proc()->admin_session == 0)
                        return -EACCES;
                }
            }
            /* Install-protected write gate: overwriting an EXISTING trusted
             * binary (anything under /bin, /sbin, /apps, /etc/aegis, or a
             * registered anchor) needs CAP_KIND_INSTALL, exactly like creating
             * one does (sys_open's create path + ext2_create's has_install arg).
             * The live session is cosmetic uid 0 and OWNS these uid-0 files, so
             * ext2 DAC alone would grant owner-write — letting a baseline
             * process open("/bin/login", O_WRONLY) and swap init/login/aegisctl
             * for a trojan (full privesc). `is_protected` was resolved under the
             * same ext2_lock hold as the inode (ext2_open_protected), so unlike
             * the old sys_open pre-check this cannot be raced by an SMP
             * symlink-swap. Runs only for user opens; kernel-internal writers
             * (!is_user) and INSTALL-holders (installer/herald) are unaffected.
             * Mirrors the shadow/admin (CAP_AUTH) and passwd/group
             * (admin_session) gates above. */
            {
                int wr = (flags & 1) || (flags & 2) ||
                         (flags & (int)VFS_O_TRUNC) ||
                         (flags & (int)VFS_O_APPEND);
                if (sched_current()->is_user && is_protected && wr &&
                    !has_install)
                    return -EACCES;
            }
            /* O_TRUNC: drop to length 0 AND free the data blocks.  Setting
             * i_size = 0 alone (the old behaviour) leaked every data/indirect
             * block of the file on each truncate. */
            if (flags & (int)VFS_O_TRUNC)
                ext2_truncate(ino);
            ext2_fd_priv_t *p = ext2_pool_alloc(ino);
            if (!p) return -ENOMEM;
            int sz = ext2_file_size(ino);
            if (sz < 0) sz = 0;
            /* O_APPEND: start writing at end of file */
            if (flags & (int)VFS_O_APPEND)
                p->write_offset = (uint32_t)sz;
            out->ops    = &s_ext2_ops;
            out->priv   = (void *)p;
            out->offset = 0;
            out->size   = (uint64_t)sz;
            out->flags  = 0;
            /* Tag fds onto install-protected files so fd-based fchmod/fchown/
             * ftruncate can't bypass the path-based install gate (the inode is
             * resolved, so symlinks/".."/read-only opens are all covered).
             * Reuses the atomically-resolved is_protected (same value
             * cap_path_is_protected would return, minus a redundant walk). */
            out->kflags = is_protected ? VFS_KF_PROTECTED : 0;
            return 0;
        }
        /* ext2 ENOENT + O_CREAT → check W+X on parent, then create */
        if (flags & (int)VFS_O_CREAT) {
            uint32_t parent_ino;
            const char *bname;
            if (ext2_lookup_parent(path, &parent_ino, &bname) == 0 &&
                sched_current()->is_user) {
                aegis_process_t *pr = current_proc();
                int pperm = ext2_check_perm(parent_ino,
                    (uint16_t)pr->uid, (uint16_t)pr->gid, 2 | 1); /* W+X */
                if (pperm != 0)
                    return -EACCES;
            }
            if (ext2_create(path, create_mode ? create_mode : 0644, has_install) == 0) {
                if (ext2_open(path, &ino) >= 0) {
                    ext2_fd_priv_t *p = ext2_pool_alloc(ino);
                    if (!p) return -ENOMEM;
                    out->ops    = &s_ext2_ops;
                    out->priv   = (void *)p;
                    out->offset = 0;
                    out->size   = 0;
                    out->flags  = 0;
                    out->kflags = cap_path_is_protected(path) ? VFS_KF_PROTECTED : 0;
                    return 0;
                }
            }
        }
    }

    /* initrd fallback — read-only boot files */
    if (initrd_open(path, out) == 0) {
        /* Capability gate on initrd /etc/shadow — same as ext2 path.
         * initrd has no symlinks, so the path string is already canonical. */
        if (path[0]=='/' && path[1]=='e' && path[2]=='t' && path[3]=='c' &&
            path[4]=='/' && path[5]=='s' && path[6]=='h' && path[7]=='a' &&
            path[8]=='d' && path[9]=='o' && path[10]=='w' && path[11]=='\0') {
            if (sched_current()->is_user) {
                aegis_process_t *pr = current_proc();
                if (cap_check(pr->caps, CAP_TABLE_SIZE,
                              CAP_KIND_AUTH, CAP_RIGHTS_READ) != 0) {
                    /* Close the fd that initrd_open just populated */
                    if (out->ops && out->ops->close)
                        out->ops->close(out->priv);
                    out->ops = (void *)0;
                    return -EACCES;
                }
            }
        }
        return 0;
    }

    return -ENOENT;
}

/* ── helpers ──────────────────────────────────────────────────────────── */

static int
streq(const char *a, const char *b)
{
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == *b;
}

/*
 * vfs_stat_path — fill *out with stat for the file at path.
 *
 * Priority order:
 *   1. /proc or /proc/  -> procfs stat
 *   2. /dev/ device specials -> synthetic chardev stat
 *   3. Synthetic dirs: /dev, /proc, /tmp, /run -> S_IFDIR|0555
 *   4. /tmp/  -> tmp ramfs stat
 *   5. /run/  -> run ramfs stat
 *   6. ext2 primary -> disk inode stat
 *   7. initrd fallback -> static file stat
 *
 * Returns 0 on success, -2 (ENOENT) if not found.
 */
int
vfs_stat_path(const char *path, k_stat_t *out)
{
    if (!path || !out) return -ENOENT;

    /* /proc → procfs stat */
    if (path[0]=='/' && path[1]=='p' && path[2]=='r' && path[3]=='o' &&
        path[4]=='c' && (path[5]=='/' || path[5]=='\0'))
        return procfs_stat(path, out);

    /* /dev/ device specials — single source of truth in s_dev_table.
     * dev_table_stat covers: console family, urandom/random, null, mouse,
     * ptmx.  /dev/pts (directory) and /dev/pts/N (slave) stay bespoke below. */
    if (dev_table_stat(path, out) == 0) return 0;

    if (streq(path, "/dev/pts")) {
        __builtin_memset(out, 0, sizeof(*out));
        out->st_dev   = 1;
        out->st_ino   = 7;
        out->st_nlink = 2;
        out->st_mode  = S_IFDIR | 0755;
        return 0;
    }

    if (path[0]=='/' && path[1]=='d' && path[2]=='e' && path[3]=='v' && path[4]=='/' &&
        path[5]=='p' && path[6]=='t' && path[7]=='s' && path[8]=='/') {
        __builtin_memset(out, 0, sizeof(*out));
        out->st_mode  = S_IFCHR | 0620;
        out->st_ino   = 8;
        out->st_rdev  = makedev(136, 0);
        out->st_dev   = 1;
        out->st_nlink = 1;
        return 0;
    }

    /* Synthetic directory stat for pseudo-fs mount points */
    if (streq(path, "/dev") || streq(path, "/proc") ||
        streq(path, "/tmp") || streq(path, "/run")) {
        __builtin_memset(out, 0, sizeof(*out));
        out->st_dev   = 1;
        out->st_ino   = 1;
        out->st_nlink = 2;
        out->st_mode  = S_IFDIR | 0555;
        return 0;
    }

    /* /tmp/ -> tmp ramfs stat */
    if (path[0]=='/' && path[1]=='t' && path[2]=='m' && path[3]=='p' && path[4]=='/')
        return ramfs_stat(&s_tmp_ramfs, path + 5, out);

    /* /run/ -> run ramfs stat */
    if (path[0]=='/' && path[1]=='r' && path[2]=='u' && path[3]=='n' && path[4]=='/')
        return ramfs_stat(&s_run_ramfs, path + 5, out);

    /* Dynamic mounts (sys_mount): tmpfs subtree */
    {
        void *ctx;
        const char *rel;
        if (mount_resolve(path, &ctx, &rel) == MOUNT_FS_TMPFS) {
            if (*rel == '\0') {
                /* the mount root itself — a synthetic directory */
                __builtin_memset(out, 0, sizeof(*out));
                out->st_dev   = 1;
                out->st_ino   = 1;
                out->st_nlink = 2;
                out->st_mode  = S_IFDIR | 0755;
                return 0;
            }
            return ramfs_stat((ramfs_t *)ctx, rel, out);
        }
    }

    /* ext2 primary */
    {
        uint32_t ino = 0;
        if (ext2_open(path, &ino) == 0) {
            int sz = ext2_file_size(ino);
            if (sz < 0) sz = 0;
            ext2_inode_t inode;
            uint32_t mode;
            if (ext2_read_inode(ino, &inode) == 0)
                mode = (uint32_t)inode.i_mode;
            else
                mode = S_IFREG | 0644;
            __builtin_memset(out, 0, sizeof(*out));
            out->st_dev     = 2;
            out->st_ino     = (uint64_t)ino;
            out->st_nlink   = inode.i_links_count ? inode.i_links_count : 1;
            out->st_mode    = mode;
            out->st_uid     = (uint32_t)inode.i_uid;
            out->st_gid     = (uint32_t)inode.i_gid;
            out->st_size    = (int64_t)sz;
            out->st_blksize = 4096;
            out->st_blocks  = (int64_t)(((uint64_t)sz + 511) / 512);
            /* Real inode times (ext2 stores 32-bit unix seconds) so `ls -l`,
             * make, and git see actual dates instead of the epoch. */
            out->st_atime   = (int64_t)inode.i_atime;
            out->st_mtime   = (int64_t)inode.i_mtime;
            out->st_ctime   = (int64_t)inode.i_ctime;
            return 0;
        }
    }

    /* initrd fallback */
    if (initrd_stat_entry(path, out) == 0)
        return 0;

    return -ENOENT;
}

/*
 * vfs_stat_path_ex — stat with symlink-follow control.
 *
 * follow: 1 = follow symlinks on final component (stat behavior)
 *         0 = do not follow (lstat behavior)
 *
 * For non-ext2 paths (procfs, /dev, /tmp, /run, initrd), delegates to
 * vfs_stat_path — those filesystems have no symlinks.
 * For ext2 paths, uses ext2_open_ex with the follow parameter.
 * Also populates st_uid and st_gid from the on-disk inode.
 */
int
vfs_stat_path_ex(const char *path, k_stat_t *out, int follow)
{
    if (!path || !out) return -ENOENT;

    /* Dynamic mounts (tmpfs): no symlinks, delegate to vfs_stat_path */
    {
        void *ctx;
        const char *rel;
        if (mount_resolve(path, &ctx, &rel) != MOUNT_FS_NONE)
            return vfs_stat_path(path, out);
    }

    /* Non-ext2 paths: no symlinks, delegate to vfs_stat_path */
    if ((path[0]=='/' && path[1]=='p' && path[2]=='r' && path[3]=='o' &&
         path[4]=='c' && (path[5]=='/' || path[5]=='\0')) ||
        (path[0]=='/' && path[1]=='d' && path[2]=='e' && path[3]=='v' &&
         (path[4]=='/' || path[4]=='\0')) ||
        (path[0]=='/' && path[1]=='t' && path[2]=='m' && path[3]=='p' &&
         (path[4]=='/' || path[4]=='\0')) ||
        (path[0]=='/' && path[1]=='r' && path[2]=='u' && path[3]=='n' &&
         (path[4]=='/' || path[4]=='\0')))
        return vfs_stat_path(path, out);

    /* ext2 primary — use ext2_open_ex for symlink control */
    {
        uint32_t ino = 0;
        if (ext2_open_ex(path, &ino, follow) == 0) {
            ext2_inode_t inode;
            int sz = ext2_file_size(ino);
            if (sz < 0) sz = 0;
            __builtin_memset(out, 0, sizeof(*out));
            out->st_dev     = 2;
            out->st_ino     = (uint64_t)ino;
            out->st_nlink   = 1;
            if (ext2_read_inode(ino, &inode) == 0) {
                out->st_mode = (uint32_t)inode.i_mode;
                out->st_uid  = (uint32_t)inode.i_uid;
                out->st_gid  = (uint32_t)inode.i_gid;
                out->st_nlink = inode.i_links_count ? inode.i_links_count : 1;
                out->st_atime = (int64_t)inode.i_atime;
                out->st_mtime = (int64_t)inode.i_mtime;
                out->st_ctime = (int64_t)inode.i_ctime;
            } else {
                out->st_mode = S_IFREG | 0644;
            }
            out->st_size    = (int64_t)sz;
            out->st_blksize = 4096;
            out->st_blocks  = (int64_t)(((uint64_t)sz + 511) / 512);
            return 0;
        }
    }

    /* initrd fallback */
    if (initrd_stat_entry(path, out) == 0)
        return 0;

    return -ENOENT;
}

/*
 * vfs_fchmod — change permission bits on an open ext2 fd.
 * Returns 0 on success, -1 if not an ext2 fd.
 */
int
vfs_fchmod(vfs_file_t *f, uint16_t mode)
{
    if (!f || f->ops != &s_ext2_ops) return -1;
    ext2_fd_priv_t *p = (ext2_fd_priv_t *)f->priv;
    ext2_inode_t inode;
    if (ext2_read_inode(p->ino, &inode) != 0) return -1;
    /* Preserve file type bits, replace permission bits */
    inode.i_mode = (inode.i_mode & 0xF000) | (mode & 0x0FFF);
    return ext2_write_inode(p->ino, &inode);
}

/*
 * vfs_fchown — change owner/group on an open ext2 fd.
 * Returns 0 on success, -1 if not an ext2 fd.
 */
int
vfs_fchown(vfs_file_t *f, uint16_t uid, uint16_t gid)
{
    if (!f || f->ops != &s_ext2_ops) return -1;
    ext2_fd_priv_t *p = (ext2_fd_priv_t *)f->priv;
    ext2_inode_t inode;
    if (ext2_read_inode(p->ino, &inode) != 0) return -1;
    inode.i_uid = uid;
    inode.i_gid = gid;
    return ext2_write_inode(p->ino, &inode);
}
