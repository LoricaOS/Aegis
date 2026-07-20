/* sys_mount.c — the mount(2) / umount(2) syscall surface.
 *
 * v1 mounts a fresh tmpfs (ramfs) instance into the /mnt tree. The whole
 * operation is gated on CAP_KIND_MOUNT and the target is restricted to the
 * /mnt subtree so a mount can never shadow /, /etc/aegis, /bin, or any
 * security-relevant path — that shadowing is a privilege-escalation primitive,
 * so it fails closed. See kernel/fs/mount.c for the table the VFS routes. */
#include "sys_impl.h"
#include "mount.h"
#include "ramfs.h"
#include "vfs.h"
#include "kva.h"
#include "cap.h"
#include "proc.h"
#include "sched.h"
#include "printk.h"
#include "../include/aegis_errno.h"
#include <stdint.h>

extern int copy_path_from_user(char *kpath, uint64_t user_ptr, uint32_t bufsz);

static int m_str_eq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

/* mount_target_ok — the security gate on the mount point. Must be a canonical
 * path strictly under /mnt/ with no ".." component and no trailing slash, so a
 * mount can only ever land inside the dedicated /mnt tree. */
static int mount_target_ok(const char *t)
{
    if (!(t[0]=='/' && t[1]=='m' && t[2]=='n' && t[3]=='t' &&
          t[4]=='/' && t[5]!='\0'))
        return 0;                                  /* not under /mnt/ */
    uint32_t n = 0;
    for (const char *p = t; *p; p++, n++) {
        /* reject a ".." path component (start-of-string or after '/') */
        if (p[0]=='.' && p[1]=='.' && (p[2]=='\0' || p[2]=='/') &&
            (p==t || p[-1]=='/'))
            return 0;
    }
    if (n > 0 && t[n-1] == '/')
        return 0;                                  /* no trailing slash */
    return 1;
}

static int mount_capable(void)
{
    if (!sched_current()->is_user) return 1;       /* kernel-internal */
    aegis_process_t *pr = current_proc();
    return cap_check(pr->caps, CAP_TABLE_SIZE,
                     CAP_KIND_MOUNT, CAP_RIGHTS_READ) == 0;
}

uint64_t
sys_mount(uint64_t source, uint64_t target_u, uint64_t fstype_u,
          uint64_t mountflags, uint64_t data)
{
    (void)source; (void)mountflags; (void)data;

    if (!mount_capable())
        return SYS_ERR(ENOCAP);

    char target[64];
    char fstype[16];
    if (copy_path_from_user(target, target_u, sizeof(target)) != 0)
        return SYS_ERR(EFAULT);
    if (copy_path_from_user(fstype, fstype_u, sizeof(fstype)) != 0)
        return SYS_ERR(EFAULT);

    if (!mount_target_ok(target))
        return SYS_ERR(EPERM);
    if (!(m_str_eq(fstype, "tmpfs") || m_str_eq(fstype, "ramfs")))
        return SYS_ERR(ENODEV);                    /* v1: tmpfs only */

    /* POSIX: the mountpoint must exist and be a directory. */
    k_stat_t st;
    if (vfs_stat_path(target, &st) != 0)
        return SYS_ERR(ENOENT);
    if ((st.st_mode & 0170000U) != S_IFDIR)
        return SYS_ERR(ENOTDIR);

    /* A tmpfs instance is ~553 KB — kva, allocated on demand, never BSS. */
    uint64_t pages = (sizeof(ramfs_t) + 4095) / 4096;
    ramfs_t *r = (ramfs_t *)kva_alloc_pages(pages);
    if (!r) return SYS_ERR(ENOMEM);
    ramfs_init(r);

    int rc = mount_add(target, MOUNT_FS_TMPFS, r);
    if (rc != 0) {
        kva_free_pages(r, pages);
        return (uint64_t)(int64_t)rc;              /* -EEXIST / -ENOSPC / … */
    }
    return 0;
}

uint64_t
sys_umount(uint64_t target_u, uint64_t flags)
{
    (void)flags;

    if (!mount_capable())
        return SYS_ERR(ENOCAP);

    char target[64];
    if (copy_path_from_user(target, target_u, sizeof(target)) != 0)
        return SYS_ERR(EFAULT);

    void *ctx = (void *)0;
    int ft = mount_remove(target, &ctx);
    if (ft < 0)
        return (uint64_t)(int64_t)ft;              /* -EINVAL: not mounted */
    if (ft == MOUNT_FS_TMPFS && ctx)
        kva_free_pages(ctx, (sizeof(ramfs_t) + 4095) / 4096);
    return 0;
}

/* ── mount_selftest — `mounttest` cmdline. Exercises the table + VFS routing
 * end to end at the kernel level (no userland/cap needed): mount a tmpfs, prove
 * a create/write/read round-trips through vfs_open, then umount and prove it is
 * gone. Bypasses the syscall wrapper (which is a thin cap+arg shell). ── */
void mount_selftest(void)
{
    const char *mp = "/mnt/selftest";
    uint64_t pages = (sizeof(ramfs_t) + 4095) / 4096;
    ramfs_t *r = (ramfs_t *)kva_alloc_pages(pages);
    if (!r) { printk("[MOUNTTEST] FAIL: kva\n"); return; }
    ramfs_init(r);
    if (mount_add(mp, MOUNT_FS_TMPFS, r) != 0) {
        printk("[MOUNTTEST] FAIL: mount_add\n");
        kva_free_pages(r, pages);
        return;
    }

    int ok = 1;
    vfs_file_t f;
    /* create + write via the routed VFS */
    if (vfs_open("/mnt/selftest/hi", VFS_O_CREAT | 1 /*O_WRONLY*/, 0644, &f) != 0) {
        printk("[MOUNTTEST] FAIL: create routed open\n"); ok = 0;
    } else {
        if (!f.ops || !f.ops->write ||
            f.ops->write(f.priv, "hello", 5) != 5) { printk("[MOUNTTEST] FAIL: write\n"); ok = 0; }
        if (f.ops && f.ops->close) f.ops->close(f.priv);
    }
    /* read back */
    if (ok) {
        char buf[8] = {0};
        vfs_file_t g;
        if (vfs_open("/mnt/selftest/hi", 0 /*O_RDONLY*/, 0, &g) != 0) {
            printk("[MOUNTTEST] FAIL: read routed open\n"); ok = 0;
        } else {
            int n = (g.ops && g.ops->read) ? g.ops->read(g.priv, buf, 0, 5) : -1;
            if (n != 5 || buf[0] != 'h' || buf[4] != 'o') {
                printk("[MOUNTTEST] FAIL: readback n=%d\n", n); ok = 0;
            }
            if (g.ops && g.ops->close) g.ops->close(g.priv);
        }
    }
    /* stat routes to the mount */
    if (ok) {
        k_stat_t st;
        if (vfs_stat_path("/mnt/selftest/hi", &st) != 0) {
            printk("[MOUNTTEST] FAIL: stat routed\n"); ok = 0;
        }
    }

    /* umount, then the path must no longer resolve to the tmpfs */
    void *ctx = (void *)0;
    if (mount_remove(mp, &ctx) < 0) { printk("[MOUNTTEST] FAIL: umount\n"); ok = 0; }
    if (ctx) kva_free_pages(ctx, pages);
    if (ok) {
        vfs_file_t h;
        if (vfs_open("/mnt/selftest/hi", 0, 0, &h) == 0) {
            printk("[MOUNTTEST] FAIL: file still visible after umount\n"); ok = 0;
            if (h.ops && h.ops->close) h.ops->close(h.priv);
        }
    }

    printk("[MOUNTTEST] %s\n", ok ? "PASS: mount/route/umount tmpfs" : "FAIL");
}
