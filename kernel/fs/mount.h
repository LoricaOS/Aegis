#ifndef AEGIS_MOUNT_H
#define AEGIS_MOUNT_H

/* mount.h — the dynamic mount table.
 *
 * The VFS has a fixed set of BUILTIN mounts wired into vfs.c by path prefix
 * (/, /proc, /dev, /tmp, /run — see vfs_open). This table adds DYNAMIC mounts
 * created at runtime by sys_mount(): it is consulted first, so a dynamic mount
 * shadows nothing but the subtree it covers. v1 mounts tmpfs (a fresh ramfs
 * instance) only, and sys_mount restricts targets to the /mnt tree so a mount
 * can never shadow /, /etc/aegis, /bin, or any security-relevant tree. */

#include <stdint.h>

#define MOUNT_FS_NONE   0
#define MOUNT_FS_TMPFS  1   /* a fresh ramfs instance (ctx = ramfs_t *) */

/* mount_add — register `ctx` (an fs instance) as `fstype` at absolute path
 * `target` (canonical, no trailing slash). Returns 0, or -EEXIST / -ENOSPC /
 * -ENAMETOOLONG. */
int mount_add(const char *target, int fstype, void *ctx);

/* mount_remove — remove the mount at exactly `target`. On success writes its
 * ctx to *ctx_out (caller frees) and returns the fstype; -EINVAL if none. */
int mount_remove(const char *target, void **ctx_out);

/* Atomically refuse removal while a routed VFS operation or an open tmpfs
 * handle still owns the mount context. */
int mount_remove_idle(const char *target, void **ctx_out);

/* mount_acquire — longest-prefix match of `path`, retaining the context until
 * mount_release. Sets *ctx and *rel (relative path, no leading slash). */
int mount_acquire(const char *path, void **ctx, const char **rel);
void mount_release(void *ctx);

#endif /* AEGIS_MOUNT_H */
