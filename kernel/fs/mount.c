/* mount.c — the dynamic mount table (see mount.h).
 *
 * A small fixed table of {target, fstype, ctx}. sys_mount adds entries,
 * sys_umount removes them, and the VFS calls mount_resolve() on every path to
 * route dynamic mounts before the builtin prefix chain.
 *
 * Concurrency ceiling (ponytail): the table is spinlock-guarded, but a ctx
 * pointer handed back by mount_resolve is NOT refcounted — a concurrent
 * umount that frees the instance while another CPU holds the resolved ctx is a
 * use-after-free. mount/umount are CAP_KIND_MOUNT-gated privileged ops and
 * umount of a busy mount is a caller error; per-mount refcounting is the
 * upgrade path if that ceiling is ever hit.
 */
#include "mount.h"
#include "spinlock.h"
#include "../include/aegis_errno.h"
#include <stddef.h>

#define MOUNT_MAX        16
#define MOUNT_TARGET_MAX 64

typedef struct {
    char     target[MOUNT_TARGET_MAX];
    uint32_t target_len;
    int      fstype;
    void    *ctx;
    int      in_use;
} mount_ent_t;

static mount_ent_t s_mounts[MOUNT_MAX];
static spinlock_t  mount_lock = SPINLOCK_INIT;

static uint32_t m_strlen(const char *s)
{
    uint32_t n = 0;
    while (s[n]) n++;
    return n;
}

static int m_streqn(const char *a, const char *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

int mount_add(const char *target, int fstype, void *ctx)
{
    uint32_t len = m_strlen(target);
    if (len == 0 || len >= MOUNT_TARGET_MAX) return -ENAMETOOLONG;

    irqflags_t fl = spin_lock_irqsave(&mount_lock);
    int free_slot = -1;
    for (int i = 0; i < MOUNT_MAX; i++) {
        if (!s_mounts[i].in_use) { if (free_slot < 0) free_slot = i; continue; }
        if (s_mounts[i].target_len == len &&
            m_streqn(s_mounts[i].target, target, len)) {
            spin_unlock_irqrestore(&mount_lock, fl);
            return -EEXIST;
        }
    }
    if (free_slot < 0) {
        spin_unlock_irqrestore(&mount_lock, fl);
        return -ENOSPC;
    }
    mount_ent_t *m = &s_mounts[free_slot];
    for (uint32_t i = 0; i < len; i++) m->target[i] = target[i];
    m->target[len] = '\0';
    m->target_len  = len;
    m->fstype      = fstype;
    m->ctx         = ctx;
    m->in_use      = 1;
    spin_unlock_irqrestore(&mount_lock, fl);
    return 0;
}

int mount_remove(const char *target, void **ctx_out)
{
    uint32_t len = m_strlen(target);
    irqflags_t fl = spin_lock_irqsave(&mount_lock);
    for (int i = 0; i < MOUNT_MAX; i++) {
        if (s_mounts[i].in_use && s_mounts[i].target_len == len &&
            m_streqn(s_mounts[i].target, target, len)) {
            int ft = s_mounts[i].fstype;
            if (ctx_out) *ctx_out = s_mounts[i].ctx;
            s_mounts[i].in_use     = 0;
            s_mounts[i].ctx        = NULL;
            s_mounts[i].target_len = 0;
            spin_unlock_irqrestore(&mount_lock, fl);
            return ft;
        }
    }
    spin_unlock_irqrestore(&mount_lock, fl);
    return -EINVAL;
}

int mount_resolve(const char *path, void **ctx, const char **rel)
{
    if (!path || path[0] != '/') return MOUNT_FS_NONE;

    irqflags_t fl = spin_lock_irqsave(&mount_lock);
    int      best = -1;
    uint32_t best_len = 0;
    for (int i = 0; i < MOUNT_MAX; i++) {
        if (!s_mounts[i].in_use) continue;
        uint32_t L = s_mounts[i].target_len;
        /* path is covered iff it equals target or continues with '/', so a
         * mount at /mnt/x never matches /mnt/xyz. */
        if (m_streqn(path, s_mounts[i].target, L) &&
            (path[L] == '\0' || path[L] == '/')) {
            if (best < 0 || L > best_len) { best = i; best_len = L; }
        }
    }
    if (best < 0) {
        spin_unlock_irqrestore(&mount_lock, fl);
        return MOUNT_FS_NONE;
    }
    int ft = s_mounts[best].fstype;
    if (ctx) *ctx = s_mounts[best].ctx;
    if (rel) {
        const char *r = path + best_len;   /* stable: into the caller's buffer */
        if (*r == '/') r++;
        *rel = r;
    }
    spin_unlock_irqrestore(&mount_lock, fl);
    return ft;
}
