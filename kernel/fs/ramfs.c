/* kernel/fs/ramfs.c — in-memory filesystem, multi-instance.
 * See ramfs.h for the inode/dentry design.  Inodes own data + identity;
 * dentries are flat-named links.  An inode is freed only when its last dentry
 * (nlink) and last open fd (open_count) are gone, so the vfs handle (priv =
 * inode*) is never aliased to the wrong file. */
#include "ramfs.h"
#include "kva.h"
#include "uaccess.h"
#include "syscall_util.h"
#include "spinlock.h"
#include "sched.h"
#include "proc.h"
#include "../include/aegis_errno.h"
#include <stdint.h>

/* ── string helpers ───────────────────────────────────────────────────── */

static int
rfs_streq(const char *a, const char *b)
{
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == *b;
}

static void
rfs_strcpy(char *dst, const char *src, uint32_t max)
{
    uint32_t i;
    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

/* rfs_name_ok — reject a name that would not fit the dentry.
 *
 * rfs_strcpy TRUNCATES, and these are flat relative paths ("a/b/c"), so two
 * long paths sharing a 127-byte prefix collapsed onto ONE dentry: the second
 * create silently returned the first file. Refuse instead of aliasing. */
static int
rfs_name_ok(const char *name)
{
    uint32_t i = 0;
    while (name[i]) {
        if (i >= RAMFS_MAX_NAMELEN - 1)
            return 0;
        i++;
    }
    return 1;
}

/* rfs_caller_uid — identity of the calling process, or a sentinel for
 * kernel-internal work (ramfs_populate at boot), which is unrestricted. */
#define RFS_KERNEL_UID 0xFFFFFFFFu
static uint32_t
rfs_caller_uid(void)
{
    aegis_task_t *t = sched_current();
    if (!t || !t->is_user)
        return RFS_KERNEL_UID;
    return current_proc()->uid;
}

/* rfs_may — DAC check against an inode. want: 4=read, 2=write.
 * No uid-0 bypass: authority in Aegis comes from capabilities, not from being
 * root. Kernel-internal callers pass through. */
static int
rfs_may(const ramfs_inode_t *n, uint32_t want)
{
    uint32_t uid = rfs_caller_uid();
    if (uid == RFS_KERNEL_UID)
        return 1;
    uint32_t bits = (uid == n->uid) ? (uint32_t)((n->mode >> 6) & 7)
                                    : (uint32_t)(n->mode & 7);
    return (bits & want) == want;
}

/* ── inode / dentry helpers (caller holds inst->lock) ─────────────────── */

static ramfs_dent_t *
dent_find(ramfs_t *inst, const char *name)
{
    uint32_t i;
    for (i = 0; i < RAMFS_MAX_DENTS; i++)
        if (inst->dents[i].in_use && rfs_streq(inst->dents[i].name, name))
            return &inst->dents[i];
    return (ramfs_dent_t *)0;
}

/* Allocate a fresh inode; returns index or -1. */
static int
inode_alloc(ramfs_t *inst)
{
    uint32_t i;
    for (i = 0; i < RAMFS_MAX_INODES; i++) {
        if (!inst->inodes[i].in_use) {
            ramfs_inode_t *n = &inst->inodes[i];
            n->in_use     = 1;
            n->is_dir     = 0;
            n->nlink      = 0;
            n->open_count = 0;
            n->size       = 0;
            n->npages     = 0;
            n->owner      = inst;
            uint32_t k;
            for (k = 0; k < RAMFS_PAGES_PER_FILE; k++)
                n->pages[k] = (uint8_t *)0;
            return (int)i;
        }
    }
    return -1;
}

/* Free an inode's data + slot once it has no dentry and no open fd. */
static void
inode_release(ramfs_inode_t *n)
{
    if (n->nlink != 0 || n->open_count != 0)
        return;
    uint32_t k;
    for (k = 0; k < n->npages; k++) {
        if (n->pages[k]) {
            kva_free_pages(n->pages[k], 1);
            n->pages[k] = (uint8_t *)0;
        }
    }
    n->npages = 0;
    n->size   = 0;
    n->in_use = 0;
}

/* Create a name → new-inode link. Returns the inode, or NULL (pools full). */
static ramfs_inode_t *
create_named(ramfs_t *inst, const char *name)
{
    uint32_t di;
    for (di = 0; di < RAMFS_MAX_DENTS; di++)
        if (!inst->dents[di].in_use)
            break;
    if (di == RAMFS_MAX_DENTS)
        return (ramfs_inode_t *)0;
    int ii = inode_alloc(inst);
    if (ii < 0)
        return (ramfs_inode_t *)0;
    inst->dents[di].in_use = 1;
    rfs_strcpy(inst->dents[di].name, name, RAMFS_MAX_NAMELEN);
    inst->dents[di].inode = (uint32_t)ii;
    inst->inodes[ii].nlink = 1;
    /* Stamp the creator's identity. Kernel-internal creates (ramfs_populate at
     * boot) land as uid 0 with the same default mode. */
    {
        uint32_t uid = rfs_caller_uid();
        inst->inodes[ii].uid  = (uid == RFS_KERNEL_UID) ? 0u : uid;
        inst->inodes[ii].gid  = inst->inodes[ii].uid;
        inst->inodes[ii].mode = inst->inodes[ii].is_dir ? 0755 : 0644;
    }
    return &inst->inodes[ii];
}

/* Return data page `idx`, allocating it if `alloc`. NULL on OOM / out of range. */
static uint8_t *
inode_page(ramfs_inode_t *n, uint32_t idx, int alloc)
{
    if (idx >= RAMFS_PAGES_PER_FILE)
        return (uint8_t *)0;
    if (!n->pages[idx] && alloc) {
        n->pages[idx] = (uint8_t *)kva_alloc_pages(1);
        if (n->pages[idx]) {
            __builtin_memset(n->pages[idx], 0, 4096);
            if (idx + 1 > n->npages)
                n->npages = (uint16_t)(idx + 1);
        }
    }
    return n->pages[idx];
}

/* ── file-handle vfs_ops (priv = ramfs_inode_t *) ─────────────────────── */

static int
ramfs_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    ramfs_inode_t *n = (ramfs_inode_t *)priv;
    if (off >= n->size) return 0;
    uint64_t avail = n->size - off;
    if (len > avail) len = avail;
    uint8_t *dst = (uint8_t *)buf;
    uint64_t done = 0;
    while (done < len) {
        uint64_t pos   = off + done;
        uint32_t pidx  = (uint32_t)(pos / 4096);
        uint32_t poff  = (uint32_t)(pos % 4096);
        uint64_t chunk = 4096 - poff;
        if (chunk > len - done) chunk = len - done;
        uint8_t *pg = inode_page(n, pidx, 0);
        if (pg)
            __builtin_memcpy(dst + done, pg + poff, chunk);
        else
            __builtin_memset(dst + done, 0, chunk);  /* sparse hole reads zero */
        done += chunk;
    }
    return (int)len;
}

static int
ramfs_write_fn(void *priv, const void *buf, uint64_t len)
{
    ramfs_inode_t *n = (ramfs_inode_t *)priv;
    /* Append at end-of-file (stdio issues several small writes; O_TRUNC reset
     * size to 0 in ramfs_open). buf may be a user or kernel pointer — both are
     * fine for copy_from_user. */
    if (len == 0) return 0;
    uint64_t base = (uint64_t)n->size;
    /* File at its size cap → return an ERROR, never 0: sys_write/sys_writev pass
     * a 0 straight back to userspace, and musl's stdio write loop treats 0 as
     * "retry" (len -= 0), spinning forever. A self-hosting cc1 writing a >cap
     * temp to /tmp (ramfs) hung the kernel this way (25M repeated writev). */
    if (base >= RAMFS_MAX_SIZE) return -ENOSPC;
    if (len > (uint64_t)RAMFS_MAX_SIZE - base)
        len = (uint64_t)RAMFS_MAX_SIZE - base;
    uint64_t done = 0;
    while (done < len) {
        uint64_t pos   = base + done;
        uint32_t pidx  = (uint32_t)(pos / 4096);
        uint32_t poff  = (uint32_t)(pos % 4096);
        uint8_t *pg = inode_page(n, pidx, 1);
        if (!pg) break;                          /* OOM: short write */
        uint64_t chunk = 4096 - poff;            /* dest page room    */
        if (chunk > len - done) chunk = len - done;
        /* Don't cross a source user page in one copy_from_user. */
        uint64_t src_off = (uint64_t)(uintptr_t)((const uint8_t *)buf + done) & 0xFFFULL;
        uint64_t to_src_end = 0x1000ULL - src_off;
        if (chunk > to_src_end) chunk = to_src_end;
        copy_from_user(pg + poff, (const uint8_t *)buf + done, chunk);
        done += chunk;
    }
    if (base + done > n->size)
        n->size = (uint32_t)(base + done);
    if (done == 0)
        return -ENOSPC;   /* OOM before a single byte landed — error, never 0 */
    return (int)done;
}

static void
ramfs_close_fn(void *priv)
{
    ramfs_inode_t *n = (ramfs_inode_t *)priv;
    if (!n || !n->owner) return;
    irqflags_t fl = spin_lock_irqsave(&n->owner->lock);
    if (n->open_count) n->open_count--;
    inode_release(n);
    spin_unlock_irqrestore(&n->owner->lock, fl);
}

static int
ramfs_stat_fn(void *priv, k_stat_t *st)
{
    ramfs_inode_t *n = (ramfs_inode_t *)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_dev   = 3;
    /* Real, distinct inode number (index+1). Every ramfs file used to report
     * st_ino == 1, so nothing could tell two /tmp files apart by identity. */
    st->st_ino   = (uint64_t)(n - n->owner->inodes) + 1;
    st->st_nlink = n->nlink ? n->nlink : 1;
    st->st_mode  = (n->is_dir ? S_IFDIR : S_IFREG) | (n->mode & 07777);
    st->st_uid   = n->uid;
    st->st_gid   = n->gid;
    st->st_size  = (int64_t)n->size;
    return 0;
}

static const vfs_ops_t s_ramfs_ops = {
    .seekable = 1,
    .read    = ramfs_read_fn,
    .write   = ramfs_write_fn,
    .close   = ramfs_close_fn,
    .readdir = 0,
    .dup     = 0,
    .stat    = ramfs_stat_fn,
    .poll    = 0,
};

/* ── directory-handle vfs_ops (priv = ramfs_t *) ──────────────────────── */

static int
ramfs_dir_readdir_fn(void *priv, uint64_t index, char *name_out, uint8_t *type_out)
{
    ramfs_t *inst = (ramfs_t *)priv;
    uint64_t found = 0;
    uint32_t i;
    for (i = 0; i < RAMFS_MAX_DENTS; i++) {
        if (!inst->dents[i].in_use) continue;
        if (found == index) {
            rfs_strcpy(name_out, inst->dents[i].name, RAMFS_MAX_NAMELEN);
            ramfs_inode_t *n = &inst->inodes[inst->dents[i].inode];
            *type_out = n->is_dir ? 4 /* DT_DIR */ : 8 /* DT_REG */;
            return 0;
        }
        found++;
    }
    return -1;
}

/* Directory-handle close: priv is the ramfs_t instance (NOT an inode), so it
 * must NOT go through ramfs_close_fn (which dereferences priv as an inode).
 * It's a no-op — but it must be NON-NULL: the VFS close path calls ops->close
 * unconditionally, so a NULL here is a jump-to-0 panic when a dir fd closes
 * (e.g. `find /tmp`). */
static void
ramfs_dir_close_fn(void *priv)
{
    (void)priv;
}

static const vfs_ops_t s_ramfs_dir_ops = {
    .read    = 0,
    .write   = 0,
    .close   = ramfs_dir_close_fn,
    .readdir = ramfs_dir_readdir_fn,
    .dup     = 0,
    .stat    = 0,
    .poll    = 0,
};

/* ── Public API ───────────────────────────────────────────────────────── */
/* ramfs_busy — 1 if any inode in this instance still has an open fd.
 *
 * umount frees the whole ramfs_t, and an open fd's vfs priv points INTO it, so
 * tearing down a busy instance hands the freed pages back to the kva pool while
 * a live fd can still write through them. Checked by sys_umount. */
int
ramfs_busy(ramfs_t *inst)
{
    if (!inst) return 0;
    irqflags_t fl = spin_lock_irqsave(&inst->lock);
    int busy = 0;
    for (uint32_t i = 0; i < RAMFS_MAX_INODES; i++) {
        if (inst->inodes[i].in_use && inst->inodes[i].open_count) { busy = 1; break; }
    }
    spin_unlock_irqrestore(&inst->lock, fl);
    return busy;
}


void
ramfs_init(ramfs_t *inst)
{
    uint32_t i;
    for (i = 0; i < RAMFS_MAX_INODES; i++)
        inst->inodes[i].in_use = 0;
    for (i = 0; i < RAMFS_MAX_DENTS; i++)
        inst->dents[i].in_use = 0;
    spinlock_t init = SPINLOCK_INIT;
    inst->lock = init;
}

int
ramfs_open(ramfs_t *inst, const char *name, int flags, vfs_file_t *out)
{
    irqflags_t fl = spin_lock_irqsave(&inst->lock);
    if (!rfs_name_ok(name)) {
        spin_unlock_irqrestore(&inst->lock, fl);
        return -ENAMETOOLONG;   /* would truncate onto another file's dentry */
    }
    ramfs_dent_t  *d = dent_find(inst, name);
    ramfs_inode_t *n;
    if (!d) {
        if (!(flags & (int)VFS_O_CREAT)) {
            spin_unlock_irqrestore(&inst->lock, fl);
            return -ENOENT;
        }
        n = create_named(inst, name);
        if (!n) {
            spin_unlock_irqrestore(&inst->lock, fl);
            return -ENOMEM;
        }
    } else {
        /* O_CREAT|O_EXCL on an existing entry: fail EEXIST (atomic create —
         * mkstemp's collision detection; two same-name creators must not both
         * "succeed" into one file). */
        if ((flags & (int)VFS_O_CREAT) && (flags & (int)VFS_O_EXCL)) {
            spin_unlock_irqrestore(&inst->lock, fl);
            return -EEXIST;
        }
        n = &inst->inodes[d->inode];
        /* DAC on an EXISTING file (a fresh create is owned by us by
         * construction). VFS_O_* has no separate read/write bit here, so gate
         * on what the open can do: any write intent needs write permission. */
        {
            uint32_t want = (flags & (int)(VFS_O_WRONLY | VFS_O_RDWR |
                                           VFS_O_TRUNC | VFS_O_APPEND)) ? 2u : 4u;
            if (!rfs_may(n, want)) {
                spin_unlock_irqrestore(&inst->lock, fl);
                return -EACCES;
            }
        }
    }
    if (flags & (int)VFS_O_TRUNC) {
        uint32_t k;
        for (k = 0; k < n->npages; k++) {
            if (n->pages[k]) { kva_free_pages(n->pages[k], 1); n->pages[k] = (uint8_t *)0; }
        }
        n->npages = 0;
        n->size   = 0;
    }
    n->open_count++;                              /* fd holds a ref            */
    out->ops    = &s_ramfs_ops;
    out->priv   = (void *)n;
    out->offset = 0;
    out->size   = (uint64_t)n->size;
    out->flags  = 0;
    out->kflags = 0;
    spin_unlock_irqrestore(&inst->lock, fl);
    return 0;
}

int
ramfs_stat(ramfs_t *inst, const char *name, k_stat_t *st)
{
    irqflags_t fl = spin_lock_irqsave(&inst->lock);
    ramfs_dent_t *d = dent_find(inst, name);
    if (!d) { spin_unlock_irqrestore(&inst->lock, fl); return -ENOENT; }
    ramfs_inode_t *n = &inst->inodes[d->inode];
    __builtin_memset(st, 0, sizeof(*st));
    st->st_dev   = 3;
    st->st_ino   = 1;
    st->st_nlink = 1;
    st->st_mode  = n->is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
    st->st_size  = (int64_t)n->size;
    spin_unlock_irqrestore(&inst->lock, fl);
    return 0;
}

int
ramfs_opendir(ramfs_t *inst, vfs_file_t *out)
{
    out->ops    = &s_ramfs_dir_ops;
    out->priv   = (void *)inst;
    out->offset = 0;
    out->size   = 0;
    out->flags  = 0;
    out->kflags = 0;
    return 0;
}

int
ramfs_mkdir(ramfs_t *inst, const char *name)
{
    irqflags_t fl = spin_lock_irqsave(&inst->lock);
    if (dent_find(inst, name)) {
        spin_unlock_irqrestore(&inst->lock, fl);
        return -EEXIST;
    }
    ramfs_inode_t *n = create_named(inst, name);
    if (!n) {
        spin_unlock_irqrestore(&inst->lock, fl);
        return -ENOMEM;
    }
    n->is_dir = 1;
    spin_unlock_irqrestore(&inst->lock, fl);
    return 0;
}

/* ramfs_rmdir — remove a directory marker, POSIX-style: it must exist, be a
 * directory, and be empty. The namespace here is FLAT (a dentry name is the
 * whole relative path, "lb/o.png"), so "empty" means no other live dentry
 * starts with "<name>/". */
int
ramfs_rmdir(ramfs_t *inst, const char *name)
{
    uint32_t nlen = 0;
    while (name[nlen]) nlen++;

    irqflags_t fl = spin_lock_irqsave(&inst->lock);
    ramfs_dent_t *d = dent_find(inst, name);
    if (!d) { spin_unlock_irqrestore(&inst->lock, fl); return -ENOENT; }
    ramfs_inode_t *n = &inst->inodes[d->inode];
    if (!n->is_dir) { spin_unlock_irqrestore(&inst->lock, fl); return -ENOTDIR; }

    for (int i = 0; i < RAMFS_MAX_DENTS; i++) {
        ramfs_dent_t *e = &inst->dents[i];
        if (!e->in_use || e == d) continue;
        uint32_t k = 0;
        while (k < nlen && e->name[k] == name[k]) k++;
        if (k == nlen && e->name[nlen] == '/') {
            spin_unlock_irqrestore(&inst->lock, fl);
            return -ENOTEMPTY;
        }
    }

    d->in_use = 0;
    if (n->nlink) n->nlink--;
    inode_release(n);
    spin_unlock_irqrestore(&inst->lock, fl);
    return 0;
}

int
ramfs_unlink(ramfs_t *inst, const char *name)
{
    irqflags_t fl = spin_lock_irqsave(&inst->lock);
    ramfs_dent_t *d = dent_find(inst, name);
    if (!d) { spin_unlock_irqrestore(&inst->lock, fl); return -ENOENT; }
    ramfs_inode_t *n = &inst->inodes[d->inode];
    /* Sticky semantics, as /tmp has had since forever elsewhere: only the
     * owner may remove a name. Without this any process could unlink another's
     * lockfile or runtime state. */
    {
        uint32_t uid = rfs_caller_uid();
        if (uid != RFS_KERNEL_UID && uid != n->uid) {
            spin_unlock_irqrestore(&inst->lock, fl);
            return -EACCES;
        }
    }
    d->in_use = 0;                                /* drop the name             */
    if (n->nlink) n->nlink--;
    inode_release(n);                             /* frees only if no open fd  */
    spin_unlock_irqrestore(&inst->lock, fl);
    return 0;
}

int
ramfs_rename(ramfs_t *inst, const char *oldname, const char *newname)
{
    irqflags_t fl = spin_lock_irqsave(&inst->lock);
    if (!rfs_name_ok(newname)) {
        spin_unlock_irqrestore(&inst->lock, fl);
        return -ENAMETOOLONG;
    }
    ramfs_dent_t *src = dent_find(inst, oldname);
    if (!src) { spin_unlock_irqrestore(&inst->lock, fl); return -ENOENT; }
    uint32_t ruid = rfs_caller_uid();
    if (ruid != RFS_KERNEL_UID && ruid != inst->inodes[src->inode].uid) {
        spin_unlock_irqrestore(&inst->lock, fl);
        return -EACCES;                 /* not yours to move */
    }
    /* POSIX replace: if the destination name exists, drop its inode ref. */
    ramfs_dent_t *dst = dent_find(inst, newname);
    if (dst && dst != src) {
        ramfs_inode_t *dn = &inst->inodes[dst->inode];
        if (ruid != RFS_KERNEL_UID && ruid != dn->uid) {
            spin_unlock_irqrestore(&inst->lock, fl);
            return -EACCES;             /* would clobber someone else's file */
        }
        dst->in_use = 0;
        if (dn->nlink) dn->nlink--;
        inode_release(dn);
    }
    /* Re-point the source name to its (unchanged) inode — data never moves. */
    rfs_strcpy(src->name, newname, RAMFS_MAX_NAMELEN);
    spin_unlock_irqrestore(&inst->lock, fl);
    return 0;
}

int
ramfs_populate(ramfs_t *inst, const char *name,
               const uint8_t *kbuf, uint32_t len)
{
    irqflags_t fl = spin_lock_irqsave(&inst->lock);
    ramfs_dent_t  *d = dent_find(inst, name);
    ramfs_inode_t *n;
    if (!d) {
        n = create_named(inst, name);
        if (!n) { spin_unlock_irqrestore(&inst->lock, fl); return -ENOMEM; }
    } else {
        n = &inst->inodes[d->inode];
    }
    n->size = 0; n->npages = 0;  /* note: assumes no concurrent fd; boot-time use */
    if (len == 0) { spin_unlock_irqrestore(&inst->lock, fl); return 0; }
    if (len > RAMFS_MAX_SIZE) len = RAMFS_MAX_SIZE;
    uint32_t done = 0;
    while (done < len) {
        uint32_t pidx  = done / 4096;
        uint32_t poff  = done % 4096;
        uint8_t *pg = inode_page(n, pidx, 1);
        if (!pg) { spin_unlock_irqrestore(&inst->lock, fl); return -ENOMEM; }
        uint32_t chunk = 4096 - poff;
        if (chunk > len - done) chunk = len - done;
        __builtin_memcpy(pg + poff, kbuf + done, chunk);
        done += chunk;
    }
    n->size = len;
    spin_unlock_irqrestore(&inst->lock, fl);
    return 0;
}
