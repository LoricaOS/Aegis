#include "fd_table.h"
#include "kva.h"
#include "../limits.h"
#include "../core/printk.h"
#include "../drivers/fb.h"   /* panic_halt */

/* Size-agnostic backing-page count for one fd table. fd_table_t embeds
 * PROC_MAX_FDS vfs_file_t inline, so a PROC_MAX_FDS bump grows it past one
 * page; compute ceil(sizeof(fd_table_t) / PAGE_SIZE) so a future capacity
 * change (limits.h, AEGIS_PROC_MAX_FDS) needs NO edit here. At 64 fds:
 * sizeof(fd_table_t) = 64*56 + metadata = 3592 B → 1 page, identical to the
 * old hard-coded kva_alloc_pages(1). Both alloc and free use this count. */
#define FD_TABLE_PAGES \
    ((sizeof(fd_table_t) + AEGIS_PAGE_SIZE - 1) / AEGIS_PAGE_SIZE)

fd_table_t *
fd_table_alloc(void)
{
    fd_table_t *t = (fd_table_t *)kva_alloc_pages(FD_TABLE_PAGES);
    if (!t) return (fd_table_t *)0;
    uint32_t i;
    for (i = 0; i < PROC_MAX_FDS; i++) {
        t->fds[i].ops    = (const vfs_ops_t *)0;
        t->fds[i].kflags = 0;   /* kva pages aren't guaranteed zeroed; keep the
                                 * "free slot ⇒ kflags==0" invariant from birth */
        t->fds[i].cap_root_inode = 0;
        t->fds[i].cap_rights = 0;
    }
    t->refcount = 1;
    t->magic    = FD_TABLE_MAGIC;
    {
        spinlock_t init = SPINLOCK_INIT;
        t->lock = init;
    }
    return t;
}

/* Shared liveness check. A table that is not live is either already freed
 * (poisoned) or was never one — either way, continuing would walk memory that
 * belongs to somebody else, so fail loudly right here. */
static void
fd_table_assert_live(fd_table_t *t, const char *who)
{
    if (t->magic == FD_TABLE_MAGIC)
        return;
    printk("[FDTABLE] FAIL: %s on a %s table at %p (magic=0x%x refcount=%u)\n",
           who, t->magic == FD_TABLE_POISON ? "FREED" : "corrupt",
           (void *)t, t->magic, t->refcount);
    panic_halt("[FDTABLE] FAIL: fd table use-after-free");
}

void
fd_table_ref(fd_table_t *t)
{
    if (!t) return;
    fd_table_assert_live(t, "ref");
    __atomic_fetch_add(&t->refcount, 1, __ATOMIC_SEQ_CST);
}

void
fd_table_unref(fd_table_t *t)
{
    if (!t) return;
    /* BEFORE touching refcount or walking fds[]: if this table is already gone,
     * every pointer below belongs to whoever owns these pages now. */
    fd_table_assert_live(t, "unref");
    if (__atomic_fetch_sub(&t->refcount, 1, __ATOMIC_SEQ_CST) > 1) return;
    uint32_t i;
    for (i = 0; i < PROC_MAX_FDS; i++) {
        if (t->fds[i].ops && t->fds[i].ops->close) {
            t->fds[i].ops->close(t->fds[i].priv);
            t->fds[i].ops = (const vfs_ops_t *)0;
        }
    }
    /* Stamp the whole table so a later stale user hits an unmistakable pattern
     * (and trips assert_live) rather than reading plausible-looking garbage.
     * Cheap: one page at the default 64-fd capacity. */
    {
        uint32_t *p = (uint32_t *)t;
        uint32_t  n = (uint32_t)(sizeof(*t) / sizeof(uint32_t));
        for (uint32_t k = 0; k < n; k++)
            p[k] = FD_TABLE_POISON;
    }
    kva_free_pages(t, FD_TABLE_PAGES);
}

fd_table_t *
fd_table_copy(fd_table_t *src)
{
    if (!src) return (fd_table_t *)0;
    fd_table_assert_live(src, "copy");
    fd_table_t *dst = (fd_table_t *)kva_alloc_pages(FD_TABLE_PAGES);
    if (!dst) return (fd_table_t *)0;
    {
        spinlock_t init = SPINLOCK_INIT;
        dst->lock = init;
    }
    /* Both passes under the SOURCE table's lock. Snapshotting and then
     * ref-taking in two unserialised passes let a concurrent close free an
     * object between them, after which the dup pass touched freed memory.
     * Copying and dup-ing slot by slot would NOT have fixed it — the close can
     * land between the copy of slot i and the dup of slot i just as easily. */
    irqflags_t fl = spin_lock_irqsave(&src->lock);
    uint32_t i;
    for (i = 0; i < PROC_MAX_FDS; i++)
        dst->fds[i] = src->fds[i];
    for (i = 0; i < PROC_MAX_FDS; i++) {
        if (dst->fds[i].ops && dst->fds[i].ops->dup)
            dst->fds[i].ops->dup(dst->fds[i].priv);
    }
    spin_unlock_irqrestore(&src->lock, fl);
    dst->refcount = 1;
    dst->magic    = FD_TABLE_MAGIC;
    return dst;
}

int
fd_table_pin(fd_table_t *t, int fd, fd_table_pin_t *out)
{
    __builtin_memset(out, 0, sizeof(*out));
    if (!t || fd < 0 || (uint32_t)fd >= PROC_MAX_FDS)
        return 0;

    fd_table_assert_live(t, "pin");
    irqflags_t fl = spin_lock_irqsave(&t->lock);
    vfs_file_t file = t->fds[fd];
    if (!file.ops || (file.ops->dup && !file.ops->close)) {
        spin_unlock_irqrestore(&t->lock, fl);
        return 0;
    }
    if (file.ops->dup) {
        file.ops->dup(file.priv);
        out->referenced = 1;
    }
    out->file = file;
    spin_unlock_irqrestore(&t->lock, fl);
    return 1;
}

void
fd_table_unpin(fd_table_pin_t *pin)
{
    if (!pin->referenced) {
        pin->file.ops = (const vfs_ops_t *)0;
        return;
    }
    const vfs_ops_t *ops = pin->file.ops;
    void *priv = pin->file.priv;
    __builtin_memset(pin, 0, sizeof(*pin));
    ops->close(priv);
}

void
fd_table_advance_offset(fd_table_t *t, int fd,
                        const fd_table_pin_t *pin, uint64_t delta)
{
    if (!delta || !t || fd < 0 || (uint32_t)fd >= PROC_MAX_FDS)
        return;
    irqflags_t fl = spin_lock_irqsave(&t->lock);
    vfs_file_t *slot = &t->fds[fd];
    if (slot->ops == pin->file.ops && slot->priv == pin->file.priv)
        slot->offset += delta;
    spin_unlock_irqrestore(&t->lock, fl);
}

void
fd_table_set_offset(fd_table_t *t, int fd,
                    const fd_table_pin_t *pin, uint64_t offset)
{
    if (!t || fd < 0 || (uint32_t)fd >= PROC_MAX_FDS)
        return;
    irqflags_t fl = spin_lock_irqsave(&t->lock);
    vfs_file_t *slot = &t->fds[fd];
    if (slot->ops == pin->file.ops && slot->priv == pin->file.priv)
        slot->offset = offset;
    spin_unlock_irqrestore(&t->lock, fl);
}

int
fd_table_update_flags(fd_table_t *t, int fd, const fd_table_pin_t *pin,
                      uint32_t clear, uint32_t set)
{
    if (!t || fd < 0 || (uint32_t)fd >= PROC_MAX_FDS)
        return 0;
    irqflags_t fl = spin_lock_irqsave(&t->lock);
    vfs_file_t *slot = &t->fds[fd];
    int same = slot->ops == pin->file.ops && slot->priv == pin->file.priv;
    if (same)
        slot->flags = (slot->flags & ~clear) | set;
    spin_unlock_irqrestore(&t->lock, fl);
    return same;
}
