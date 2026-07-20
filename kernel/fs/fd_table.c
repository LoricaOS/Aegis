#include "fd_table.h"
#include "kva.h"
#include "../limits.h"
#include "../core/printk.h"
#include "../drivers/fb.h"   /* panic_halt */

/* Size-agnostic backing-page count for one fd table. fd_table_t embeds
 * PROC_MAX_FDS vfs_file_t inline, so a PROC_MAX_FDS bump grows it past one
 * page; compute ceil(sizeof(fd_table_t) / PAGE_SIZE) so a future capacity
 * change (limits.h, AEGIS_PROC_MAX_FDS) needs NO edit here. At 64 fds:
 * sizeof(fd_table_t) = 64*40 + 4 (+pad) = 2564 B → 1 page, identical to the
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
    }
    t->refcount = 1;
    t->magic    = FD_TABLE_MAGIC;
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
    uint32_t i;
    for (i = 0; i < PROC_MAX_FDS; i++)
        dst->fds[i] = src->fds[i];
    for (i = 0; i < PROC_MAX_FDS; i++) {
        if (dst->fds[i].ops && dst->fds[i].ops->dup)
            dst->fds[i].ops->dup(dst->fds[i].priv);
    }
    dst->refcount = 1;
    dst->magic    = FD_TABLE_MAGIC;
    return dst;
}
