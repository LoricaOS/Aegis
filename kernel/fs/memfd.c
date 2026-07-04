/* kernel/fs/memfd.c — anonymous shared memory file descriptors */
#include "memfd.h"
#include "../lib/string.h"
#include "fd_table.h"
#include "proc.h"
#include "kva.h"
#include "pmm.h"
#include "vmm.h"
#include "spinlock.h"
#include "fd_resolve.h"
#include "../include/aegis_errno.h"
#include <stdint.h>

static memfd_t   s_memfds[MEMFD_MAX];
static spinlock_t memfd_lock = SPINLOCK_INIT;

/* ── Local helpers ─────────────────────────────────────────────────────── */


static void _mf_strcpy(char *dst, const char *src, uint32_t max)
{
    uint32_t i = 0;
    while (i < max - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

/* ── VFS ops ───────────────────────────────────────────────────────────── */

static int memfd_vfs_read(void *priv, void *buf, uint64_t off, uint64_t len)
{
    uint32_t id = (uint32_t)(uintptr_t)priv;
    irqflags_t fl = spin_lock_irqsave(&memfd_lock);
    memfd_t *mf = memfd_get(id);
    if (!mf) { spin_unlock_irqrestore(&memfd_lock, fl); return -EBADF; }

    if (off >= mf->size) { spin_unlock_irqrestore(&memfd_lock, fl); return 0; }
    if (off + len > mf->size) len = mf->size - off;

    uint8_t *dst = (uint8_t *)buf;
    uint64_t done = 0;
    while (done < len) {
        uint32_t page_idx = (uint32_t)((off + done) / 4096);
        uint32_t page_off = (uint32_t)((off + done) % 4096);
        uint32_t chunk = 4096 - page_off;
        if (chunk > len - done) chunk = (uint32_t)(len - done);

        if (page_idx < mf->page_count && mf->phys_pages[page_idx]) {
            /* Snapshot phys addr, release memfd_lock to avoid lock inversion
             * with vmm_window_lock. Single-reader: safe because refcount > 0
             * prevents page free. */
            uint64_t phys = mf->phys_pages[page_idx];
            spin_unlock_irqrestore(&memfd_lock, fl);

            /* Copy under vmm_window_lock — the window VA is a single global
             * shared slot; using vmm_window_map directly without the lock
             * races every other CPU's window use (fork copy, vmm_zero_page,
             * page-table walks) and corrupts an unrelated physical frame.
             * Latent under BSP-only scheduling; live once APs schedule. */
            vmm_copy_from_phys(dst + done, phys, page_off, chunk);

            fl = spin_lock_irqsave(&memfd_lock);
            mf = memfd_get(id);
            if (!mf) { spin_unlock_irqrestore(&memfd_lock, fl); return (int)done; }
        } else {
            for (uint32_t i = 0; i < chunk; i++)
                dst[done + i] = 0;
        }
        done += chunk;
    }

    spin_unlock_irqrestore(&memfd_lock, fl);
    return (int)done;
}

static int memfd_vfs_write(void *priv, const void *buf, uint64_t len)
{
    /* memfd write is not commonly used (mmap is preferred).
     * For simplicity, only support writing at offset 0 up to size. */
    (void)priv; (void)buf; (void)len;
    return -ENOSYS;  /* use mmap instead */
}

static void memfd_vfs_close(void *priv)
{
    uint32_t id = (uint32_t)(uintptr_t)priv;
    irqflags_t fl = spin_lock_irqsave(&memfd_lock);
    if (id >= MEMFD_MAX || !s_memfds[id].in_use) {
        spin_unlock_irqrestore(&memfd_lock, fl);
        return;
    }
    memfd_t *mf = &s_memfds[id];
    if (!refcount_dec_and_test(&mf->refcount)) {
        spin_unlock_irqrestore(&memfd_lock, fl);
        return;
    }

    /* Free all physical pages */
    for (uint32_t i = 0; i < mf->page_count; i++) {
        if (mf->phys_pages[i])
            pmm_free_page(mf->phys_pages[i]);
    }
    uint64_t *_arr = mf->phys_pages;
    mf->phys_pages = (uint64_t *)0;
    mf->in_use = 0;
    spin_unlock_irqrestore(&memfd_lock, fl);
    /* Return the phys_pages array VA to the kva freelist (coalescing, no leak).
     * Done outside memfd_lock to keep mm locks below it. */
    if (_arr)
        kva_free_pages(_arr, MEMFD_PHYS_ARR_PAGES);
}

static void memfd_vfs_dup(void *priv)
{
    uint32_t id = (uint32_t)(uintptr_t)priv;
    irqflags_t fl = spin_lock_irqsave(&memfd_lock);
    if (id < MEMFD_MAX && s_memfds[id].in_use)
        refcount_inc(&s_memfds[id].refcount);
    spin_unlock_irqrestore(&memfd_lock, fl);
}

static int memfd_vfs_stat(void *priv, k_stat_t *st)
{
    uint32_t id = (uint32_t)(uintptr_t)priv;
    kmemset(st, 0, sizeof(*st));
    irqflags_t fl = spin_lock_irqsave(&memfd_lock);
    memfd_t *mf = memfd_get(id);
    if (mf) {
        st->st_size = (int64_t)mf->size;
        st->st_blocks = (int64_t)(mf->page_count * 8);  /* 512-byte units */
    }
    spin_unlock_irqrestore(&memfd_lock, fl);
    st->st_mode = 0100000U | 0600U;  /* S_IFREG | 0600 */
    st->st_blksize = 4096;
    return 0;
}

/* memfd is always ready: the existing .poll callback returns
 * POLLIN | POLLOUT immediately for every open. There's no producer
 * to wake, so get_waitq stays NULL and sys_poll falls through to
 * its permissive default. */
const vfs_ops_t g_memfd_ops = {
    .read    = memfd_vfs_read,
    .write   = memfd_vfs_write,
    .close   = memfd_vfs_close,
    .readdir = (void *)0,
    .dup     = memfd_vfs_dup,
    .stat    = memfd_vfs_stat,
    .poll    = (void *)0,
};

/* ── Alloc / Get ───────────────────────────────────────────────────────── */

int memfd_alloc(const char *name)
{
    irqflags_t fl = spin_lock_irqsave(&memfd_lock);
    for (int i = 0; i < MEMFD_MAX; i++) {
        if (!s_memfds[i].in_use) {
            kmemset(&s_memfds[i], 0, sizeof(memfd_t));
            s_memfds[i].in_use   = 1;
            refcount_init(&s_memfds[i].refcount, 1);
            if (name)
                _mf_strcpy(s_memfds[i].name, name, 32);
            spin_unlock_irqrestore(&memfd_lock, fl);
            return i;
        }
    }
    spin_unlock_irqrestore(&memfd_lock, fl);
    return -1;
}

memfd_t *memfd_get(uint32_t id)
{
    if (id >= MEMFD_MAX) return (void *)0;
    if (!s_memfds[id].in_use) return (void *)0;
    return &s_memfds[id];
}

memfd_t *memfd_from_fd(int fd, void *proc_ptr)
{
    vfs_file_t *f = fd_resolve((aegis_process_t *)proc_ptr, fd, &g_memfd_ops);
    return f ? memfd_get((uint32_t)(uintptr_t)f->priv) : (memfd_t *)0;
}

/* ── Truncate ──────────────────────────────────────────────────────────── */

int memfd_truncate(uint32_t id, uint64_t size)
{
    irqflags_t fl = spin_lock_irqsave(&memfd_lock);
    memfd_t *mf = memfd_get(id);
    if (!mf) { spin_unlock_irqrestore(&memfd_lock, fl); return -EBADF; }

    uint32_t new_pages = (uint32_t)((size + 4095) / 4096);
    if (new_pages > MEMFD_PAGES_MAX) {
        spin_unlock_irqrestore(&memfd_lock, fl);
        return -ENOMEM;
    }

    /* Grow: allocate new pages.
     * Release memfd_lock before calling pmm/vmm to avoid lock inversion. */
    uint32_t old_count = mf->page_count;
    int _need_arr = (new_pages > 0 && mf->phys_pages == (uint64_t *)0);
    spin_unlock_irqrestore(&memfd_lock, fl);

    /* Lazily allocate the dynamic phys_pages array (kva-backed) on first grow.
     * kva_alloc_pages takes kva_lock; call it without memfd_lock held. */
    if (_need_arr) {
        uint64_t *_arr = (uint64_t *)kva_alloc_pages(MEMFD_PHYS_ARR_PAGES);
        kmemset(_arr, 0, MEMFD_PAGES_MAX * sizeof(uint64_t));
        fl = spin_lock_irqsave(&memfd_lock);
        mf = memfd_get(id);
        if (!mf) { spin_unlock_irqrestore(&memfd_lock, fl); kva_free_pages(_arr, MEMFD_PHYS_ARR_PAGES); return -EBADF; }
        if (mf->phys_pages == (uint64_t *)0) {
            mf->phys_pages = _arr;
            spin_unlock_irqrestore(&memfd_lock, fl);
        } else {
            spin_unlock_irqrestore(&memfd_lock, fl);
            kva_free_pages(_arr, MEMFD_PHYS_ARR_PAGES);  /* a racer already set it */
        }
    }

    for (uint32_t i = old_count; i < new_pages; i++) {
        uint64_t phys = pmm_alloc_page();
        if (!phys) {
            /* OOM mid-grow.  Truncate is all-or-nothing (POSIX-friendly):
             * page_count was never advanced, so the pages we stored in
             * phys_pages[old_count..i) this call are invisible to
             * memfd_vfs_close's free loop (bounded by page_count) and would
             * leak.  Free and clear them here so the memfd is left exactly as
             * it was before the call.  No double-free: page_count stays at
             * old_count, so close never touches these slots. */
            fl = spin_lock_irqsave(&memfd_lock);
            mf = memfd_get(id);
            if (mf) {
                for (uint32_t k = old_count; k < i; k++) {
                    if (mf->phys_pages[k]) {
                        pmm_free_page(mf->phys_pages[k]);
                        mf->phys_pages[k] = 0;
                    }
                }
            }
            spin_unlock_irqrestore(&memfd_lock, fl);
            return -ENOMEM;
        }

        /* Zero the fresh page under vmm_window_lock (vmm_zero_page self-locks)
         * — a bare vmm_window_map here races other CPUs' window use. */
        vmm_zero_page(phys);

        fl = spin_lock_irqsave(&memfd_lock);
        mf = memfd_get(id);
        if (!mf) { spin_unlock_irqrestore(&memfd_lock, fl); pmm_free_page(phys); return -EBADF; }
        mf->phys_pages[i] = phys;
        spin_unlock_irqrestore(&memfd_lock, fl);
    }

    fl = spin_lock_irqsave(&memfd_lock);
    mf = memfd_get(id);
    if (!mf) { spin_unlock_irqrestore(&memfd_lock, fl); return -EBADF; }

    /* Shrink: free excess pages */
    for (uint32_t i = new_pages; i < mf->page_count; i++) {
        if (mf->phys_pages[i]) {
            pmm_free_page(mf->phys_pages[i]);
            mf->phys_pages[i] = 0;
        }
    }

    mf->page_count = new_pages;
    mf->size       = size;
    spin_unlock_irqrestore(&memfd_lock, fl);
    return 0;
}

/* ── Open fd ───────────────────────────────────────────────────────────── */

int memfd_open_fd(uint32_t id, void *proc_ptr)
{
    aegis_process_t *proc = (aegis_process_t *)proc_ptr;
    for (int i = 0; i < PROC_MAX_FDS; i++) {
        if (!proc->fd_table->fds[i].ops) {
            proc->fd_table->fds[i].ops    = &g_memfd_ops;
            proc->fd_table->fds[i].priv   = (void *)(uintptr_t)id;
            proc->fd_table->fds[i].offset = 0;
            proc->fd_table->fds[i].size   = 0;
            proc->fd_table->fds[i].flags  = VFS_O_RDWR;
            return i;
        }
    }
    return -1;
}
