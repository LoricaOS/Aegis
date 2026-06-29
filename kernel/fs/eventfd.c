#include "eventfd.h"
#include "vfs.h"
#include "sched.h"
#include "wait_event.h"
#include "proc.h"
#include "kva.h"
#include "uaccess.h"
#include "../include/aegis_errno.h"
#include <stdint.h>
#include <stddef.h>

/* Linux eventfd flag values (also the matching O_* bits). */
#define EFD_SEMAPHORE 0x00001U
#define EFD_NONBLOCK  0x00800U   /* == VFS_O_NONBLOCK */
#define EFD_CLOEXEC   0x80000U   /* == VFS_FD_CLOEXEC */

#define EFD_VALMAX 0xFFFFFFFFFFFFFFFEULL  /* counter ceiling (UINT64_MAX-1) */

static int           eventfd_read_fn(void *priv, void *buf, uint64_t off, uint64_t len);
static int           eventfd_write_fn(void *priv, const void *buf, uint64_t len);
static void          eventfd_close_fn(void *priv);
static void          eventfd_dup_fn(void *priv);
static int           eventfd_stat_fn(void *priv, k_stat_t *st);
static uint16_t      eventfd_poll_fn(void *priv);
static struct waitq *eventfd_read_get_waitq_fn(void *priv);

const vfs_ops_t g_eventfd_ops = {
    .read      = eventfd_read_fn,
    .write     = eventfd_write_fn,
    .close     = eventfd_close_fn,
    .readdir   = (void *)0,
    .dup       = eventfd_dup_fn,
    .stat      = eventfd_stat_fn,
    .poll      = eventfd_poll_fn,
    .get_waitq = eventfd_read_get_waitq_fn,
};

/*
 * read — drain the counter into the 8-byte buffer. buf is a KERNEL buffer
 * (sys_read's kbuf). Blocks while count==0 unless the fd is O_NONBLOCK
 * (per-task read_nonblock flag), in which case it returns -EAGAIN.
 */
static int
eventfd_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    eventfd_t *e = (eventfd_t *)priv;
    (void)off;
    if (len < 8)
        return -EINVAL;

    for (;;) {
        irqflags_t fl = spin_lock_irqsave(&e->lock);
        if (e->count == 0) {
            spin_unlock_irqrestore(&e->lock, fl);
            if (sched_current()->read_nonblock)
                return -EAGAIN;
            wait_event(&e->read_waiters, e->count > 0);
            continue;
        }
        uint64_t val;
        if (e->flags & EFD_SEMAPHORE) {
            val = 1;
            e->count -= 1;
        } else {
            val = e->count;
            e->count = 0;
        }
        spin_unlock_irqrestore(&e->lock, fl);

        __builtin_memcpy(buf, &val, 8);
        /* Draining freed counter space — wake writers + POLLOUT pollers. */
        waitq_wake_all(&e->write_waiters);
        return 8;
    }
}

/*
 * write — add the 8-byte value to the counter. buf is a KERNEL staging buffer
 * (sys_write copies from user first). A write that would overflow the ceiling
 * returns -EAGAIN.
 *
 * ponytail: write-side blocking (the POSIX behavior when the counter is full
 * and the fd is blocking) is not implemented — sys_write passes no nonblock
 * flag, and the only consumer (libcurl wakeup) opens EFD_NONBLOCK and never
 * lets the counter approach the ceiling. Add a write_nonblock flag mirroring
 * read_nonblock if a blocking-mode writer ever needs it.
 */
static int
eventfd_write_fn(void *priv, const void *buf, uint64_t len)
{
    eventfd_t *e = (eventfd_t *)priv;
    if (len < 8)
        return -EINVAL;

    uint64_t val;
    __builtin_memcpy(&val, buf, 8);
    if (val == 0xFFFFFFFFFFFFFFFFULL)   /* -1 is reserved/invalid */
        return -EINVAL;

    irqflags_t fl = spin_lock_irqsave(&e->lock);
    if (val > EFD_VALMAX - e->count) {
        spin_unlock_irqrestore(&e->lock, fl);
        return -EAGAIN;
    }
    e->count += val;
    spin_unlock_irqrestore(&e->lock, fl);

    /* Deposited a signal — wake readers + POLLIN pollers. */
    waitq_wake_all(&e->read_waiters);
    return 8;
}

static uint16_t
eventfd_poll_fn(void *priv)
{
    eventfd_t *e = (eventfd_t *)priv;
    uint16_t events = 0;
    irqflags_t fl = spin_lock_irqsave(&e->lock);
    if (e->count > 0)
        events |= 0x0001;          /* POLLIN  */
    if (e->count < EFD_VALMAX)
        events |= 0x0004;          /* POLLOUT */
    spin_unlock_irqrestore(&e->lock, fl);
    return events;
}

static struct waitq *
eventfd_read_get_waitq_fn(void *priv)
{
    /* One queue is enough for poll registration: any state change (a write
     * makes it readable, a read makes it writable) wakes read_waiters. Writers
     * also wake read_waiters; readers wake write_waiters. sys_poll registers on
     * this one; the producer paths wake both queues so nothing is missed. */
    return &((eventfd_t *)priv)->read_waiters;
}

static void
eventfd_close_fn(void *priv)
{
    eventfd_t *e = (eventfd_t *)priv;
    if (refcount_dec_and_test(&e->refs))
        kva_free_pages(e, 1);
}

static void
eventfd_dup_fn(void *priv)
{
    refcount_inc(&((eventfd_t *)priv)->refs);
}

static int
eventfd_stat_fn(void *priv, k_stat_t *st)
{
    eventfd_t *e = (eventfd_t *)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_mode = S_IFIFO | 0600;
    st->st_ino  = 0;
    st->st_size = (int64_t)e->count;
    return 0;
}

/*
 * sys_eventfd2 — syscall 290. Creates an eventfd object and installs it in the
 * lowest free fd slot. EFD_NONBLOCK / EFD_CLOEXEC share their bit values with
 * VFS_O_NONBLOCK / VFS_FD_CLOEXEC, so the relevant flags map straight across.
 */
uint64_t
sys_eventfd2(uint64_t initval, uint64_t flags)
{
    aegis_process_t *proc = current_proc();

    int fd = -1, i;
    for (i = 0; i < PROC_MAX_FDS; i++) {
        if (!proc->fd_table->fds[i].ops) { fd = i; break; }
    }
    if (fd < 0)
        return SYS_ERR(EMFILE);

    eventfd_t *e = kva_alloc_pages(1);
    if (!e)
        return SYS_ERR(ENOMEM);
    __builtin_memset(e, 0, sizeof(*e));
    e->count = initval;
    e->flags = (uint32_t)flags & EFD_SEMAPHORE;
    refcount_init(&e->refs, 1);

    proc->fd_table->fds[fd].ops    = &g_eventfd_ops;
    proc->fd_table->fds[fd].priv   = e;
    proc->fd_table->fds[fd].offset = 0;
    proc->fd_table->fds[fd].size   = 0;
    proc->fd_table->fds[fd].flags  =
        (uint32_t)flags & (VFS_O_NONBLOCK | VFS_FD_CLOEXEC);
    proc->fd_table->fds[fd].kflags = 0;

    return (uint64_t)fd;
}
