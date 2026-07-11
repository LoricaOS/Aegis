#include "pipe.h"
#include "vfs.h"
#include "sched.h"
#include "wait_event.h"
#include "proc.h"
#include "signal.h"
#include "kva.h"
#include "uaccess.h"
#include "../lib/ringbuf.h"
#include "../include/aegis_errno.h"
#include <stdint.h>
#include <stddef.h>

_Static_assert(sizeof(pipe_t) == 4096,
    "pipe_t must be exactly 4096 bytes (one kva page); adjust PIPE_BUF_SIZE");

/* Forward declarations */
static int           pipe_read_fn(void *priv, void *buf, uint64_t off, uint64_t len);
static int           pipe_write_fn(void *priv, const void *buf, uint64_t len);
static void          pipe_read_close_fn(void *priv);
static void          pipe_write_close_fn(void *priv);
static void          pipe_dup_read_fn(void *priv);
static void          pipe_dup_write_fn(void *priv);
static int           pipe_stat_fn(void *priv, k_stat_t *st);
static uint16_t      pipe_read_poll_fn(void *priv);
static uint16_t      pipe_write_poll_fn(void *priv);
static struct waitq *pipe_read_get_waitq_fn(void *priv);
static struct waitq *pipe_write_get_waitq_fn(void *priv);

static uint16_t
pipe_read_poll_fn(void *priv)
{
    pipe_t *p = (pipe_t *)priv;
    uint16_t events = 0;
    irqflags_t fl = spin_lock_irqsave(&p->lock);
    if (p->count > 0 || refcount_read(&p->write_refs) == 0)
        events |= 0x0001; /* POLLIN */
    if (refcount_read(&p->write_refs) == 0)
        events |= 0x0010; /* POLLHUP */
    spin_unlock_irqrestore(&p->lock, fl);
    return events;
}

static uint16_t
pipe_write_poll_fn(void *priv)
{
    pipe_t *p = (pipe_t *)priv;
    uint16_t events = 0;
    irqflags_t fl = spin_lock_irqsave(&p->lock);
    if (p->count < PIPE_BUF_SIZE || refcount_read(&p->read_refs) == 0)
        events |= 0x0004; /* POLLOUT */
    if (refcount_read(&p->read_refs) == 0)
        events |= 0x0008; /* POLLERR */
    spin_unlock_irqrestore(&p->lock, fl);
    return events;
}

static struct waitq *
pipe_read_get_waitq_fn(void *priv)
{
    return &((pipe_t *)priv)->read_waiters;
}

static struct waitq *
pipe_write_get_waitq_fn(void *priv)
{
    return &((pipe_t *)priv)->write_waiters;
}

const vfs_ops_t g_pipe_read_ops = {
    .read      = pipe_read_fn,
    .write     = (void *)0,
    .close     = pipe_read_close_fn,
    .readdir   = (void *)0,
    .dup       = pipe_dup_read_fn,
    .stat      = pipe_stat_fn,
    .poll      = pipe_read_poll_fn,
    .get_waitq = pipe_read_get_waitq_fn,
};

const vfs_ops_t g_pipe_write_ops = {
    .read      = (void *)0,
    .write     = pipe_write_fn,
    .close     = pipe_write_close_fn,
    .readdir   = (void *)0,
    .dup       = pipe_dup_write_fn,
    .stat      = pipe_stat_fn,
    .poll      = pipe_write_poll_fn,
    .get_waitq = pipe_write_get_waitq_fn,
};

/*
 * pipe_read_fn — read up to len bytes from the pipe into kernel buffer buf.
 *
 * Blocking semantics (retry-as-loop):
 *   - If empty and write end closed: return 0 (EOF).
 *   - If empty and write end open: block until data arrives or write end closes.
 *   - After sched_block() returns, execution resumes at `continue` in the loop
 *     and the conditions are re-evaluated. Same pattern as sys_waitpid.
 *
 * buf is a kernel buffer (kbuf inside sys_read), NOT a user pointer. Plain memcpy.
 * offset is ignored — pipes have no seek position.
 */
static int
pipe_read_fn(void *priv, void *buf, uint64_t off, uint64_t len)
{
    pipe_t *p = (pipe_t *)priv;
    (void)off;

    for (;;) {
        irqflags_t fl = spin_lock_irqsave(&p->lock);

        /*
         * Defensive: ring buffer indices must stay within [0, PIPE_BUF_SIZE).
         * Reset to 0 rather than panic — index corruption is a kernel bug, not
         * user-visible input, and a silent reset is safer than an undiagnosable
         * halt. The ring invariant (read_pos < PIPE_BUF_SIZE) is restored before
         * any arithmetic that could wrap or overflow.
         */
        if (p->read_pos  >= PIPE_BUF_SIZE) p->read_pos  = 0;
        if (p->write_pos >= PIPE_BUF_SIZE) p->write_pos = 0;

        if (p->count == 0 && refcount_read(&p->write_refs) == 0) {
            spin_unlock_irqrestore(&p->lock, fl);
            return 0;   /* EOF: all writers gone */
        }
        if (p->count == 0) {
            /* Empty, writers still around. O_NONBLOCK (per-task read_nonblock,
             * set by sys_read from the fd flags): return EAGAIN instead of
             * blocking — without this an O_NONBLOCK pipe read hangs forever. */
            if (sched_current()->read_nonblock) {
                spin_unlock_irqrestore(&p->lock, fl);
                return -EAGAIN;
            }
            /* Block until a writer deposits data or closes the write end. Drop
             * the lock first — wait_event's condition is a lockless hint,
             * re-validated authoritatively under p->lock at the top of this
             * loop.  Uninterruptible, matching historical pipe read semantics. */
            spin_unlock_irqrestore(&p->lock, fl);
            wait_event(&p->read_waiters,
                       p->count > 0 || refcount_read(&p->write_refs) == 0);
            continue;
        }

        /* Data is available. Copy min(len, count) bytes out of the ring via
         * the modulo view (head = write_pos / producer, tail = read_pos /
         * consumer); rb_pull_n clamps to count and handles the wrap split. */
        ringbuf_t rb;
        rb_init(&rb, p->buf, PIPE_BUF_SIZE, p->write_pos, p->read_pos, p->count);
        uint32_t n = rb_pull_n(&rb, (uint8_t *)buf, (uint32_t)len);
        p->read_pos = rb.tail;   /* write back consumer index + count */
        p->count    = rb.count;
        spin_unlock_irqrestore(&p->lock, fl);

        /*
         * Draining freed space — wake blocked writers AND write-end pollers
         * (one waitq for both).  Done AFTER releasing p->lock: waitq_wake_all
         * takes sched_lock, and the order is sched_lock > waitq > p->lock.
         * The woken writers re-validate p->count under p->lock in their retry
         * loop, so they observe the freed space — no lost wakeup (and a wake
         * that races their block window is caught by wake_pending).
         */
        waitq_wake_all(&p->write_waiters);

        return (int)n;
    }
}

/*
 * pipe_write_fn — write up to len bytes from user buf into the pipe.
 *
 * buf is a USER virtual address (from sys_write after user_ptr_valid check).
 * Uses copy_from_user + staging buffer for SMAP correctness.
 *
 * Stack: staging[PIPE_BUF_SIZE] = 4040 bytes on kernel stack.
 * Call chain: sys_write -> pipe_write_fn. Total depth ~4400 bytes.
 * Kernel stack is 4 pages (16 KB) — within budget.
 * DO NOT add further large locals to this call chain.
 *
 * Returns n bytes written (partial write allowed; sys_write caller loops).
 */
static int
pipe_write_fn(void *priv, const void *buf, uint64_t len)
{
    pipe_t *p = (pipe_t *)priv;
    char staging[PIPE_BUF_SIZE];

    for (;;) {
        irqflags_t fl = spin_lock_irqsave(&p->lock);

        /*
         * Defensive: ring buffer indices must stay within [0, PIPE_BUF_SIZE).
         * Same rationale as pipe_read_fn: silent reset preferred over panic for
         * kernel-internal corruption. Restores invariant before any wrap arithmetic.
         */
        if (p->read_pos  >= PIPE_BUF_SIZE) p->read_pos  = 0;
        if (p->write_pos >= PIPE_BUF_SIZE) p->write_pos = 0;

        if (refcount_read(&p->read_refs) == 0) {
            spin_unlock_irqrestore(&p->lock, fl);
            /* Deliver SIGPIPE to the writer before returning -EPIPE.
             * If the process has SIGPIPE masked or SIG_IGN, it handles
             * -EPIPE via errno. SIGPIPE = 13 per POSIX.
             * Kernel tasks (is_user == 0) have no sigactions and must not
             * receive signals; they get -EPIPE only and must check it. */
            aegis_task_t *t = sched_current();
            if (t && t->is_user) {
                aegis_process_t *p_cur = (aegis_process_t *)t;
                signal_send_pid(p_cur->pid, SIGPIPE);
            }
            return -EPIPE;   /* all readers gone */
        }
        if (p->count == PIPE_BUF_SIZE) {
            /* Full. O_NONBLOCK (per-task write_nonblock, set by sys_write from
             * the fd flags): return EAGAIN instead of blocking — without this an
             * O_NONBLOCK pipe write on a full pipe hangs forever. Only when NO
             * bytes have been written this call; a partial write returns its
             * count from the normal path below. (sys_write returns the partial
             * total and suppresses the EAGAIN if total>0, per POSIX.) */
            if (sched_current()->write_nonblock) {
                spin_unlock_irqrestore(&p->lock, fl);
                return -EAGAIN;
            }
            /* Block until a reader drains space or closes the read end. Drop
             * the lock; wait_event re-validates under p->lock at the top of the
             * loop.  Uninterruptible, matching historical semantics. */
            spin_unlock_irqrestore(&p->lock, fl);
            wait_event(&p->write_waiters,
                       p->count < PIPE_BUF_SIZE ||
                       refcount_read(&p->read_refs) == 0);
            continue;
        }

        /* Compute how many bytes we can accept this call. */
        uint32_t avail = PIPE_BUF_SIZE - p->count;
        uint32_t n = (uint32_t)len;
        if (n > avail) n = avail;

        /* Copy n bytes from user space via staging buffer (SMAP guard).
         * n is already clamped to avail above, so copy_from_user never stages
         * more than the ring can take. */
        copy_from_user(staging, buf, n);

        /* Push the staged bytes through the modulo view (head = write_pos /
         * producer, tail = read_pos / consumer); rb_push_n handles the wrap
         * split.  n <= avail, so it accepts all n. */
        ringbuf_t rb;
        rb_init(&rb, p->buf, PIPE_BUF_SIZE, p->write_pos, p->read_pos, p->count);
        n = rb_push_n(&rb, (const uint8_t *)staging, n);
        p->write_pos = rb.head;   /* write back producer index + count */
        p->count     = rb.count;
        spin_unlock_irqrestore(&p->lock, fl);

        /*
         * Deposited data — wake blocked readers AND read-end pollers (one
         * waitq for both), AFTER releasing p->lock (sched_lock > waitq >
         * p->lock).  The woken readers re-validate p->count under p->lock, so
         * they observe the freshly written bytes — no lost wakeup.
         */
        waitq_wake_all(&p->read_waiters);

        return (int)n;   /* partial write; caller must loop if n < len */
    }
}

/*
 * pipe_read_close_fn — called when the read end of the pipe is closed.
 * Decrements read_refs. If write end is also gone, frees the pipe_t.
 * Wakes any blocked writer so it can observe read_refs == 0 and return EPIPE.
 */
static void
pipe_read_close_fn(void *priv)
{
    pipe_t *p = (pipe_t *)priv;
    irqflags_t fl = spin_lock_irqsave(&p->lock);
    int last_reader_gone = refcount_dec_and_test(&p->read_refs);
    /* Conjunctive free: only when this end newly hit zero AND the opposite
     * end is already at zero. refcount_read of write_refs under p->lock is
     * the other half of the free test. */
    int do_free = (last_reader_gone && refcount_read(&p->write_refs) == 0);

    /* Wake the write-end waitq UNDER p->lock, not after unlock. pipe_t is
     * kva-freed (unlike pty/unix/memfd's never-freed static pools), so a wake
     * after unlock is a use-after-free: the OPPOSITE-end closer, seeing both
     * refs zero, can kva_free_pages(p) in the window between our unlock and our
     * wake — then waitq_wake_all touches a freed p->write_waiters. Waking under
     * the lock is deadlock-safe (p->lock → sched_lock has no inverse: the
     * scheduler never takes a pipe lock) and means only the sole freeing closer
     * touches p after unlock. Blocked writers then observe read_refs == 0 and
     * return EPIPE / see POLLERR. */
    if (last_reader_gone)
        waitq_wake_all(&p->write_waiters);
    spin_unlock_irqrestore(&p->lock, fl);
    if (do_free)
        kva_free_pages(p, 1);
}

/*
 * pipe_write_close_fn — called when the write end of the pipe is closed.
 * Decrements write_refs. Wakes any blocked reader so it observes
 * write_refs == 0 and returns 0 (EOF) on its next retry.
 */
static void
pipe_write_close_fn(void *priv)
{
    pipe_t *p = (pipe_t *)priv;
    irqflags_t fl = spin_lock_irqsave(&p->lock);
    int last_writer_gone = refcount_dec_and_test(&p->write_refs);
    /* Conjunctive free: only when this end newly hit zero AND the opposite
     * end is already at zero. refcount_read of read_refs under p->lock is
     * the other half of the free test. */
    int do_free = (last_writer_gone && refcount_read(&p->read_refs) == 0);

    /* Wake under p->lock — see pipe_read_close_fn: pipe_t is kva-freed, so a
     * post-unlock wake races the opposite-end closer's free (UAF on
     * p->read_waiters). Blocked readers then observe write_refs == 0 with
     * count == 0 and return 0 (EOF) / see POLLIN|POLLHUP. */
    if (last_writer_gone)
        waitq_wake_all(&p->read_waiters);
    spin_unlock_irqrestore(&p->lock, fl);
    if (do_free)
        kva_free_pages(p, 1);
}

/* dup hooks — increment the appropriate ref count when an fd is duplicated */

static void
pipe_dup_read_fn(void *priv)
{
    pipe_t *p = (pipe_t *)priv;
    irqflags_t fl = spin_lock_irqsave(&p->lock);
    refcount_inc(&p->read_refs);
    spin_unlock_irqrestore(&p->lock, fl);
}

static void
pipe_dup_write_fn(void *priv)
{
    pipe_t *p = (pipe_t *)priv;
    irqflags_t fl = spin_lock_irqsave(&p->lock);
    refcount_inc(&p->write_refs);
    spin_unlock_irqrestore(&p->lock, fl);
}

static int
pipe_stat_fn(void *priv, k_stat_t *st)
{
    pipe_t *p = (pipe_t *)priv;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_mode = S_IFIFO | 0600;
    st->st_ino  = 0;    /* anonymous pipe: no inode */
    st->st_size = (int64_t)p->count;
    return 0;
}
