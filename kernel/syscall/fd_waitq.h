/* fd_waitq.h — fd → waitq dispatch for sys_poll / sys_epoll_wait. */
#ifndef AEGIS_FD_WAITQ_H
#define AEGIS_FD_WAITQ_H

#include "vfs.h"   /* vfs_ops_t is an anonymous-struct typedef — cannot be
                   * forward-declared, so the real header is required here.
                   * vfs.h does not include this file, so no cycle. */

struct waitq;

/* fd_get_waitq — return the wait queue for an fd in the current process,
 * or NULL if the fd type has no events to wait on.
 *
 * DANGER: this takes NO reference on the object owning the queue. The pointer
 * is only safe while nothing can close the fd — i.e. it must NOT be held
 * across a block. Use fd_waitq_pin for that; see below.
 */
struct waitq *fd_get_waitq(int fd);

/* fd_waitq_pin / fd_waitq_unpin — resolve an fd to its wait queue AND hold a
 * reference on the backing object for as long as we are linked into that queue.
 *
 * THE BUG THIS EXISTS TO PREVENT.  A multiplexer links a waitq_entry_t that
 * lives on ITS OWN KERNEL STACK into an object's queue and then blocks. The
 * queue is interior to the object (`&p->read_waiters`, `&s->poll_waiters`, …).
 * If a sibling thread sharing the fd table (CLONE_FILES) closes that fd while
 * we are parked, the last reference drops and the object is freed — pipe_t and
 * eventfd_t are kva_alloc_pages(1)/kva_free_pages(1), and freed KVA goes onto a
 * coalescing freelist that hands the range straight back to the next
 * allocation. Our entry is then linked into memory that now belongs to a
 * DIFFERENT live object, and the waitq_remove on wake writes through it.
 *
 * Six blocking-I/O paths already defend against exactly this by taking a
 * reference for the duration (sock_vfs_read, unix_sock_read, pipe_read_fn,
 * pipe_write_fn, master_read_fn, slave_read_fn — each calls its own ops->dup
 * on entry and ops->close on every exit). The multiplexers park on those same
 * queues and had no such protection. This is that same pin, factored so every
 * caller gets it from one place.
 *
 * Returns 1 and fills *out if the fd has a queue (pinned); 0 otherwise, with
 * *out zeroed. An unpin of a zeroed/unfilled pin is a no-op, so callers can
 * unconditionally unpin the whole array.
 */
typedef struct {
    struct waitq         *q;     /* the queue, or NULL */
    const vfs_ops_t      *ops;   /* non-NULL only while a ref is held */
    void                 *priv;
} fd_pin_t;

int  fd_waitq_pin(int fd, fd_pin_t *out);
void fd_waitq_unpin(fd_pin_t *p);

#endif /* AEGIS_FD_WAITQ_H */
