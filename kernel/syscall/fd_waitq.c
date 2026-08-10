/* fd_waitq.c — fd → waitq dispatch. See fd_waitq.h. */
#include "fd_waitq.h"
#include "proc.h"
#include "sched.h"
#include "waitq.h"
#include "vfs.h"

struct waitq *
fd_get_waitq(int fd)
{
    aegis_process_t *proc = current_proc();

    /* Every pollable fd — AF_INET sockets (s_sock_ops), AF_UNIX sockets
     * (g_unix_sock_ops), pipe, tty, console, kbd, mouse, memfd — exposes its
     * wait queue through vfs_ops_t.get_waitq. (AF_INET/AF_UNIX used to have
     * dedicated branches here; both now carry get_waitq, so the one generic
     * dispatch covers them.) NULL ops or NULL get_waitq = no events to wait on. */
    if (fd >= 0 && (uint32_t)fd < PROC_MAX_FDS) {
        const vfs_ops_t *ops = proc->fd_table->fds[fd].ops;
        if (ops && ops->get_waitq)
            return ops->get_waitq(proc->fd_table->fds[fd].priv);
    }

    return (struct waitq *)0;
}

/* See fd_waitq.h for the failure this prevents. */
int
fd_waitq_pin(int fd, fd_pin_t *out)
{
    aegis_process_t *proc = current_proc();

    out->q = (struct waitq *)0;
    out->ops = (const vfs_ops_t *)0;
    out->priv = (void *)0;

    if (fd < 0 || (uint32_t)fd >= PROC_MAX_FDS)
        return 0;

    const vfs_ops_t *ops = proc->fd_table->fds[fd].ops;
    void            *priv = proc->fd_table->fds[fd].priv;
    if (!ops || !ops->get_waitq)
        return 0;

    struct waitq *q = ops->get_waitq(priv);
    if (!q)
        return 0;

    /* Take the reference BEFORE publishing the queue pointer, so there is no
     * window in which a caller holds the queue without holding the object.
     * An fd type with no ->dup cannot be refcounted; report no queue rather
     * than hand back one we cannot keep alive (fail closed — the caller then
     * simply does not register on it, and still wakes via the timer waitq). */
    if (!ops->dup)
        return 0;
    ops->dup(priv);

    out->q    = q;
    out->ops  = ops;
    out->priv = priv;
    return 1;
}

void
fd_waitq_unpin(fd_pin_t *p)
{
    if (!p->ops)
        return;                     /* never pinned, or already unpinned */
    const vfs_ops_t *ops = p->ops;
    void *priv = p->priv;
    p->q    = (struct waitq *)0;
    p->ops  = (const vfs_ops_t *)0;
    p->priv = (void *)0;
    if (ops->close)
        ops->close(priv);           /* may run teardown if we held the last ref */
}
