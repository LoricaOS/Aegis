/* fd_waitq.c — fd → waitq dispatch. See fd_waitq.h. */
#include "fd_waitq.h"
#include "proc.h"
#include "sched.h"
#include "waitq.h"
#include "vfs.h"

/* See fd_waitq.h for the failure this prevents. */
int
fd_waitq_pin(int fd, fd_pin_t *out)
{
    aegis_process_t *proc = current_proc();

    out->q = (struct waitq *)0;
    if (!fd_table_pin(proc->fd_table, fd, &out->file))
        return 0;

    const vfs_ops_t *ops = out->file.file.ops;
    if (!ops->get_waitq) {
        fd_table_unpin(&out->file);
        return 0;
    }

    out->q = ops->get_waitq(out->file.file.priv);
    if (!out->q) {
        fd_table_unpin(&out->file);
        return 0;
    }
    return 1;
}

void
fd_waitq_unpin(fd_pin_t *p)
{
    p->q = (struct waitq *)0;
    fd_table_unpin(&p->file);
}
