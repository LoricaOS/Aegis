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
