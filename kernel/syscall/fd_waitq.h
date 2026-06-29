/* fd_waitq.h — fd → waitq dispatch for sys_poll / sys_epoll_wait. */
#ifndef AEGIS_FD_WAITQ_H
#define AEGIS_FD_WAITQ_H

struct waitq;

/* fd_get_waitq — return the wait queue for an fd in the current process,
 * or NULL if the fd type has no events to wait on. AF_INET is stubbed
 * NULL until Task 6 wires it in.
 *
 * Used by sys_poll and sys_epoll_wait to register the calling task on
 * each watched fd's queue so producers (writes, ISRs, state changes)
 * can wake all blocked pollers immediately. */
struct waitq *fd_get_waitq(int fd);

#endif /* AEGIS_FD_WAITQ_H */
