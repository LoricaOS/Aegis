#ifndef AEGIS_FD_RESOLVE_H
#define AEGIS_FD_RESOLVE_H
/*
 * fd_resolve.h — the one fd→object resolver, replacing N copies of the same
 * three-line check.
 *
 * Every fd-backed subsystem has a `*_id_from_fd` (or get-by-fd) helper that:
 *   1. bounds-checks fd against PROC_MAX_FDS,
 *   2. compares proc->fd_table->fds[fd].ops against its own ops vtable,
 *   3. returns fds[fd].priv (an id or pointer) on a match, a sentinel otherwise.
 * The raw `fds[fd].ops` compare appears ~60×. The helpers:
 *   - sock_id_from_fd        net/socket.c
 *   - unix_sock_id_from_fd   net/unix_socket.c
 *   - epoll_id_from_fd       net/epoll.c
 *   - memfd_from_fd          fs/memfd.c
 *   - get_proc_sock (wraps sock_id_from_fd)  syscall/sys_socket.c
 *
 * THE REAL DIVERGENCE THIS FIXES (a latent NULL-deref): sock_id_from_fd
 * null-checks `.ops` BEFORE comparing it; unix_sock_id_from_fd and memfd_from_fd
 * do NOT — they go straight to `fds[fd].ops != &g_..._ops`. Comparing a NULL ops
 * to a non-NULL vtable address happens to return "not equal" (safe by luck), but
 * the inconsistency is exactly the kind of thing that bites when someone copies
 * the wrong template. The unified resolver ALWAYS null-checks .ops first, so
 * every subsystem gets the safe behaviour and the question never recurs.
 *
 * The bounds check uses PROC_MAX_FDS and the same fd_table->fds[] layout every
 * caller already touches, so this is a pure de-duplication — no semantic change
 * beyond the null-check unification.
 *
 * Each subsystem keeps its existing public function as a ONE-LINE cast wrapper
 * so callers and return-type sentinels (SOCK_NONE / UNIX_NONE / EPOLL_NONE /
 * NULL) are unchanged:
 *
 *   uint32_t sock_id_from_fd(int fd, aegis_process_t *proc) {
 *       vfs_file_t *f = fd_resolve(proc, fd, &s_sock_ops);
 *       return f ? (uint32_t)(uintptr_t)f->priv : SOCK_NONE;
 *   }
 *   memfd_t *memfd_from_fd(int fd, void *proc) {
 *       vfs_file_t *f = fd_resolve((aegis_process_t *)proc, fd, &g_memfd_ops);
 *       return f ? memfd_get((uint32_t)(uintptr_t)f->priv) : (memfd_t *)0;
 *   }
 *
 * Header-only static inline (like refcount.h): no TU, no SRCS entry. Include as
 * "fd_resolve.h" from the fs/ TUs already on -Ikernel/fs, or "../fs/fd_resolve.h"
 * from net/ and syscall/. Pulls in vfs.h (for vfs_ops_t, PROC_MAX_FDS, the
 * fd_table layout) and proc.h (aegis_process_t).
 */
#include "vfs.h"
#include "proc.h"
#include <stdint.h>

/*
 * fd_resolve — return the fd-table SLOT (&fds[fd]) if `fd` is a valid open fd in
 * `proc` whose ops vtable is exactly `expected`; otherwise NULL.
 *
 * Order of checks (all required):
 *   - fd in [0, PROC_MAX_FDS)            — out-of-range / negative fd
 *   - fds[fd].ops != NULL                — closed slot (the null-check that
 *                                          socket had but unix/memfd lacked)
 *   - fds[fd].ops == expected            — wrong object type for this fd
 *
 * IMPORTANT: this returns the SLOT POINTER, never fds[fd].priv. The validity
 * signal (non-NULL slot) is kept SEPARATE from the stored value, because every
 * subsystem stores an integer id in `priv` for which 0 is a VALID id — and the
 * lowest-numbered object (id 0) therefore has priv == NULL. If fd_resolve
 * returned priv directly, a valid slot-0 object (priv NULL) would be
 * indistinguishable from a closed slot, and the wrapper's `? : SENTINEL` would
 * wrongly report "not found". (That exact bug broke AF_UNIX slot 0 → Lumen's
 * bind() returned EBADF.) Returning the slot makes "found" unambiguous; the
 * caller then reads f->priv, whose 0 is a perfectly good id. The one-line
 * wrappers (above) translate a NULL slot to each subsystem's sentinel.
 */
static inline vfs_file_t *
fd_resolve(aegis_process_t *proc, int fd, const vfs_ops_t *expected)
{
    if (fd < 0 || (uint32_t)fd >= PROC_MAX_FDS)
        return (vfs_file_t *)0;
    vfs_file_t *f = &proc->fd_table->fds[fd];
    if (!f->ops || f->ops != expected)
        return (vfs_file_t *)0;
    return f;
}

#endif /* AEGIS_FD_RESOLVE_H */
