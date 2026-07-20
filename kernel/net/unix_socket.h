/* kernel/net/unix_socket.h — AF_UNIX domain sockets */
#ifndef UNIX_SOCKET_H
#define UNIX_SOCKET_H

#include "vfs.h"
#include "sched.h"
#include "spinlock.h"
#include "../sched/waitq.h"
#include "../lib/refcount.h"
#include "../limits.h"
#include <stdint.h>

#define AF_UNIX          1
#define UNIX_SOCK_MAX    AEGIS_UNIX_SOCK_MAX
#define UNIX_PATH_MAX    108
/* Must be a power of two — `unix_socket.c` uses `(head - tail) & (UNIX_BUF_SIZE - 1)`
 * for ring math, which is only valid when the mask is one-bits-only (i.e. size is
 * a power of two). 4056 (the prior value, matching the pipe ring) silently
 * corrupted ring_used()/ring_free() because 4055 = 0b1111_1101_0111 — bits 3
 * and 5 are clear, so any byte count with only those bits set masked to 0
 * (8 bytes available looked like 0 bytes available — see the lumen handshake
 * EAGAIN-after-POLLIN race, fixed 2026-04-15).
 *
 * A protocol frame LARGER than this ring can never be written in one go: the
 * writer spins for space and both ends can end up stuck mid-frame (that was
 * the lumen top-bar freeze — a 4360-byte menu frame against this 4096 ring).
 * The fix belongs on the protocol side (glyph's lumen_set_menu_t is now 2504
 * bytes and static_asserts itself under 4096); raising the ring instead was
 * tried on 2026-07-19 and corrupted memory on arm64 — see the note below.
 *
 * DO NOT raise this without understanding that: bumping it to 16384 (4 kva
 * pages per ring) made the Pi 5 panic during shutdown in fd_table_unref with
 * a garbage fds[].ops, i.e. two owners of the same pages. The alloc/free page
 * counts were consistent and it never reproduced on x86 or in arm64 QEMU, so
 * there is a latent multi-page kva/TLB bug on arm64 hiding behind it. */
#define UNIX_BUF_SIZE    4096
#define UNIX_BUF_PAGES   (UNIX_BUF_SIZE / 4096)
#define UNIX_NONE        0xFFFFFFFFU

/* Staged fd for SCM_RIGHTS passing */
typedef struct {
    const vfs_ops_t *ops;
    void            *priv;
    uint32_t         flags;
} unix_passed_fd_t;

/* Max fds per SCM_RIGHTS send. Canonical value + sizing rationale live in
 * limits.h (AEGIS_UNIX_PASSED_FD_MAX) alongside the other IPC ceilings. */
#define UNIX_PASSED_FD_MAX  AEGIS_UNIX_PASSED_FD_MAX

typedef enum {
    UNIX_FREE, UNIX_CREATED, UNIX_BOUND, UNIX_LISTENING,
    UNIX_CONNECTING, UNIX_CONNECTED, UNIX_CLOSED
} unix_state_t;

typedef struct {
    uint8_t        in_use;
    unix_state_t   state;
    uint8_t        nonblocking;
    char           path[UNIX_PATH_MAX];

    /* Ring buffer — this socket's tx direction (peer reads from it) */
    uint8_t       *ring;           /* kva-allocated page */
    uint16_t       ring_head;      /* write position */
    uint16_t       ring_tail;      /* read position */

    /* Peer link */
    uint32_t       peer_id;        /* connected peer (UNIX_NONE = none) */

    /* Accept queue (listening sockets) */
    uint32_t       accept_queue[8];
    uint8_t        accept_head, accept_tail;

    /* Pending connections waiting for accept */
    aegis_task_t  *connect_waiter; /* task blocked in connect() */

    /* Peer credentials (captured at connect time) */
    uint32_t       peer_pid;
    uint32_t       peer_uid;
    uint32_t       peer_gid;

    /* fd passing staging area */
    unix_passed_fd_t passed_fds[UNIX_PASSED_FD_MAX];
    uint8_t          passed_fd_count;

    /* Refcount for dup/fork */
    refcount_t     refcount;

    /* Wake queue for ALL waiters on this fd — blocking accept/read/write
     * (via wait_event) AND sys_poll / sys_epoll_wait.  One mechanism, not two
     * (the old single-slot waiter_task pointer was removed: it could only
     * remember ONE blocked task, so two threads blocked on the same socket
     * lost a wakeup).  Producers (this socket's ring writer, peer's connect,
     * peer's free) call waitq_wake_all(&poll_waiters), and unix_sock_wake()
     * is now a thin wrapper around it. */
    waitq_t        poll_waiters;
} unix_sock_t;

/* VFS ops for AF_UNIX socket fds */
extern const vfs_ops_t g_unix_sock_ops;

/* Allocate a unix socket. Returns slot index or -1. */
int unix_sock_alloc(void);

/* Create two pre-connected AF_UNIX stream sockets (socketpair). Sets the two out
 * params to the sock ids. Returns 0 or negative errno. */
int unix_sock_pair(uint32_t *a, uint32_t *b);

/* Get unix_sock_t by id. Returns NULL if invalid/free. */
unix_sock_t *unix_sock_get(uint32_t id);

/* Free (decrement refcount, cleanup on zero). */
void unix_sock_free(uint32_t id);

/* Wake everything blocked on this unix socket (blocking accept/read/write +
 * poll/epoll waiters) by waking its poll_waiters queue. Thin wrapper around
 * waitq_wake_all; do NOT call under unix_lock. */
void unix_sock_wake(uint32_t id);

/* Bind a unix socket to a path. Returns 0 or -errno. */
int unix_sock_bind(uint32_t id, const char *path);

/* Listen on a bound unix socket. Returns 0 or -errno. */
int unix_sock_listen(uint32_t id);

/* Connect to a listening unix socket by path. Returns 0 or -errno. */
int unix_sock_connect(uint32_t id, const char *path);

/* Accept a connection on a listening socket. Returns new sock_id or -errno. */
int unix_sock_accept(uint32_t id);

/* Read from unix socket (from peer's tx_ring). Returns bytes read or -errno.
 * force_nb: if nonzero, behave as O_NONBLOCK for THIS call only (per-call
 * MSG_DONTWAIT) — return -EAGAIN instead of blocking when no data. */
int unix_sock_read(uint32_t id, void *buf, uint32_t len, int force_nb);

/* Write to unix socket (to own tx_ring). Returns bytes written or -errno. */
int unix_sock_write(uint32_t id, const void *buf, uint32_t len);

/* Get peer credentials. Returns 0 or -errno. */
int unix_sock_peercred(uint32_t id, uint32_t *pid, uint32_t *uid, uint32_t *gid);

/* Stage fds for SCM_RIGHTS passing to peer. Returns 0 or -errno. */
int unix_sock_stage_fds(uint32_t peer_id, unix_passed_fd_t *fds, uint8_t count);

/* Receive staged fds. Returns count installed or -errno. */
int unix_sock_recv_fds(uint32_t id, int *fd_out, int max_fds);

/* Open an fd backed by a unix socket. Returns fd or -1. */
int unix_sock_open_fd(uint32_t sock_id, void *proc);

/* Get unix_sock_id from an fd. Returns UNIX_NONE if not a unix socket. */
uint32_t unix_sock_id_from_fd(int fd, void *proc);

/* Get the wait queue for an AF_UNIX socket. Used by sys_poll. */
waitq_t *unix_sock_get_waitq(uint32_t id);

#endif /* UNIX_SOCKET_H */
