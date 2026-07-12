/* kernel/net/socket.h — in-kernel socket table */
#ifndef SOCKET_H
#define SOCKET_H

#include "net.h"
#include "vfs.h"
#include "sched.h"
#include "proc.h"
#include "../sched/waitq.h"
#include "../lib/refcount.h"
#include "../limits.h"
#include <stdint.h>

#define SOCK_TABLE_SIZE  AEGIS_SOCK_TABLE_SIZE
#define SOCK_NONE        0xFFFFFFFFU   /* sentinel: no socket/conn */

#define SOCK_TYPE_STREAM 1   /* SOCK_STREAM — TCP */
#define SOCK_TYPE_DGRAM  2   /* SOCK_DGRAM — UDP */

/* AF_INET */
#define AF_INET  2
/* INADDR_ANY */
#define INADDR_ANY 0

typedef enum {
    SOCK_FREE, SOCK_CREATED, SOCK_BOUND, SOCK_LISTENING,
    SOCK_CONNECTING, SOCK_CONNECTED, SOCK_CLOSED
} sock_state_t;

/* UDP receive ring: 8 datagrams of up to 1500 bytes each */
#define UDP_RX_SLOTS  8
#define UDP_RX_MAXBUF 1500

typedef struct {
    uint8_t    data[UDP_RX_MAXBUF];
    uint16_t   len;
    ip4_addr_t src_ip;
    uint16_t   src_port;
    uint8_t    in_use;
} udp_rx_slot_t;

typedef struct {
    sock_state_t  state;
    /* Reference count: one per fd pointing at this slot. dup/dup2/fcntl
     * F_DUPFD and fork (fd_table_copy) each fire sock_vfs_dup → refcount_inc;
     * sock_vfs_close → refcount_dec_and_test and only tears down the slot on
     * the last close. Without this, dup-then-close / fork-then-close
     * double-freed the slot and handed a reused slot to the surviving fd
     * (cross-connection UAF). See docs/refcount-migration-spec.md §5. */
    refcount_t    refcount;
    uint8_t       type;          /* SOCK_TYPE_STREAM or SOCK_TYPE_DGRAM */
    uint8_t       nonblocking;
    ip4_addr_t    local_ip;
    uint16_t      local_port;
    ip4_addr_t    remote_ip;
    uint16_t      remote_port;
    uint32_t      tcp_conn_id;   /* index into tcp_conn table; SOCK_NONE if none */
    /* accept queue: ring of completed tcp_conn_id values */
    uint32_t      accept_queue[8];
    uint8_t       accept_head, accept_tail;
    /* UDP receive ring */
    udp_rx_slot_t udp_rx[UDP_RX_SLOTS];
    uint8_t       udp_rx_head, udp_rx_tail;
    /* epoll back-reference */
    uint32_t      epoll_id;      /* SOCK_NONE = not watched */
    uint64_t      epoll_events;
    /* options */
    uint8_t       reuseaddr;
    uint8_t       broadcast;
    /* SO_RCVTIMEO / SO_SNDTIMEO: timeout in PIT ticks (0 = no timeout) */
    uint32_t      rcvtimeo_ticks;
    uint32_t      sndtimeo_ticks;
    /* Wake queue for ALL waiters on this fd — blocking accept/connect/recv
     * (via wait_event) AND sys_poll / sys_epoll_wait.  One mechanism, not two
     * (the old single-slot waiter_task pointer was removed: it could only
     * remember ONE blocked task, so two threads blocked on the same socket
     * lost a wakeup).  Producers (TCP rx, accept enqueue, UDP rx, TCP state→
     * CLOSE_WAIT/CLOSED/TIME_WAIT) call waitq_wake_all(&poll_waiters), and
     * sock_wake() is now a thin wrapper around it. */
    waitq_t       poll_waiters;
} sock_t;

/* sock_alloc: find a free slot, mark it in-use, set type. Returns sock_id >= 0 or -1. */
int sock_alloc(uint8_t type);

/* sock_get: return pointer to sock_t for sock_id, or NULL if invalid/free. */
sock_t *sock_get(uint32_t sock_id);

/* sock_get_nolock: return pointer without acquiring sock_lock.
 * Only safe when caller holds a lock that prevents concurrent sock_free. */
sock_t *sock_get_nolock(uint32_t sock_id);

/* sock_free: mark slot free. Called on close. */
void sock_free(uint32_t sock_id);

/* sock_ref/sock_unref: pin a socket across a blocking syscall (send/recv/accept/
 * connect) so a concurrent close of the same fd can't free the slot under a
 * parked waiter. sock_unref tears down at the last reference. */
void sock_ref(uint32_t sock_id);
void sock_unref(uint32_t sock_id);

/* sock_wake: wake everything blocked on this socket (blocking accept/connect/
 * recv + poll/epoll waiters) by waking its poll_waiters queue. Thin wrapper
 * around waitq_wake_all; do NOT call under tcp_lock/sock_lock. */
void sock_wake(uint32_t sock_id);

/* sock_stream_send: blocking TCP send of a user buffer (`ubuf`), segmenting
 * over time and blocking on send-space when the ring fills (honors O_NONBLOCK).
 * Returns bytes sent (>=0) or -errno.  Shared by write() and send()/sendto(). */
int64_t sock_stream_send(sock_t *s, uint64_t ubuf, uint64_t len);

/* sock_open_fd: allocate an fd backed by sock_id. Returns fd >= 0 or -1. */
int sock_open_fd(uint32_t sock_id, aegis_process_t *proc);

/* sock_id_from_fd: look up the sock_id from an fd. Returns SOCK_NONE on error. */
uint32_t sock_id_from_fd(int fd, aegis_process_t *proc);

/* sock_get_waitq: return the embedded poll_waiters for sock_id, or NULL.
 * Used by fd_waitq.c to dispatch sys_poll / sys_epoll_wait waiters. */
waitq_t *sock_get_waitq(uint32_t sock_id);

/* k_sockaddr_in: musl struct sockaddr_in layout */
typedef struct {
    uint16_t sin_family;
    uint16_t sin_port;   /* network byte order */
    uint32_t sin_addr;   /* network byte order */
    uint8_t  sin_zero[8];
} k_sockaddr_in_t;

_Static_assert(sizeof(k_sockaddr_in_t) == 16,
    "k_sockaddr_in_t must be 16 bytes");

#endif /* SOCKET_H */
