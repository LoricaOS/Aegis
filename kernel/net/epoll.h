/* kernel/net/epoll.h — epoll implementation */
#ifndef EPOLL_H
#define EPOLL_H

#include "sched.h"
#include "vfs.h"
#include "proc.h"
#include "../lib/refcount.h"
#include <stdint.h>

#define EPOLL_MAX_INSTANCES  8
#define EPOLL_MAX_WATCHES    64
#define EPOLL_NONE           0xFFFFFFFFU

/* Linux epoll event flags (values match the Linux ABI exactly). */
#define EPOLLIN       0x00000001U
#define EPOLLPRI      0x00000002U
#define EPOLLOUT      0x00000004U
#define EPOLLERR      0x00000008U
#define EPOLLHUP      0x00000010U
#define EPOLLRDHUP    0x00002000U
#define EPOLLONESHOT  0x40000000U   /* one-shot: disarm after first report */
#define EPOLLET       0x80000000U   /* edge-triggered */

/* Mask of behaviour flags (not readiness bits). Stripped when comparing
 * the requested interest set against computed readiness. */
#define EPOLL_BEHAVIOUR_FLAGS  (EPOLLET | EPOLLONESHOT)

/* Readiness conditions Linux reports unconditionally (the caller does NOT
 * need to request them in events). EPOLLERR/EPOLLHUP are always delivered;
 * EPOLLRDHUP only when explicitly requested. */
#define EPOLL_ALWAYS_REPORT  (EPOLLERR | EPOLLHUP)

/* EPOLL_CTL opcodes */
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef struct __attribute__((packed)) {
    uint32_t events;
    uint64_t data;   /* user data (epoll_data_t union — we treat as uint64_t) */
} k_epoll_event_t;

_Static_assert(sizeof(k_epoll_event_t) == 12,
    "k_epoll_event_t must be 12 bytes (packed, matching Linux ABI)");

typedef struct {
    uint32_t fd;
    uint32_t events;        /* interest mask (incl. EPOLLET/EPOLLONESHOT) */
    uint64_t data;
    uint8_t  in_use;
    /* EPOLLONESHOT: once an event is delivered for this watch, it is
     * disarmed until EPOLL_CTL_MOD re-arms it (re-sets events). */
    uint8_t  oneshot_disabled;
} epoll_watch_t;

typedef struct {
    uint8_t        in_use;
    /* Reference count: one per fd pointing at this instance. dup/dup2/fcntl
     * F_DUPFD and fork (fd_table_copy) fire epoll_vfs_dup → refcount_inc;
     * epoll_vfs_close → refcount_dec_and_test and only frees on the last close.
     * Without this, dup-then-close / fork-then-close double-freed the instance
     * and handed a reused slot to the surviving fd (same UAF class as sock_t).
     * See docs/refcount-migration-spec.md §6. */
    refcount_t     refcount;
    epoll_watch_t  watches[EPOLL_MAX_WATCHES];
    uint8_t        nwatches;
} epoll_fd_t;

/* epoll_alloc: allocate an epoll instance. Returns epoll_id >= 0 or -1. */
int epoll_alloc(void);

/* epoll_get: return pointer to epoll_fd_t, or NULL if invalid. */
epoll_fd_t *epoll_get(uint32_t epoll_id);

/* epoll_free: release an epoll instance. */
void epoll_free(uint32_t epoll_id);

/* epoll_ctl_impl: add/del/mod a watch. */
int epoll_ctl_impl(uint32_t epoll_id, int op, int fd, k_epoll_event_t *ev);

/* epoll_notify: called from TCP/UDP when data or connection event occurs. */
void epoll_notify(uint32_t sock_id, uint32_t events);

/* epoll_wait_impl: wait for events. timeout_ticks: 0=non-blocking, UINT32_MAX=infinite. */
int epoll_wait_impl(uint32_t epoll_id, uint64_t events_uptr,
                    int maxevents, uint32_t timeout_ticks);

/* epoll_open_fd: create an fd for this epoll instance in proc->fd_table->fds[]. */
int epoll_open_fd(uint32_t epoll_id, aegis_process_t *proc);

/* epoll_id_from_fd: reverse-look up epoll_id from a fd. Returns EPOLL_NONE on error. */
uint32_t epoll_id_from_fd(int fd, aegis_process_t *proc);

#endif /* EPOLL_H */
