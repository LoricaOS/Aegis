#ifndef PIPE_H
#define PIPE_H

#include "vfs.h"
#include "sched.h"
#include "spinlock.h"
#include "../sched/waitq.h"
#include "../lib/refcount.h"
#include <stdint.h>

/*
 * PIPE_BUF_SIZE is chosen so that sizeof(pipe_t) == 4096 exactly.
 *
 * Layout:
 *   buf[PIPE_BUF_SIZE]          = PIPE_BUF_SIZE bytes
 *   read_pos/write_pos/count    = 3 * 4 = 12 bytes
 *   read_refs/write_refs        = 2 * 4 =  8 bytes   (total uint32 = 20 bytes)
 *                                 (each is a refcount_t, which is exactly one
 *                                  uint32_t — byte-for-byte identical layout)
 *   lock (spinlock_t)           = 4 bytes             (fills alignment gap)
 *   read_waiters  (waitq_t)     = 16 bytes (8 ptr + 4 spinlock + 4 pad)
 *   write_waiters (waitq_t)     = 16 bytes
 *
 * 4040 + 20 + 4 + 32 = 4096 = one kva page.
 * Verified by _Static_assert in pipe.c.
 *
 * The blocking read/write paths register on read_waiters / write_waiters via
 * wait_event() — the same queues sys_poll/sys_epoll use — so there is one
 * waiter mechanism, not two. (The old bespoke reader_waiting/writer_waiting
 * single-task pointers were removed: they could only remember ONE blocked
 * task, silently losing wakeups when multiple readers/writers blocked on the
 * same pipe. waitq_wake_all wakes them all.)
 */
#define PIPE_BUF_SIZE 4040

typedef struct {
    uint8_t          buf[PIPE_BUF_SIZE];
    uint32_t         read_pos;
    uint32_t         write_pos;
    uint32_t         count;           /* bytes currently buffered */
    refcount_t       read_refs;       /* number of open read-end fds */
    refcount_t       write_refs;      /* number of open write-end fds */
    spinlock_t       lock;            /* per-pipe lock for SMP safety */
    /* Wake queues for blocking I/O AND sys_poll / sys_epoll_wait waiters on
     * each end (one unified mechanism).
     * read_waiters: blocked readers + pollers on the read end (wake when data
     *   arrives or the write end closes — POLLIN / POLLHUP).
     * write_waiters: blocked writers + pollers on the write end (wake when the
     *   buffer drains or the read end closes — POLLOUT / POLLHUP). */
    waitq_t          read_waiters;
    waitq_t          write_waiters;
} pipe_t;

/*
 * g_pipe_read_ops / g_pipe_write_ops — installed by sys_pipe2 into fds[].
 * Defined in pipe.c; declared here for use in syscall.c.
 */
extern const vfs_ops_t g_pipe_read_ops;
extern const vfs_ops_t g_pipe_write_ops;

#endif /* PIPE_H */
