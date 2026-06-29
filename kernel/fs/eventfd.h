#ifndef EVENTFD_H
#define EVENTFD_H

#include "vfs.h"
#include "spinlock.h"
#include "../sched/waitq.h"
#include "../lib/refcount.h"
#include <stdint.h>

/*
 * eventfd_t — a 64-bit counter exposed as a single fd (read+write share ops).
 * write(efd, &v, 8) adds v to the counter; read(efd, &v, 8) drains it (returns
 * the value and resets to 0, or returns 1 and decrements in EFD_SEMAPHORE mode).
 * Backed by one kva page like pipe_t. Used by libcurl's curl_multi wakeup.
 */
typedef struct {
    uint64_t   count;
    uint32_t   flags;          /* EFD_SEMAPHORE (other bits ignored here) */
    refcount_t refs;           /* open fd count; freed when it hits 0 */
    spinlock_t lock;
    waitq_t    read_waiters;   /* blocked readers + POLLIN pollers */
    waitq_t    write_waiters;  /* blocked writers + POLLOUT pollers */
} eventfd_t;

extern const vfs_ops_t g_eventfd_ops;

/* sys_eventfd2 — syscall 290. arg1 = initval, arg2 = flags. Returns fd. */
uint64_t sys_eventfd2(uint64_t initval, uint64_t flags);

#endif /* EVENTFD_H */
