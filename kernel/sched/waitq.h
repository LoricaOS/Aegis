#ifndef AEGIS_WAITQ_H
#define AEGIS_WAITQ_H

/*
 * waitq_t — kernel wait queue with caller-allocated entries.
 *
 * One task may register on N queues simultaneously by using N entries.
 * sys_poll uses this: one entry per pollfd, all on the kernel stack.
 *
 * Producer pattern:
 *     waitq_wake_all(&obj->poll_waiters);
 *
 * Consumer pattern (multi-queue):
 *     waitq_entry_t e[N];
 *     for (i = 0; i < N; i++) {
 *         e[i].task = sched_current();
 *         waitq_add(&queues[i], &e[i]);
 *     }
 *     sched_block();
 *     for (i = 0; i < N; i++) waitq_remove(&queues[i], &e[i]);
 *
 * Consumer pattern (single-queue convenience):
 *     waitq_wait(&obj->poll_waiters);
 *
 * waitq_remove is idempotent — safe even if the entry was never added or
 * has already been removed by another path. This keeps the cleanup loop
 * simple regardless of which queue actually fired the wake.
 *
 * All ops take spin_lock_irqsave on the queue's lock. ISR-safe.
 */

#include <stddef.h>
#include <stdint.h>
#include "spinlock.h"

struct aegis_task_t;

typedef struct waitq_entry {
    struct aegis_task_t *task;
    struct waitq_entry  *next;
    struct waitq_entry  *prev;
    /* on_queue: 1 while linked into a waitq's list; 0 otherwise.
     * Used by waitq_remove to be idempotent. */
    uint8_t              on_queue;
} waitq_entry_t;

typedef struct waitq {
    waitq_entry_t *head;
    spinlock_t     lock;
} waitq_t;

#define WAITQ_INIT { .head = NULL, .lock = SPINLOCK_INIT }

static inline void
waitq_init(waitq_t *wq)
{
    wq->head = NULL;
    wq->lock = (spinlock_t)SPINLOCK_INIT;
}

/* waitq_add — link entry into queue at head. Caller fills entry->task
 * before calling. Must NOT be called on an entry that is already on
 * any queue (no double-add). */
void waitq_add(waitq_t *wq, waitq_entry_t *entry);

/* waitq_remove — unlink entry from queue. Idempotent. */
void waitq_remove(waitq_t *wq, waitq_entry_t *entry);

/* waitq_wake_one — sched_wake the head waiter (no remove; the woken
 * task removes itself in its cleanup path). No-op if queue empty.
 * Safe to call from IRQ context. */
void waitq_wake_one(waitq_t *wq);

/* waitq_wake_all — sched_wake every entry's task in the queue (no
 * remove; each woken task removes itself). Safe from IRQ context. */
void waitq_wake_all(waitq_t *wq);

/* waitq_wait — convenience for single-queue blocking I/O paths.
 * Allocates a stack entry, adds, sched_block, removes on return.
 * Caller must have checked the wait condition is NOT met. */
void waitq_wait(waitq_t *wq);

/* g_timer_waitq — woken once per PIT tick by the timer ISR.
 * sys_poll / sys_epoll_wait with a finite timeout register on this
 * queue so they wake to re-check their deadline. Calls with timeout=-1
 * skip it (zero overhead, no spurious wakes). */
extern waitq_t g_timer_waitq;

#endif /* AEGIS_WAITQ_H */
