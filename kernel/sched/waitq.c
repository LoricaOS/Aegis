/* waitq.c — wait queue with caller-allocated entries. See waitq.h. */
#include "waitq.h"
#include "sched.h"
#include "spinlock.h"
#include <stddef.h>

/* PIT-tick-driven timer waitq; see waitq.h for usage. */
waitq_t g_timer_waitq = WAITQ_INIT;

void
waitq_add(waitq_t *wq, waitq_entry_t *e)
{
    irqflags_t fl = spin_lock_irqsave(&wq->lock);
    e->prev = NULL;
    e->next = wq->head;
    if (wq->head) wq->head->prev = e;
    wq->head    = e;
    e->on_queue = 1;
    spin_unlock_irqrestore(&wq->lock, fl);
}

void
waitq_remove(waitq_t *wq, waitq_entry_t *e)
{
    irqflags_t fl = spin_lock_irqsave(&wq->lock);
    if (e->on_queue) {
        if (e->prev) e->prev->next = e->next;
        else         wq->head      = e->next;
        if (e->next) e->next->prev = e->prev;
        e->prev     = NULL;
        e->next     = NULL;
        e->on_queue = 0;
    }
    spin_unlock_irqrestore(&wq->lock, fl);
}

void
waitq_wake_one(waitq_t *wq)
{
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    spin_lock(&wq->lock);
    if (wq->head && wq->head->task)
        sched_wake_locked(wq->head->task);
    spin_unlock(&wq->lock);
    spin_unlock_irqrestore(&sched_lock, fl);
}

void
waitq_wake_all(waitq_t *wq)
{
    /* Protect both waiter entries and task lifetime through the wake. Walk
     * once: waiters need not run or unlink before this function returns. */
    irqflags_t fl = spin_lock_irqsave(&sched_lock);
    spin_lock(&wq->lock);
    for (waitq_entry_t *e = wq->head; e; e = e->next)
        if (e->task) sched_wake_locked(e->task);
    spin_unlock(&wq->lock);
    spin_unlock_irqrestore(&sched_lock, fl);
}

void
waitq_wait(waitq_t *wq)
{
    /* Wake holds the queue lock through task access, so the entry remains
     * live until waitq_remove completes. */
    waitq_entry_t e = { .task = sched_current(), .next = NULL,
                        .prev = NULL,           .on_queue = 0 };
    waitq_add(wq, &e);
    sched_block();
    waitq_remove(wq, &e);
}
