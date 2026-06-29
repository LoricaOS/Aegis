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
    irqflags_t fl = spin_lock_irqsave(&wq->lock);
    waitq_entry_t *e = wq->head;
    aegis_task_t  *t = e ? e->task : NULL;
    spin_unlock_irqrestore(&wq->lock, fl);
    if (t) sched_wake(t);
}

void
waitq_wake_all(waitq_t *wq)
{
    /* Snapshot tasks under the lock, sched_wake outside (sched_lock >
     * waitq_lock). Loop in batches of 64 stack entries so we never
     * silently drop a waiter when fan-out exceeds the snapshot size.
     * The woken tasks are responsible for calling waitq_remove on
     * themselves — sched_wake just flips state to RUNNING. */
    for (;;) {
        aegis_task_t *snap[64];
        int           n = 0;

        irqflags_t fl = spin_lock_irqsave(&wq->lock);
        for (waitq_entry_t *e = wq->head; e && n < 64; e = e->next)
            snap[n++] = e->task;
        spin_unlock_irqrestore(&wq->lock, fl);

        if (n == 0) return;

        for (int i = 0; i < n; i++)
            if (snap[i]) sched_wake(snap[i]);

        if (n < 64) return;
        /* List had >= 64 entries — there may be more after the woken
         * tasks remove themselves. Re-acquire and continue. */
    }
}

void
waitq_wait(waitq_t *wq)
{
    /* Stack-allocated entry. Safe across the sched_block window because
     * waitq_wake_one / waitq_wake_all snapshot e->task (a stable pointer
     * to the TCB), not &e itself — they never dereference the entry
     * after dropping wq->lock. A future refactor that snapshots entry
     * pointers would silently introduce a UAF here. */
    waitq_entry_t e = { .task = sched_current(), .next = NULL,
                        .prev = NULL,           .on_queue = 0 };
    waitq_add(wq, &e);
    sched_block();
    waitq_remove(wq, &e);
}
