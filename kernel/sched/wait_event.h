#ifndef AEGIS_WAIT_EVENT_H
#define AEGIS_WAIT_EVENT_H
/*
 * wait_event.h — the blessed blocking primitive for Aegis kernel code.
 *
 * Replaces hand-rolled "register a waiter; loop; sched_block()" code with one
 * audited, race-free pattern. Every blocking wait in the kernel should go
 * through these macros, so the sleep/wakeup logic lives in exactly one place
 * and no call site can reintroduce a lost-wakeup or a missing re-check.
 *
 * Why a loop is still here (and always will be): a blocked task can be woken
 * for reasons other than its own condition — a delivered signal, or a
 * waitq_wake_all() that wakes every waiter on a shared queue when only one can
 * make progress. The woken task MUST therefore re-check its condition. That is
 * fundamental to interruptible blocking (it is exactly what Linux's wait_event
 * does). The LOST-WAKEUP RACE is a different problem and is fully handled by
 * sched.c's wake_pending guard: a wake that lands after waitq_add() but before
 * sched_block() is recorded, not lost. So callers never hand-roll the loop and
 * can never reintroduce the race — the loop here only absorbs the inherent
 * spurious/shared wakeups.
 *
 * Contract:
 *   - wqp:  &obj->waiters (waitq_t *). After updating state and dropping the
 *           object lock, the waker calls waitq_wake_all(wqp).
 *           Lock order: sched_lock > waitq lock > object lock. Wake OUTSIDE the
 *           object lock.
 *   - cond: re-evaluated on every wakeup. It MUST be safe to evaluate WITHOUT
 *           the object lock — a stale read just costs one extra loop iteration.
 *           The authoritative re-check + data consumption happens under the
 *           object lock in the caller AFTER the wait returns. The macro does
 *           waitq_add() BEFORE the first cond check, which together with
 *           wake_pending closes the race: any wake after registration is seen.
 *   - cond and wqp are evaluated multiple times — keep them side-effect-free.
 *
 * Memory ordering (SMP/weak-memory safe, no explicit barrier needed): the
 * lockless cond read is safe because every false-path iteration goes through
 * sched_block(), which acquires sched_lock, and a waker publishes its state
 * then calls waitq_wake_all()->sched_wake() which sets the woken task RUNNING
 * under sched_lock. So the cond re-check that follows sched_block() is ordered
 * after the waker's writes (acquire/release pair on sched_lock). A first,
 * pre-block cond read that sees a stale value is always followed by a
 * synchronizing sched_block() + re-check, so it cannot wedge.
 *
 * The including translation unit gets sched.h + signal.h via this header; the
 * _timeout variant additionally needs arch.h (for arch_get_ticks()).
 */
#include "waitq.h"
#include "sched.h"
#include "signal.h"

/* block_result_t — typed outcome of a wait_event_interruptible / _timeout wait.
 * Values are deliberately the negative errnos callers already return, so
 * existing `if (rc == BLOCK_EINTR)` and `if (rc < 0)` tests are unchanged; the
 * names just make the magic numbers self-documenting (Serenity's BlockResult,
 * Kernel/Tasks/Thread.h, but kept as plain errno-valued codes to stay
 * behaviour-identical). `rc` may still be a plain int. */
typedef enum {
    BLOCK_OK        = 0,      /* condition satisfied */
    BLOCK_EINTR     = -4,     /* interrupted by a pending signal (-EINTR) */
    BLOCK_ETIMEDOUT = -110,   /* deadline reached (-ETIMEDOUT) */
} block_result_t;

/* Block until cond is true. Uninterruptible: a signal does not break the wait
 * (it is noticed after the wait completes, the way an uninterruptible kernel
 * sleep behaves). */
#define wait_event(wqp, cond)                                             \
    do {                                                                  \
        waitq_entry_t __we = { .task = sched_current() };                 \
        waitq_add((wqp), &__we);                                          \
        while (!(cond))                                                   \
            sched_block();                                                \
        waitq_remove((wqp), &__we);                                       \
    } while (0)

/* Block until cond is true OR a signal is pending. Sets (rc) to BLOCK_OK on a
 * normal completion, or BLOCK_EINTR if a signal interrupted the wait. */
#define wait_event_interruptible(wqp, cond, rc)                           \
    do {                                                                  \
        waitq_entry_t __we = { .task = sched_current() };                 \
        waitq_add((wqp), &__we);                                          \
        (rc) = BLOCK_OK;                                                  \
        while (!(cond)) {                                                 \
            if (signal_check_pending()) { (rc) = BLOCK_EINTR; break; }    \
            sched_block();                                                \
        }                                                                 \
        waitq_remove((wqp), &__we);                                       \
    } while (0)

/* Block until cond is true, a signal is pending, or arch_get_ticks() reaches
 * `deadline` (absolute PIT ticks). Sets (rc) to BLOCK_OK (cond met),
 * BLOCK_EINTR, or BLOCK_ETIMEDOUT. Requires arch.h in the including TU for
 * arch_get_ticks(). Sets the task's sleep_deadline so sched_tick wakes it. */
#define wait_event_timeout(wqp, cond, deadline, rc)                       \
    do {                                                                  \
        waitq_entry_t __we = { .task = sched_current() };                 \
        waitq_add((wqp), &__we);                                          \
        sched_current()->sleep_deadline = (deadline);                     \
        (rc) = BLOCK_OK;                                                  \
        while (!(cond)) {                                                 \
            if (signal_check_pending()) { (rc) = BLOCK_EINTR; break; }    \
            if (arch_get_ticks() >= (deadline)) {                         \
                (rc) = BLOCK_ETIMEDOUT; break;                            \
            }                                                             \
            sched_block();                                                \
        }                                                                 \
        sched_current()->sleep_deadline = 0;                              \
        waitq_remove((wqp), &__we);                                       \
    } while (0)

#endif /* AEGIS_WAIT_EVENT_H */
