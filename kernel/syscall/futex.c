/* kernel/syscall/futex.c — futex WAIT/WAKE implementation */
#include "futex.h"
#include "sched.h"
#include "proc.h"      /* current_proc()->pml4_phys — the futex address-space key */
#include "syscall_util.h"
#include "uaccess.h"
#include "spinlock.h"
#include "signal.h"
#include "../limits.h"
#include "../include/aegis_errno.h"

/* Value single-sourced in limits.h (AEGIS_FUTEX_MAX_WAIT). */
#define FUTEX_MAX_WAIT AEGIS_FUTEX_MAX_WAIT

typedef struct {
    aegis_task_t *task;
    uint64_t      addr;
    uint64_t      mm;      /* address-space key (process pml4_phys): a futex VA is
                            * per-address-space, so two processes' private futexes
                            * at the SAME user VA (e.g. libc's fixed-VA malloc/stdio
                            * locks) are DIFFERENT futexes. Matching addr alone made
                            * one process's FUTEX_WAKE wake another's waiter, which
                            * re-blocked → the intended waiter hung. Threads of one
                            * process share pml4_phys, so they still match. */
    uint8_t       in_use;
    uint8_t       woken;   /* set by the waker; cleared ONLY by the owning waiter */
} futex_waiter_t;

static futex_waiter_t s_pool[FUTEX_MAX_WAIT];

static spinlock_t futex_lock = SPINLOCK_INIT;

int futex_wake_addr(uint64_t addr, uint32_t count, uint64_t mm)
{
    irqflags_t fl = spin_lock_irqsave(&futex_lock);
    int woken = 0;
    uint32_t i;
    for (i = 0; i < FUTEX_MAX_WAIT && (uint32_t)woken < count; i++) {
        /* Mark woken + wake, but do NOT free the slot here.  Freeing it (the old
         * behavior) let another FUTEX_WAIT recycle the lowest-free slot before
         * the just-woken waiter rechecked it, so the waiter saw the new
         * occupant's in_use=1, concluded "not woken", and re-blocked forever
         * (slot-recycle lost-wakeup — reproduced via condvar broadcast under
         * smp_sched).  Only the owning waiter clears its slot, so it can never
         * be recycled out from under it.  Skip already-woken slots. */
        if (s_pool[i].in_use && !s_pool[i].woken &&
            s_pool[i].addr == addr && s_pool[i].mm == mm) {
            s_pool[i].woken = 1;
            sched_wake(s_pool[i].task);
            woken++;
        }
    }
    spin_unlock_irqrestore(&futex_lock, fl);
    return woken;
}

/* futex_requeue — wake up to wake_n waiters on `addr`, then move up to
 * requeue_n of the remaining waiters from `addr` to `addr2` (they will be woken
 * by a future FUTEX_WAKE on addr2).  Implements FUTEX_REQUEUE / FUTEX_CMP_REQUEUE.
 *
 * Required by musl's PRIVATE pthread condvars: pthread_cond_signal/broadcast →
 * __private_cond_signal → unlock_requeue() does FUTEX_REQUEUE(barrier, 0, 1,
 * mutex) to hand the next waiter to the mutex futex instead of waking it into a
 * thundering-herd mutex contention.  Without this op the kernel returned ENOSYS,
 * musl's requeue did NOTHING (no wake, no move), and the waiter blocked on its
 * barrier FOREVER — every contended pthread_cond_broadcast/signal hung.  (Latent
 * until something used condvars; reproduced by the condvar-broadcast phase of
 * futexstress under smp_sched.)  Returns woken+requeued (musl only checks
 * != -ENOSYS). */
static int futex_requeue(uint64_t addr, uint64_t addr2,
                         uint32_t wake_n, uint32_t requeue_n, uint64_t mm)
{
    irqflags_t fl = spin_lock_irqsave(&futex_lock);
    int woken = 0, requeued = 0;
    uint32_t i;
    for (i = 0; i < FUTEX_MAX_WAIT && (uint32_t)woken < wake_n; i++) {
        if (s_pool[i].in_use && !s_pool[i].woken &&
            s_pool[i].addr == addr && s_pool[i].mm == mm) {
            s_pool[i].woken = 1;
            sched_wake(s_pool[i].task);
            woken++;
        }
    }
    for (i = 0; i < FUTEX_MAX_WAIT && (uint32_t)requeued < requeue_n; i++) {
        if (s_pool[i].in_use && !s_pool[i].woken &&
            s_pool[i].addr == addr && s_pool[i].mm == mm) {
            s_pool[i].addr = addr2;   /* now waits on addr2; woken via FUTEX_WAKE(addr2) */
            requeued++;
        }
    }
    spin_unlock_irqrestore(&futex_lock, fl);
    return woken + requeued;
}

uint64_t sys_futex(uint64_t addr, uint64_t op, uint64_t val,
                   uint64_t timeout, uint64_t addr2, uint64_t val3)
{
    /* timeout/addr2/val3 are used by the REQUEUE ops below (val2/uaddr2/cmpval);
     * WAIT here ignores timeout (no timed wait yet). */
    uint32_t cmd = (uint32_t)op & ~(uint32_t)FUTEX_PRIVATE_FLAG;

    if (!user_ptr_valid(addr, sizeof(uint32_t)))
        return SYS_ERR(EFAULT);

    /* H1: futex address must be 4-byte aligned (atomic access requirement). */
    if (addr & 0x3)
        return SYS_ERR(EINVAL);

    if (cmd == FUTEX_WAIT) {
        /* Register on the futex queue BEFORE re-checking *uaddr — the
         * lost-wakeup-critical ordering.  The old code checked the value FIRST
         * and registered SECOND: a waker that changed *uaddr and issued
         * FUTEX_WAKE in that window found NO registered waiter (we were not in
         * the pool yet), so it woke nobody — then we registered and blocked
         * FOREVER.  This deadlocked Ladybird's multi-process IPC ~75% of runs
         * (pthread condvars/mutexes: WebContent + ladybird-min threads stuck in
         * FUTEX_WAIT with their wake already gone).  Linux closes this by
         * enqueuing first, then re-loading *uaddr under the bucket lock: either
         * the waker sees our queued waiter (and wakes us) or we observe the new
         * value and don't block. */
        irqflags_t fl = spin_lock_irqsave(&futex_lock);
        uint32_t i;
        futex_waiter_t *w = (futex_waiter_t *)0;
        for (i = 0; i < FUTEX_MAX_WAIT; i++) {
            if (!s_pool[i].in_use) {
                w = &s_pool[i];
                break;
            }
        }
        if (!w) {
            spin_unlock_irqrestore(&futex_lock, fl);
            return SYS_ERR(ENOMEM);
        }
        w->in_use = 1;
        w->woken  = 0;
        w->task = sched_current();
        w->addr = addr;
        w->mm   = current_proc()->pml4_phys;   /* address-space key (see struct) */
        spin_unlock_irqrestore(&futex_lock, fl);

        /* Re-load *uaddr AFTER registering.  If it no longer matches val, a
         * waker raced us (changed the value): do NOT block.  If a concurrent
         * FUTEX_WAKE already freed our slot, that IS a real wake (return 0);
         * else deregister and return EAGAIN.  musl re-checks either way.
         * (user_ptr_valid validated addr above and user pages are eagerly
         * mapped, so this read does not fault under no-fault-fixup uaccess.) */
        {
            uint32_t uval;
            copy_from_user(&uval, (const void *)(uintptr_t)addr,
                           sizeof(uint32_t));
            if (uval != (uint32_t)val) {
                irqflags_t f3 = spin_lock_irqsave(&futex_lock);
                int woke = w->woken;
                w->in_use = 0;
                w->woken  = 0;
                w->task   = (aegis_task_t *)0;
                spin_unlock_irqrestore(&futex_lock, f3);
                return woke ? 0 : SYS_ERR(EAGAIN);
            }
        }

        /* Block until a real FUTEX_WAKE frees our slot. sched_block() may now
         * return early (lost-wakeup guard) or a signal may wake us, so a single
         * block is not enough: re-check whether our slot was actually freed
         * (futex_wake_addr clears in_use+task when it wakes us). On a spurious
         * wake the slot is still ours → re-block. On a pending signal, free our
         * own slot and return so the signal is delivered on the return path
         * (musl re-loads *uaddr and re-waits if still contended) — this also
         * fixes a slot leak the old single-block path had on signal wakeups. */
        for (;;) {
            sched_block();
            irqflags_t f2 = spin_lock_irqsave(&futex_lock);
            /* Detect our wake via OUR OWN woken flag (not !in_use, which is
             * ambiguous after slot recycle).  We are the only clearer of our
             * slot, so it cannot be recycled while we sleep. */
            if (w->woken) {
                w->in_use = 0;
                w->woken  = 0;
                w->task   = (aegis_task_t *)0;
                spin_unlock_irqrestore(&futex_lock, f2);
                return 0;  /* real wake */
            }
            if (signal_check_pending()) {
                w->in_use = 0;
                w->woken  = 0;
                w->task   = (aegis_task_t *)0;
                spin_unlock_irqrestore(&futex_lock, f2);
                return 0;
            }
            spin_unlock_irqrestore(&futex_lock, f2);
            /* spurious wake — slot still registered, block again */
        }
    }

    if (cmd == FUTEX_WAKE)
        return (uint64_t)futex_wake_addr(addr, (uint32_t)val,
                                         current_proc()->pml4_phys);

    /* FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: wake `val` waiters on addr, requeue up
     * to `timeout` (the val2 arg) of the rest to addr2.  Required by musl's
     * private pthread condvars (unlock_requeue).  CMP_REQUEUE first checks
     * *addr == val3.  addr2 must be a valid, aligned user address. */
    if (cmd == FUTEX_REQUEUE || cmd == FUTEX_CMP_REQUEUE) {
        if (!user_ptr_valid(addr2, sizeof(uint32_t)) || (addr2 & 0x3))
            return SYS_ERR(EINVAL);
        if (cmd == FUTEX_CMP_REQUEUE) {
            uint32_t uval;
            copy_from_user(&uval, (const void *)(uintptr_t)addr,
                           sizeof(uint32_t));
            if (uval != (uint32_t)val3)
                return SYS_ERR(EAGAIN);
        }
        return (uint64_t)futex_requeue(addr, addr2, (uint32_t)val,
                                       (uint32_t)timeout,
                                       current_proc()->pml4_phys);
    }

    return SYS_ERR(ENOSYS);
}
