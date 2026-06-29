/* lockrank.h — debug-only lock-order (rank) enforcement.
 *
 * Aegis documents a canonical lock order (CLAUDE.md "Lock Ordering"), but
 * nothing enforced it in code.  This is a Serenity-style LockRank check
 * (serenity Kernel/Locking/LockRank.h): selected spinlocks are assigned a
 * rank, and each acquire asserts the new rank is strictly INNER (lower) than
 * every rank the current task already holds.  A lock-order inversion therefore
 * crashes at the offending acquire instead of deadlocking later under rare SMP
 * timing.
 *
 * Compiled to NOTHING unless AEGIS_LOCK_DEBUG is defined: the accounting calls
 * in spinlock.h and the per-task held-mask are #ifdef'd out, so shipping builds
 * are byte-identical (smp_sched is default-ON — production codegen must not
 * change).  Build a debug ISO with `make iso EXTRA_CFLAGS=-DAEGIS_LOCK_DEBUG`.
 *
 * Ranks are keyed by the lock's ADDRESS through a small registry, NOT a field
 * on spinlock_t — so spinlock_t (and every struct that embeds it, including the
 * page-exact ones like pipe_t) keeps an identical layout in both builds.  A
 * lock becomes ranked by calling lockrank_register(&lock, RANK) at init; locks
 * that are never registered are unranked and not order-checked.
 *
 * Ranks are single bits, HIGHER value = OUTER lock (acquired first), mirroring
 * the documented order:  sched_lock > vmm_window_lock > pmm_lock > kva_lock.
 * With single-bit ranks the held set is a simple OR-mask and "must acquire
 * strictly inward" is the one integer compare `mask > rank` (Serenity model).
 */
#ifndef AEGIS_LOCKRANK_H
#define AEGIS_LOCKRANK_H

#include <stdint.h>

enum lock_rank {
    LOCK_RANK_NONE  = 0x00,
    LOCK_RANK_KVA   = 0x02,
    LOCK_RANK_PMM   = 0x04,
    LOCK_RANK_VMM   = 0x08,
    LOCK_RANK_SCHED = 0x10,   /* outermost — sched_lock > all others */
};

#ifdef AEGIS_LOCK_DEBUG
/* Tag a lock with a rank (call once at init, before/around first use). */
void lockrank_register(const void *lock, uint16_t rank);
/* Account an acquire/release on the current task's held-rank mask, asserting
 * the canonical order on acquire.  No-ops until lockrank_arm() runs and for
 * unregistered locks. */
void lockrank_acquire(const void *lock);
void lockrank_release(const void *lock);
/* Enable checking.  Called once GS.base is valid (end of smp_percpu_init_bsp);
 * before this, sched_current() may read an uninitialised per-CPU slot. */
void lockrank_arm(void);
#else
static inline void lockrank_register(const void *lock, uint16_t rank)
                                            { (void)lock; (void)rank; }
static inline void lockrank_acquire(const void *lock) { (void)lock; }
static inline void lockrank_release(const void *lock) { (void)lock; }
static inline void lockrank_arm(void) { }
#endif

#endif /* AEGIS_LOCKRANK_H */
