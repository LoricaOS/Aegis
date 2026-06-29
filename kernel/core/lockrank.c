/* lockrank.c — debug-only lock-order enforcement. See lockrank.h.
 *
 * The whole translation unit is empty unless AEGIS_LOCK_DEBUG is defined, so
 * release builds link an object with no symbols and zero codegen change. */
#ifdef AEGIS_LOCK_DEBUG

#include "lockrank.h"
#include "sched.h"     /* sched_current, aegis_task_t::lock_rank_mask */
#include "smp.h"       /* percpu_self (cpu id for the diag line) */
#include "printk.h"    /* printk, KASSERT */

/* Rank registry — a handful of named global locks (sched/vmm/pmm/kva).  Tiny
 * and debug-only, so a linear scan on every acquire is fine.  Keyed by lock
 * address so spinlock_t never needs a rank field. */
#define LOCKRANK_MAX 16
static struct { const void *lock; uint16_t rank; } s_reg[LOCKRANK_MAX];
static uint32_t s_reg_n = 0;
static volatile int s_armed = 0;

void
lockrank_register(const void *lock, uint16_t rank)
{
    if (s_reg_n >= LOCKRANK_MAX) {
        printk("[LOCKRANK] FAIL: registry full (raise LOCKRANK_MAX)\n");
        return;
    }
    s_reg[s_reg_n].lock = lock;
    s_reg[s_reg_n].rank = rank;
    s_reg_n++;
}

static uint16_t
rank_of(const void *lock)
{
    for (uint32_t i = 0; i < s_reg_n; i++)
        if (s_reg[i].lock == lock)
            return s_reg[i].rank;
    return LOCK_RANK_NONE;
}

void
lockrank_arm(void)
{
    s_armed = 1;
}

void
lockrank_acquire(const void *lock)
{
    if (!s_armed)
        return;
    uint16_t rank = rank_of(lock);
    if (rank == LOCK_RANK_NONE)
        return;
    aegis_task_t *t = sched_current();
    if (!t)                       /* no current task yet — skip */
        return;

    /* Must acquire strictly inward: every held ranked lock must be OUTER
     * (higher value) than this one.  With single-bit ranks, mask > rank holds
     * iff the new rank's bit is below the highest held bit (Serenity model). */
    if (t->lock_rank_mask != 0 && !(t->lock_rank_mask > rank)) {
        printk("[LOCKRANK] FAIL: acquire rank 0x%x while holding mask 0x%x on cpu%u\n",
               (unsigned)rank, (unsigned)t->lock_rank_mask,
               (unsigned)percpu_self()->cpu_id);
        KASSERT(0);
    }
    t->lock_rank_mask |= rank;
}

void
lockrank_release(const void *lock)
{
    if (!s_armed)
        return;
    uint16_t rank = rank_of(lock);
    if (rank == LOCK_RANK_NONE)
        return;
    aegis_task_t *t = sched_current();
    if (!t)
        return;
    t->lock_rank_mask &= ~(uint32_t)rank;
}

#endif /* AEGIS_LOCK_DEBUG */
