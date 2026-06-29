/* locked.h — bind a piece of data to the spinlock that guards it (opt-in).
 *
 * A C analogue of Serenity's SpinlockProtected<T> (serenity
 * Kernel/Locking/SpinlockProtected.h): instead of a bare lock + separate data
 * and a "caller must hold X" comment, the data lives INSIDE a struct with its
 * lock, and the only ergonomic way to reach it is through WITH_LOCKED, which
 * takes the lock for the duration of a block.  This turns "forgot the lock"
 * from a review-time catch into something the structure makes awkward to get
 * wrong.  Purely additive: existing locks are untouched; adopt per-struct.
 *
 * Pairs with the debug LockRank checker (lockrank.h): give a LOCKED struct a
 * ranked lock with LOCKED_INIT_RANKED and its accesses are order-checked too.
 *
 *   DEFINE_LOCKED(hostname_t, struct { char name[65]; uint32_t len; });
 *   static hostname_t g_host = LOCKED_INIT({ "aegis", 5 });
 *   ...
 *   WITH_LOCKED(&g_host, h) {        // h = pointer to the guarded data
 *       h->len = n;
 *   }                               // lock released here (and on `break`)
 *
 * CONTRACT — read this: WITH_LOCKED holds a spinlock across the block, so the
 * block must NOT `return`, `goto`, or otherwise jump out of it (that would skip
 * the unlock and leave the lock held — a deadlock).  `break` is fine and
 * releases the lock.  For paths that need an early return, take the lock
 * explicitly with spin_lock_irqsave on &lp->lock instead.  Keep blocks short.
 */
#ifndef AEGIS_LOCKED_H
#define AEGIS_LOCKED_H

#include "spinlock.h"

/* Declare a type `name` = data of type T guarded by an embedded spinlock. */
#define DEFINE_LOCKED(name, T) \
    typedef struct { spinlock_t lock; T data; } name

/* Static initialisers.  Variadic so a braced initialiser for the guarded T
 * (which contains commas) is passed as a single argument:
 *   LOCKED_INIT({ .name = "aegis", .len = 5 }). */
#define LOCKED_INIT(...)              { SPINLOCK_INIT, __VA_ARGS__ }
#define LOCKED_INIT_RANKED(rank, ...) { SPINLOCK_INIT_RANKED(rank), __VA_ARGS__ }

/* Run the following block with *lp's lock held (IRQ-safe).  `v` is a pointer to
 * the guarded data, scoped to and valid only inside the block.  See CONTRACT. */
#define WITH_LOCKED(lp, v)                                                     \
    for (struct { irqflags_t fl; int go; }                                     \
             _wl = { spin_lock_irqsave(&(lp)->lock), 1 };                      \
         _wl.go;                                                               \
         spin_unlock_irqrestore(&(lp)->lock, _wl.fl), _wl.go = 0)              \
        for (typeof(&(lp)->data) v = &(lp)->data; _wl.go; _wl.go = 0)

#endif /* AEGIS_LOCKED_H */
