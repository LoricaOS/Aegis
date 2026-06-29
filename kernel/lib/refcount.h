#ifndef AEGIS_REFCOUNT_H
#define AEGIS_REFCOUNT_H
/*
 * refcount.h — the one reference-count primitive for object lifetime.
 *
 * Every fd-backed kernel object (pipe, pty, AF_UNIX/AF_INET socket, memfd,
 * epoll, the fd_table itself) is shared by more than one fd: dup/dup2/fcntl
 * F_DUPFD make a second fd point at the same object, and fork (fd_table_copy)
 * fires every fd's .dup hook so the child's fds reference the same objects as
 * the parent's. The object must therefore live until the LAST referencing fd
 * is closed — not the first. That is exactly a reference count.
 *
 * Before this header, four objects hand-rolled the count correctly
 * (fd_table_t, pipe_t, unix_sock_t, memfd_t, pty_pair_t) and two got it wrong:
 * AF_INET sock_t and epoll_fd_t had a no-op .dup and an unconditional free on
 * .close, so dup-then-close (or fork-then-close) double-freed the object and
 * handed a reused slot to the surviving fd (cross-connection UAF). This
 * primitive gives every object ONE correct, audited implementation so the bug
 * cannot be reintroduced per-object.
 *
 * Design (mirrors kernel/fs/fd_table.c, the reference model — same
 * __atomic_* SEQ_CST choices, same "fetch_sub > 1 means others remain" idiom):
 *
 *   - The count wraps a single uint32_t. Initialised to 1 by the alloc path
 *     (one fd holds the object the moment it is created).
 *   - All operations are SEQ_CST atomics. fd_table.c uses SEQ_CST and these
 *     objects are reached from the same dup/close paths (and, under SMP, from
 *     ISR-context producers that may also hold a reference via a conn/binding
 *     table), so we match it rather than reason about a weaker order per call
 *     site. The cost is irrelevant next to the surrounding spin_lock_irqsave.
 *
 * Why a struct wrapper and not a bare uint32_t: the type makes "this field is
 * a reference count, touch it only through these calls" checkable by eye and
 * by the compiler (you cannot accidentally `mf->refcount++` past it). It is
 * laid out as a plain uint32_t with no padding, so an object can keep its
 * existing in-struct size by swapping `uint32_t refcount` for `refcount_t
 * refcount` (see docs/refcount-migration-spec.md for the per-object field
 * substitution; pipe_t is size-pinned by _Static_assert and its substitution is
 * byte-for-byte since its counts are already uint32_t. pty_pair_t's counts are
 * uint8_t and it is NOT size-pinned, so migrating it grows the struct by a few
 * bytes per pair in static BSS — safe, see the spec).
 *
 * no_std C, K&R, no libc. Header-only (all static inline) so it adds no
 * translation unit and no Makefile SRCS entry — only an include path (see the
 * migration spec's "Build" note; include as "../lib/refcount.h" or add
 * -Ikernel/lib).
 *
 * NOT a lock. The count is atomic, but the object's OWN state (ring indices,
 * peer pointers, open flags) is still protected by the object's spinlock. The
 * canonical pattern is: take the object lock, mutate state, drop the lock,
 * THEN refcount_dec_and_test — and free only if it returns true. The two are
 * orthogonal; this header deliberately does not try to be both.
 */
#include <stdint.h>
#include <stdbool.h>

/*
 * refcount_t — a reference count. The struct exists purely to make the field
 * type-checked; it is exactly one uint32_t with no padding (no other members),
 * so it is a drop-in replacement for a `uint32_t refcount` field.
 */
typedef struct {
    uint32_t v;
} refcount_t;

/*
 * refcount_init — set the count to `n` (callers pass 1: the creating fd).
 *
 * Plain store, no atomic: init runs before the object is published to any
 * other fd or CPU (it is still being filled in by alloc, under the object's
 * pool lock), so there is nothing to race with. Mirrors fd_table_alloc's
 * `t->refcount = 1;` (also a plain store).
 */
static inline void
refcount_init(refcount_t *r, uint32_t n)
{
    r->v = n;
}

/*
 * refcount_inc — add one reference. Called from the .dup hook (fork copy,
 * dup/dup2, fcntl F_DUPFD) and from any path that hands a fresh fd to an
 * already-live object (e.g. memfd's refcount-on-mmap).
 *
 * SEQ_CST fetch_add, matching fd_table_ref. The return value is discarded:
 * after an inc the count is necessarily > 0 (the caller already held a
 * reference, which is what it is duplicating), so there is nothing to test.
 */
static inline void
refcount_inc(refcount_t *r)
{
    __atomic_fetch_add(&r->v, 1, __ATOMIC_SEQ_CST);
}

/*
 * refcount_dec_and_test — drop one reference; return true iff this was the
 * LAST one (the count reached 0) and the caller must now free the object.
 *
 * SEQ_CST fetch_sub returns the value BEFORE the subtraction, exactly like
 * fd_table_unref's `__atomic_fetch_sub(...) > 1`:
 *   - prev > 1  → others still hold references → returns false, do not free.
 *   - prev == 1 → we were the last holder → count is now 0 → returns true.
 *
 * Underflow guard: prev == 0 should be impossible — it means the object was
 * already at zero (already freed, or a double-close). We treat it the same as
 * "last holder" (return true) so the bug surfaces as a single free attempt on
 * a (presumably) already-freed object rather than silently wrapping the count
 * to 0xFFFFFFFF and leaking the object forever / hiding the double-close.
 * Callers that can hit this (sock_vfs_close double-free was the motivating
 * case) are fixed by the migration so prev is never 0 in correct operation;
 * the guard is a last line of defence, not a license to lean on. fd_table.c
 * has no such guard because its single-owner discipline makes prev==0
 * unreachable; we add it because these objects are reached from more paths.
 */
static inline bool
refcount_dec_and_test(refcount_t *r)
{
    uint32_t prev = __atomic_fetch_sub(&r->v, 1, __ATOMIC_SEQ_CST);
    return prev <= 1;
}

/*
 * refcount_read — current value, for asserts/diagnostics only.
 *
 * SEQ_CST load. The result is a snapshot: by the time the caller looks at it
 * another CPU may have inc'd or dec'd, so NEVER branch on this to decide
 * whether to free — only refcount_dec_and_test's return value is a safe
 * free decision (it is atomic with the decrement). Use this for "ASSERT the
 * count is what I expect at teardown" and for stat/debug output.
 */
static inline uint32_t
refcount_read(const refcount_t *r)
{
    return __atomic_load_n(&r->v, __ATOMIC_SEQ_CST);
}

/*
 * refcount_inc_not_zero — add a reference ONLY if the object is still alive
 * (count != 0); return true on success, false if it had already hit zero.
 *
 * This is the lookup-then-ref race guard. It is NEEDED only where an object is
 * found by walking a shared table by index/id WITHOUT holding a reference, and
 * could be concurrently dropped to zero and freed between the lookup and the
 * inc — the classic refcount_inc_not_zero pattern (cf. Linux kref_get_unless_zero).
 *
 * In the CURRENT design NO migrated object needs it: every .dup runs under the
 * object's pool lock (sock_lock/unix_lock/memfd_lock/pair->lock/p->lock) which
 * also serialises the matching free, so the slot cannot transition to free
 * across the inc — a plain refcount_inc under that lock is sufficient and is
 * what the migration uses. It is provided so that if a future caller ever refs
 * an object found by lockless id lookup (e.g. a get-by-id fast path that drops
 * the pool lock before reffing), it reaches for this instead of inventing a
 * racy `if (in_use) refcount_inc`. Document at the call site WHY the plain
 * inc is unsafe there if you use it.
 *
 * Implementation: a SEQ_CST compare-exchange loop. Reads the current value; if
 * 0, the object is dead → return false without touching it; else attempt to
 * publish value+1, retrying on contention.
 */
static inline bool
refcount_inc_not_zero(refcount_t *r)
{
    uint32_t cur = __atomic_load_n(&r->v, __ATOMIC_SEQ_CST);
    for (;;) {
        if (cur == 0)
            return false;  /* already dead — do not resurrect */
        if (__atomic_compare_exchange_n(&r->v, &cur, cur + 1,
                                        /*weak=*/true,
                                        __ATOMIC_SEQ_CST,
                                        __ATOMIC_SEQ_CST))
            return true;
        /* cur was reloaded by the failed cmpxchg; loop and re-test. */
    }
}

#endif /* AEGIS_REFCOUNT_H */
