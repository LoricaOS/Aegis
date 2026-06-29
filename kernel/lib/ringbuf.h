#ifndef AEGIS_RINGBUF_H
#define AEGIS_RINGBUF_H
/*
 * ringbuf.h — the one byte-ring primitive for Aegis kernel code.
 *
 * Nine subsystems hand-rolled a byte ring (pipe, the two tcp rings, the two
 * AF_UNIX rings, udp, keyboard, pty, mouse) using THREE different conventions:
 *   - derived count, pow2 mask: free-running head/tail, `(head - tail) &
 *     (SIZE - 1)`, "leave one slot empty" so full != empty (pty, kbd, AF_UNIX —
 *     the clean ones; pty's ring_count/space/push/pull are the prototype this
 *     header promotes verbatim). REQUIRES SIZE be a power of two.
 *   - explicit count, modulo: a separate `count` field + bounded `% SIZE` index
 *     math (pipe — the odd one out). It can hold all SIZE bytes because count
 *     disambiguates full from empty, AND it does NOT need a power-of-two SIZE
 *     because `%` is a true modulo for any size (a mask would not be).
 *   - ring-of-structs: udp's slot ring (NOT a byte ring — out of scope here).
 *
 * The recurring trap is the MASK contract: `idx & (SIZE - 1)` is a real modulo
 * ONLY when SIZE is a power of two. AF_UNIX's original UNIX_BUF_SIZE = 4056
 * made `8 & 4055 == 0` (4055 = 0xFD7, bit 3 clear) so a perfectly normal write
 * silently wrapped to offset 0 and corrupted the ring; it was force-changed to
 * 4096. This has bitten at least twice.
 *
 * THIS HEADER PROVIDES BOTH SHAPES, each with its own safety contract, so a
 * caller never has to hand-roll either — and pipe in particular can be unified
 * WITHOUT changing its size (it stays 4040, a non-power-of-two, because the
 * view shape below uses modulo, not a mask):
 *
 *   1. Bare-index inlines (ringbuf_count/space/push/pull/empty/full over the
 *      caller's own free-running head/tail) — a byte-for-byte promotion of
 *      pty's helpers. POW2-MASK shape. Capacity = size - 1 (one slot left
 *      empty). Use when the object already has free-standing head/tail and a
 *      power-of-two SIZE (kbd, pty; later tcp/AF_UNIX). Assert the contract once
 *      with RINGBUF_ASSERT_POW2 next to the SIZE #define.
 *
 *   2. ringbuf_t view + rb_* (bounded index in [0, size) + explicit count,
 *      modulo arithmetic) — the EXACT shape pipe already uses, generalized.
 *      MODULO shape: works for ANY size (no power-of-two requirement). Capacity
 *      = size (full). Use when the object carries a separate count and does
 *      `% SIZE` math (pipe): the view hides the wrap split and the bookkeeping,
 *      removing the duplicated `%`+count code, with ZERO change to size or
 *      capacity. The `%` is the deliberate non-pow2 path; it is off any hot loop
 *      (one division per bulk copy, not per byte) so its cost is irrelevant.
 *
 * Picking the wrong shape is the only footgun, and it is guarded: the bare
 * inlines are mask-based (assert pow2), the view is modulo-based (any size). A
 * non-pow2 ring MUST use the view, never the bare inlines.
 *
 * no_std C, K&R, no libc. Header-only (all static inline) — no TU, no SRCS
 * entry, only an include path (include as "../lib/ringbuf.h" or add
 * -Ikernel/lib, exactly like refcount.h).
 *
 * Both shapes are non-owning and are NOT a lock: the object's own spinlock
 * still serialises every operation (same rule as refcount.h: orthogonal to
 * locking).
 *
 * NOT for: udp's ring-of-structs (different element type) and the tcp/AF_UNIX
 * load-bearing wrap+linger rings are DEFERRED by the migration spec (their
 * "divergence" interacts with retransmit / linger semantics — migrate later,
 * carefully). See docs/growing-pains-tier1-migration-spec.md §1.
 */
#include <stdint.h>
#include <stdbool.h>

/*
 * RINGBUF_ASSERT_POW2(size) — compile-time guard that `size` is a non-zero
 * power of two, so `& (size - 1)` is a true modulo. Place ONE of these next to
 * each POW2-MASK ring's SIZE #define (where it is a constant expression), e.g.
 *   RINGBUF_ASSERT_POW2(PTY_BUF_SIZE);
 * This is the single thing that makes the mask contract un-foolable; the 4056
 * bug would have failed the build here. (The header cannot _Static_assert the
 * size itself because the bare-index inlines take size as a runtime argument —
 * the assert belongs at the call site where SIZE is constant.) The ringbuf_t
 * VIEW does NOT need this — it is modulo-based and accepts any size.
 */
#define RINGBUF_ASSERT_POW2(size) \
    _Static_assert((size) != 0 && ((size) & ((size) - 1)) == 0, \
                   #size " must be a non-zero power of two (ringbuf mask contract)")

/* ── Shape 1: pow2-mask bare-index inlines (pty/kbd model) ─────────────────
 * The promoted pty helpers, parameterised by `size`. The caller owns head and
 * tail (uint32_t, FREE-RUNNING — they wrap at 2^32, which is why `size` MUST be
 * a power of two: only then does masking a free-running counter give a correct
 * index) and the backing buffer. Capacity is size - 1 (one slot reserved to
 * tell full from empty). The caller passes its SIZE constant so the compiler
 * folds the mask. Assert the pow2 contract once with RINGBUF_ASSERT_POW2. */

/* Number of bytes currently in the ring. */
static inline uint32_t
ringbuf_count(uint32_t head, uint32_t tail, uint32_t size)
{
    return (head - tail) & (size - 1);
}

/* Free space — bytes that can still be pushed. One slot is reserved to
 * distinguish full from empty, so this is (size - 1) - count. */
static inline uint32_t
ringbuf_space(uint32_t head, uint32_t tail, uint32_t size)
{
    return (size - 1) - ringbuf_count(head, tail, size);
}

static inline bool
ringbuf_empty(uint32_t head, uint32_t tail)
{
    return head == tail;
}

static inline bool
ringbuf_full(uint32_t head, uint32_t tail, uint32_t size)
{
    return ringbuf_space(head, tail, size) == 0;
}

/* Push one byte. Caller MUST have checked ringbuf_space() >= 1 (or
 * !ringbuf_full) first — push does not itself guard against overrun, exactly
 * like pty's ring_push. Advances *head. */
static inline void
ringbuf_push(uint8_t *buf, uint32_t *head, uint8_t ch, uint32_t size)
{
    buf[*head] = ch;
    *head = (*head + 1) & (size - 1);
}

/* Pull one byte. Caller MUST have checked !ringbuf_empty() first. Advances
 * *tail and returns the byte. */
static inline uint8_t
ringbuf_pull(const uint8_t *buf, uint32_t *tail, uint32_t size)
{
    uint8_t ch = buf[*tail];
    *tail = (*tail + 1) & (size - 1);
    return ch;
}

/* ── Shape 2: ringbuf_t view (pipe model — explicit count, modulo) ─────────
 * A non-owning view that works for ANY `size` (NOT restricted to powers of two)
 * because it uses bounded indices in [0, size) with `% size` wrap, plus an
 * explicit `count`. This is precisely pipe's existing model — read_pos /
 * write_pos / count — generalized so the wrap arithmetic and the two-segment
 * copy live in one audited place. Capacity is the FULL `size` (count
 * disambiguates full from empty).
 *
 * Migration shape for pipe (and only pipe, for now): at the top of a locked
 * section, rb_init() from the object's pos/count fields, call rb_*, then write
 * head / tail / count back before dropping the lock. pipe_t keeps its exact
 * layout and PIPE_BUF_SIZE stays 4040 — sizeof(pipe_t) == 4096 is unchanged.
 *
 * head = producer index (pipe's write_pos), tail = consumer index (read_pos),
 * count = bytes currently buffered (pipe's count). All three in [0, size) /
 * [0, size]. */
typedef struct {
    uint8_t  *buf;
    uint32_t  size;   /* ANY size >= 1 (need NOT be a power of two) */
    uint32_t  head;   /* producer index in [0, size)  (pipe write_pos) */
    uint32_t  tail;   /* consumer index in [0, size)  (pipe read_pos)  */
    uint32_t  count;  /* bytes buffered, in [0, size]                   */
} ringbuf_t;

static inline void
rb_init(ringbuf_t *rb, uint8_t *buf, uint32_t size,
        uint32_t head, uint32_t tail, uint32_t count)
{
    rb->buf   = buf;
    rb->size  = size;
    rb->head  = head;
    rb->tail  = tail;
    rb->count = count;
}

static inline uint32_t rb_count(const ringbuf_t *rb) { return rb->count; }
static inline uint32_t rb_space(const ringbuf_t *rb) { return rb->size - rb->count; }
static inline bool     rb_empty(const ringbuf_t *rb) { return rb->count == 0; }
static inline bool     rb_full(const ringbuf_t *rb)  { return rb->count == rb->size; }

/*
 * rb_push_n — copy up to `n` bytes from src into the ring, handling wrap via
 * modulo. Returns the number actually pushed (min(n, rb_space)). One audited
 * copy of the two-segment wrap split (the code pipe writes by hand at
 * pipe.c:230-234). src is a kernel buffer — callers stage user data through
 * copy_from_user BEFORE calling; this helper does no uaccess. Advances head and
 * count.
 */
static inline uint32_t
rb_push_n(ringbuf_t *rb, const uint8_t *src, uint32_t n)
{
    uint32_t avail = rb_space(rb);
    if (n > avail) n = avail;
    uint32_t first = rb->size - rb->head;   /* bytes until the buffer end */
    if (first > n) first = n;
    __builtin_memcpy(&rb->buf[rb->head], src, first);
    if (first < n)
        __builtin_memcpy(rb->buf, src + first, n - first);
    rb->head   = (rb->head + n) % rb->size;
    rb->count += n;
    return n;
}

/*
 * rb_pull_n — copy up to `n` bytes out of the ring into dst, handling wrap via
 * modulo. Returns the number actually pulled (min(n, rb_count)). dst is a
 * kernel buffer. Advances tail and count.
 */
static inline uint32_t
rb_pull_n(ringbuf_t *rb, uint8_t *dst, uint32_t n)
{
    if (n > rb->count) n = rb->count;
    uint32_t first = rb->size - rb->tail;
    if (first > n) first = n;
    __builtin_memcpy(dst, &rb->buf[rb->tail], first);
    if (first < n)
        __builtin_memcpy(dst + first, rb->buf, n - first);
    rb->tail   = (rb->tail + n) % rb->size;
    rb->count -= n;
    return n;
}

#endif /* AEGIS_RINGBUF_H */
