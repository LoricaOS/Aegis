#ifndef AEGIS_VA_FREELIST_H
#define AEGIS_VA_FREELIST_H
/*
 * va_freelist.{h,c} — the one coalescing best-fit address-range freelist.
 *
 * Two near-identical copies of a {base,len} array allocator exist:
 *   - mmap VA freelist: sys_memory.c mmap_free_insert/mmap_free_alloc, backing
 *     array proc->mmap_free[MMAP_FREE_MAX=64], unit = bytes.
 *   - KVA freelist: kva.c freelist_insert/freelist_alloc, backing array
 *     s_free[KVA_FREE_MAX=128], unit = pages (va + npages*4096).
 * Both do best-fit alloc + coalesce-on-insert, and the coalesce logic is even
 * duplicated WITHIN each insert (merge-with-predecessor then merge-with-
 * successor). This primitive is that allocator, once.
 *
 * It is UNIT-AGNOSTIC: it stores {base, len} as plain uint64_t and never
 * multiplies by a page size. The KVA caller passes pages as len (its existing
 * convention); the mmap caller passes bytes. Coalescing is `a.base + a.len ==
 * b.base`, which is correct in either unit. Keeping the page<->byte choice in
 * the caller means neither migration has to change its math.
 *
 * The caller OWNS the backing array, its capacity, the live count, AND the
 * lock. This header does no allocation and takes no lock — exactly like
 * refcount.h/ringbuf.h, locking is orthogonal. The mmap freelist is per-process
 * (proc->mmap_free_lock); the KVA freelist is global (kva_lock). The caller
 * holds its lock across the va_freelist_* call. A small `va_freelist_t` view
 * bundles {arr, cap, count} so the two long functions take one struct instead
 * of three loose pointers; `count` is read AND written through the view.
 *
 * THE LEAK THIS FIXES: both original *_insert SILENTLY DROP the range when the
 * array is full (`if (count < MAX) { ... }` with no else) — an unbounded,
 * un-logged VA leak. va_freelist_insert returns false on overflow so the caller
 * can WARN (and the .c emits a throttled printk itself). The coalesce-first
 * design means a full-but-coalescable insert still succeeds, so overflow is
 * rare in practice — but it is now visible instead of silent.
 *
 * Split header/impl (not header-only) because the bodies are non-trivial and
 * two TUs call them — one out-of-line copy is smaller than inlining the loops
 * into every caller, and matches kva.c/sys_memory.c being .c already. Add
 * kernel/lib/va_freelist.c to the kernel SRCS (see the spec's Build note).
 */
#include <stdint.h>
#include <stdbool.h>

/* One free range. `len` is in the caller's chosen unit (bytes for mmap, pages
 * for KVA) — va_freelist never interprets it beyond add/compare. */
typedef struct {
    uint64_t base;
    uint64_t len;
} va_region_t;

/* Non-owning view over a caller-supplied array. `count` is live and mutated by
 * insert/alloc; the caller stores it back (or shares the same field — e.g. a
 * pointer to proc->mmap_free_count). */
typedef struct {
    va_region_t *arr;    /* caller's backing array (>= cap entries)      */
    uint32_t     cap;    /* capacity (MMAP_FREE_MAX / KVA_FREE_MAX)       */
    uint32_t     count;  /* current number of live entries               */
} va_freelist_t;

/*
 * va_freelist_insert — add [base, base+len) to the freelist, coalescing with an
 * adjacent existing range on either side (and merging the two neighbours if the
 * inserted range bridges them). Returns true if the range is now represented in
 * the freelist; false ONLY if it could not coalesce AND the array was full (the
 * range is dropped — caller MUST log this; the .c also WARNs). Caller holds its
 * lock. `fl->count` is updated in place.
 */
bool va_freelist_insert(va_freelist_t *fl, uint64_t base, uint64_t len);

/*
 * va_freelist_alloc — best-fit: find the smallest range with len >= want,
 * carve `want` off its front, and return the carved base in *out_base. Returns
 * true on success (a range was found and *out_base set), false if no range is
 * large enough. On an exact fit the entry is removed; otherwise it is shrunk
 * from the front. Caller holds its lock. `fl->count` is updated in place.
 */
bool va_freelist_alloc(va_freelist_t *fl, uint64_t want, uint64_t *out_base);

#endif /* AEGIS_VA_FREELIST_H */
