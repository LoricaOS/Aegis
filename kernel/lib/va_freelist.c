/*
 * va_freelist.c — coalescing best-fit address-range freelist (see
 * va_freelist.h for the design rationale and the silent-leak fix).
 *
 * Unifies the two hand-rolled copies (sys_memory.c mmap freelist, kva.c KVA
 * freelist). Unit-agnostic: {base, len} are plain uint64_t, never multiplied by
 * a page size — the caller chooses bytes or pages. No locking here; the caller
 * holds its own lock across each call.
 */
#include "va_freelist.h"
#include "printk.h"

/*
 * Coalesce the entry at index `i` with any other single entry it is now
 * adjacent to (predecessor OR successor). Called after growing arr[i].len or
 * lowering arr[i].base. Removes the absorbed neighbour by swapping the tail
 * entry into its slot (order-independent array). At most one neighbour can be
 * adjacent on each side; we merge whichever we find and return — a second pass
 * is unnecessary because the original ranges were already maximally coalesced
 * (invariant: no two live entries are adjacent), so a freshly grown entry can
 * touch at most one neighbour on the side it grew toward.
 */
static void
coalesce_neighbour(va_freelist_t *fl, uint32_t i)
{
    uint64_t end = fl->arr[i].base + fl->arr[i].len;
    for (uint32_t j = 0; j < fl->count; j++) {
        if (j == i)
            continue;
        /* arr[i] directly precedes arr[j] */
        if (end == fl->arr[j].base) {
            fl->arr[i].len += fl->arr[j].len;
            fl->arr[j] = fl->arr[--fl->count];
            return;
        }
        /* arr[j] directly precedes arr[i] */
        if (fl->arr[j].base + fl->arr[j].len == fl->arr[i].base) {
            fl->arr[i].base  = fl->arr[j].base;
            fl->arr[i].len  += fl->arr[j].len;
            fl->arr[j] = fl->arr[--fl->count];
            return;
        }
    }
}

bool
va_freelist_insert(va_freelist_t *fl, uint64_t base, uint64_t len)
{
    if (len == 0)
        return true;   /* nothing to track; not an error */

    /* Coalesce with an adjacent existing range if one exists. */
    for (uint32_t i = 0; i < fl->count; i++) {
        /* new range directly follows arr[i] */
        if (fl->arr[i].base + fl->arr[i].len == base) {
            fl->arr[i].len += len;
            coalesce_neighbour(fl, i);
            return true;
        }
        /* new range directly precedes arr[i] */
        if (base + len == fl->arr[i].base) {
            fl->arr[i].base  = base;
            fl->arr[i].len  += len;
            coalesce_neighbour(fl, i);
            return true;
        }
    }

    /* No coalescing possible — need a fresh slot. */
    if (fl->count < fl->cap) {
        fl->arr[fl->count].base = base;
        fl->arr[fl->count].len  = len;
        fl->count++;
        return true;
    }

    /* Overflow: the range is dropped (VA leaked). Previously SILENT in both
     * copies — now loud. The caller may also WARN with its own unit context. */
    printk("[VA] WARN: freelist full (%u entries), leaked range base=0x%lx len=0x%lx\n",
           fl->cap, (unsigned long)base, (unsigned long)len);
    return false;
}

bool
va_freelist_alloc(va_freelist_t *fl, uint64_t want, uint64_t *out_base)
{
    if (want == 0)
        return false;

    uint32_t best = (uint32_t)-1;
    uint64_t best_len = (uint64_t)-1;
    for (uint32_t i = 0; i < fl->count; i++) {
        if (fl->arr[i].len >= want && fl->arr[i].len < best_len) {
            best = i;
            best_len = fl->arr[i].len;
            if (best_len == want)
                break;   /* exact fit — cannot do better */
        }
    }
    if (best == (uint32_t)-1)
        return false;

    *out_base = fl->arr[best].base;
    if (fl->arr[best].len == want) {
        fl->arr[best] = fl->arr[--fl->count];   /* exact fit — remove */
    } else {
        fl->arr[best].base += want;             /* carve off the front */
        fl->arr[best].len  -= want;
    }
    return true;
}
