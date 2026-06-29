/* kernel/mm/vma.c — per-process Virtual Memory Area tracking */

#include "vma.h"
#include "proc.h"
#include "kva.h"
#include "spinlock.h"
#include "../limits.h"
#include "../lib/refcount.h"

#define PAGE_SIZE AEGIS_PAGE_SIZE

/* The VMA table is VMA_TABLE_PAGES contiguous kva pages. One page (170 entries)
 * was too small for processes that dynamically link MANY shared objects: the
 * browser frontend loads ~137 .so (~350 VMAs after per-segment splits), which
 * overflowed the table — mmap then rolled back and the dynamic linker SIGSEGV'd.
 * 8 pages ≈ 1360 entries. The shared refcount (vma_rc) lives in the tail of the
 * block; VMA_CAPACITY reserves room for it. Cost: 32 KB per address space. */
#define VMA_TABLE_PAGES 8

/* The shared table HEADER lives in the tail of the table page, AFTER the
 * entries. It holds BOTH the refcount AND the live entry count, so that all
 * CLONE_VM threads — which point at the SAME vma_table page — observe ONE
 * authoritative count. (A per-process vma_count field was the bug: the table
 * pointer was shared but the count was copied, so a sibling thread's stale
 * count truncated vma_find's binary-search range and it could not see VMAs
 * inserted by another thread after the clone — fatal once mmap became lazy and
 * the demand-fault path depends on vma_find.) */
/* `lock` guards the SHARED vma_table (entries + count) against concurrent
 * mutation by CLONE_VM/CLONE_THREAD siblings. They share this table + pml4 but
 * each got a FRESH per-TCB proc->mmap_free_lock (sys_clone re-inits it), so that
 * lock can NOT serialize them — concurrent mmap/munmap syscalls from siblings
 * would otherwise race vma_insert/remove's array shifts (out-of-bounds / tearing)
 * and vma_find's binary search (tear-read). Living in the shared header, `lock`
 * is automatically the SAME lock for every thread of the address space, like the
 * count. It is a SHORT LEAF lock: taken only INSIDE vma_find/insert/remove/
 * update_prot for the array op itself, and those touch only the table (no vmm/pmm
 * calls), so it nests under nothing and is never held across the slow mmap
 * map/read path (the "held across" recursion that deadlocked an earlier attempt). */
typedef struct { refcount_t rc; uint32_t count; spinlock_t lock; } vma_hdr_t;
#define VMA_CAPACITY (((VMA_TABLE_PAGES * PAGE_SIZE) - sizeof(vma_hdr_t)) / sizeof(vma_entry_t))
#define VMA_HDR_OFFSET (VMA_CAPACITY * sizeof(vma_entry_t))
_Static_assert(VMA_HDR_OFFSET + sizeof(vma_hdr_t) <= (VMA_TABLE_PAGES * PAGE_SIZE),
               "vma_table header overruns the table page");

static inline vma_hdr_t *vma_hdr(struct aegis_process *proc) {
    return (vma_hdr_t *)((char *)proc->vma_table + VMA_HDR_OFFSET);
}
static inline refcount_t *vma_rc(struct aegis_process *proc) {
    return &vma_hdr(proc)->rc;
}
/* shared authoritative entry count */
static inline uint32_t *vcnt(struct aegis_process *proc) {
    return &vma_hdr(proc)->count;
}
static inline spinlock_t *vlock(struct aegis_process *proc) {
    return &vma_hdr(proc)->lock;
}

/* Public read-only accessor for code outside vma.c (procfs, brk). */
uint32_t vma_count_get(struct aegis_process *proc) {
    return (proc && proc->vma_table) ? *vcnt(proc) : 0;
}

/* ── helpers ─────────────────────────────────────────────────────────── */

static void vma_shift_right(vma_entry_t *table, uint32_t count, uint32_t idx) {
    uint32_t i = count;
    while (i > idx) {
        table[i] = table[i - 1];
        i--;
    }
}

static void vma_shift_left(vma_entry_t *table, uint32_t count, uint32_t idx) {
    uint32_t i = idx;
    while (i + 1 < count) {
        table[i] = table[i + 1];
        i++;
    }
}

static int vma_can_merge(const vma_entry_t *a, const vma_entry_t *b) {
    /* VMA_FILE entries carry per-entry file backing (ino + offset), so two of
     * them can never be represented by one merged entry — never merge them. */
    if (a->type == VMA_FILE || b->type == VMA_FILE)
        return 0;
    return a->prot == b->prot &&
           a->type == b->type &&
           (a->base + a->len) == b->base;
}

/* ── public API ──────────────────────────────────────────────────────── */

/* vma_find — return the VMA entry containing va, or NULL. The table is kept
 * sorted by base with non-overlapping entries, so binary search is valid.
 *
 * Self-locks the shared table lock: a sibling thread mutating the table
 * concurrently (vma_insert/remove shifting entries) would otherwise let this
 * binary search tear-read a half-moved entry and return garbage / walk OOB.
 * Note: the returned pointer is into the shared table; callers must consume it
 * before any concurrent vma_remove could shift it. All current callers read the
 * fields immediately under the same IF=0 syscall/fault context, before yielding,
 * so the pointer stays valid for that use. */
vma_entry_t *vma_find(struct aegis_process *proc, uint64_t va) {
    if (!proc || !proc->vma_table) return (vma_entry_t *)0;
    spinlock_t *lk = vlock(proc);
    irqflags_t fl = spin_lock_irqsave(lk);
    vma_entry_t *t = proc->vma_table;
    vma_entry_t *result = (vma_entry_t *)0;
    int lo = 0, hi = (int)*vcnt(proc) - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (va < t[mid].base) hi = mid - 1;
        else if (va >= t[mid].base + t[mid].len) lo = mid + 1;
        else { result = &t[mid]; break; }
    }
    spin_unlock_irqrestore(lk, fl);
    return result;
}

void vma_init(struct aegis_process *proc) {
    vma_entry_t *table = (vma_entry_t *)kva_alloc_pages(VMA_TABLE_PAGES);
    proc->vma_table    = table;
    proc->vma_capacity = (uint32_t)VMA_CAPACITY;
    refcount_init(vma_rc(proc), 1);
    *vcnt(proc) = 0;
    { spinlock_t init = SPINLOCK_INIT; vma_hdr(proc)->lock = init; }
}

/* vma_insert_nolock — caller holds vlock. Returns 0 on success (inserted/merged),
 * -1 on NULL table / len==0 / table full, -2 if [base,base+len) STRICTLY overlaps
 * an existing entry (a concurrent reserver already took this range — the loser
 * backs off and retries). Adjacency (boundary ==) is allowed (it merges). */
static int vma_insert_nolock(struct aegis_process *proc,
               uint64_t base, uint64_t len, uint32_t prot, uint8_t type) {
    vma_entry_t *table = proc->vma_table;
    uint32_t count = *vcnt(proc);

    if (!table || len == 0)
        return -1;

    /* Find insertion point: first entry with base > our base */
    uint32_t idx = 0;
    while (idx < count && table[idx].base < base)
        idx++;

    /* Reject a STRICT overlap with the predecessor or successor entry. This is
     * the atomicity guarantee for concurrent mmap reservation: two sibling
     * threads that pre-scanned the same clear range both call here, but the lock
     * serializes them — the first inserts, the second sees its range now occupied
     * and gets -2, then re-selects. `>` (not `>=`) so an adjacent same-prot/type
     * range still reaches the merge paths below. An exact-same-base duplicate is
     * caught by the successor test (base+len > table[idx].base, len>0). */
    if (idx > 0 && (table[idx - 1].base + table[idx - 1].len) > base)
        return -2;
    if (idx < count && (base + len) > table[idx].base)
        return -2;

    /* Try merging with the previous entry (never for VMA_FILE — per-entry
     * file backing can't be represented by one merged entry). */
    if (type != VMA_FILE && idx > 0 && table[idx - 1].prot == prot &&
        table[idx - 1].type == type &&
        (table[idx - 1].base + table[idx - 1].len) == base) {
        /* Extend previous entry */
        table[idx - 1].len += len;

        /* Check if we can also merge with the next entry */
        if (idx < count && vma_can_merge(&table[idx - 1], &table[idx])) {
            table[idx - 1].len += table[idx].len;
            vma_shift_left(table, count, idx);
            *vcnt(proc) = count - 1;
        }
        return 0;
    }

    /* Try merging with the next entry (never for VMA_FILE). */
    if (type != VMA_FILE && idx < count && table[idx].prot == prot &&
        table[idx].type == type &&
        (base + len) == table[idx].base) {
        table[idx].base = base;
        table[idx].len += len;
        return 0;
    }

    /* No merge possible — insert a new entry. If the table is full we MUST
     * signal failure rather than drop: the caller has already wired up page
     * tables for [base, base+len), so an untracked region would corrupt
     * /proc/maps and leave munmap/teardown unable to find (and free) it.
     * The caller is responsible for rolling back the mapping on -1. */
    if (count >= proc->vma_capacity)
        return -1;  /* table full — caller must roll back the mapping */

    vma_shift_right(table, count, idx);
    table[idx].base = base;
    table[idx].len  = len;
    table[idx].prot = prot;
    table[idx].type = type;
    table[idx].file_off  = 0;
    table[idx].file_size = 0;
    table[idx].file_ino  = 0;
    table[idx].file_gen  = 0;
    __builtin_memset(table[idx]._pad, 0, sizeof(table[idx]._pad));
    *vcnt(proc) = count + 1;
    return 0;
}

/* vma_set_file_backing — see vma.h. Find the entry at base (just reserved by
 * vma_insert as VMA_FILE; merges are disabled for that type so it is unique)
 * and record its ext2 file backing. */
void vma_set_file_backing(struct aegis_process *proc, uint64_t base,
                          uint32_t ino, uint64_t file_off, uint64_t file_size,
                          uint32_t file_gen) {
    if (!proc || !proc->vma_table) return;
    spinlock_t *lk = vlock(proc);
    irqflags_t fl = spin_lock_irqsave(lk);
    vma_entry_t *t = proc->vma_table;
    uint32_t count = *vcnt(proc);
    for (uint32_t i = 0; i < count; i++) {
        if (t[i].base == base) {
            t[i].file_ino  = ino;
            t[i].file_off  = file_off;
            t[i].file_size = file_size;
            t[i].file_gen  = file_gen;
            break;
        }
    }
    spin_unlock_irqrestore(lk, fl);
}

int vma_insert(struct aegis_process *proc,
               uint64_t base, uint64_t len, uint32_t prot, uint8_t type) {
    if (!proc || !proc->vma_table) return -1;
    spinlock_t *lk = vlock(proc);
    irqflags_t fl = spin_lock_irqsave(lk);
    int r = vma_insert_nolock(proc, base, len, prot, type);
    spin_unlock_irqrestore(lk, fl);
    return r;
}

static int vma_remove_nolock(struct aegis_process *proc, uint64_t base, uint64_t len) {
    vma_entry_t *table = proc->vma_table;
    uint32_t count = *vcnt(proc);
    uint64_t end = base + len;

    if (!table || len == 0)
        return 0;  /* nothing to remove — vacuously successful */

    /* PASS 1 (read-only): determine whether the operation needs a free table
     * slot it cannot get, and bail out BEFORE mutating anything. Only the
     * "range entirely within one entry" case splits the entry in two, needing
     * one new slot. At most one entry can be split per call: a split entry
     * satisfies e->base < base && e_end > end, so it spans the whole removal
     * range — no other entry can overlap that range, hence no full-removal can
     * coexist with (or precede) the split. So the conservative check
     * (count == capacity at a split) is exact: it rejects only the genuinely
     * impossible case, and rejecting here leaves the table untouched, giving
     * the caller true all-or-nothing semantics. */
    {
        uint32_t i;
        for (i = 0; i < count; i++) {
            vma_entry_t *e = &table[i];
            uint64_t e_end = e->base + e->len;
            if (e->base < base && e_end > end) {       /* contained split */
                if (count >= proc->vma_capacity)
                    return -1;                          /* table full — no mutation */
                break;  /* at most one split per call; no need to scan further */
            }
        }
    }

    uint32_t i = 0;
    while (i < count) {
        vma_entry_t *e = &table[i];
        uint64_t e_end = e->base + e->len;

        /* No overlap */
        if (e_end <= base || e->base >= end) {
            i++;
            continue;
        }

        /* Fully contained — remove entire entry */
        if (e->base >= base && e_end <= end) {
            vma_shift_left(table, count, i);
            count--;
            continue;  /* don't increment i — next entry shifted into slot */
        }

        /* Remove range cuts the beginning of this entry */
        if (e->base >= base && e->base < end) {
            uint64_t trim = end - e->base;
            e->base += trim;
            e->len  -= trim;
            if (e->type == VMA_FILE) e->file_off += trim;  /* track file pos */
            i++;
            continue;
        }

        /* Remove range cuts the end of this entry */
        if (e_end > base && e_end <= end) {
            e->len = base - e->base;
            i++;
            continue;
        }

        /* Remove range is entirely within this entry — split */
        if (e->base < base && e_end > end) {
            /* PASS 1 guaranteed room for this single split. The check below is
             * defensive: if it ever fired it would mean the table changed
             * under us — propagate failure rather than silently corrupt. */
            if (count >= proc->vma_capacity)
                return -1;
            /* Create right fragment. Capture the parent's file backing BEFORE
             * truncating the left fragment; the right fragment starts at `end`
             * so its file offset advances by (end - e->base). */
            uint8_t  ftype = e->type;
            uint32_t fino  = e->file_ino;
            uint32_t fgen  = e->file_gen;
            uint64_t fsize = e->file_size;
            uint64_t foff  = e->file_off;
            uint64_t obase = e->base;
            vma_shift_right(table, count, i + 1);
            count++;
            table[i + 1].base = end;
            table[i + 1].len  = e_end - end;
            table[i + 1].prot = e->prot;
            table[i + 1].type = ftype;
            table[i + 1].file_ino  = fino;
            table[i + 1].file_gen  = fgen;
            table[i + 1].file_size = fsize;
            table[i + 1].file_off  = (ftype == VMA_FILE) ? foff + (end - obase) : 0;
            __builtin_memset(table[i + 1]._pad, 0, sizeof(table[i + 1]._pad));
            /* Truncate left fragment (base unchanged → file_off unchanged) */
            e->len = base - e->base;
            i += 2;  /* skip both fragments */
            continue;
        }

        i++;
    }

    *vcnt(proc) = count;
    return 0;
}

int vma_remove(struct aegis_process *proc, uint64_t base, uint64_t len) {
    if (!proc || !proc->vma_table) return 0;
    spinlock_t *lk = vlock(proc);
    irqflags_t fl = spin_lock_irqsave(lk);
    int r = vma_remove_nolock(proc, base, len);
    spin_unlock_irqrestore(lk, fl);
    return r;
}

static int vma_update_prot_nolock(struct aegis_process *proc,
                    uint64_t base, uint64_t len, uint32_t new_prot) {
    vma_entry_t *table = proc->vma_table;
    uint32_t count = *vcnt(proc);
    uint64_t end = base + len;

    if (!table || len == 0)
        return 0;  /* nothing to update — vacuously successful */

    /* PASS 1 (read-only): sum the new slots this operation will need and bail
     * out BEFORE mutating anything if the table cannot hold them. This gives
     * the caller true all-or-nothing semantics (mprotect must not change page
     * protections and then fail to record the split). vma_update_prot never
     * removes entries, so no slot is ever freed mid-call — the running total
     * never dips, making this conservative sum exact. The classification here
     * mirrors PASS 2 exactly; keep them in sync.
     *   start-partial split  → +1
     *   end-partial   split  → +1
     *   middle three-way     → +2 */
    {
        uint32_t extra = 0;
        uint32_t i;
        for (i = 0; i < count; i++) {
            vma_entry_t *e = &table[i];
            uint64_t e_end = e->base + e->len;
            if (e_end <= base || e->base >= end)
                continue;                              /* no overlap */
            if (e->prot == new_prot)
                continue;                              /* unchanged — no split */
            if (e->base >= base && e_end <= end)
                continue;                              /* fully contained — in place */
            if (e->base >= base && e->base < end && e_end > end)
                extra += 1;                            /* start-partial */
            else if (e->base < base && e_end > base && e_end <= end)
                extra += 1;                            /* end-partial */
            else if (e->base < base && e_end > end)
                extra += 2;                            /* middle three-way */
        }
        if ((uint64_t)count + (uint64_t)extra > (uint64_t)proc->vma_capacity)
            return -1;                                 /* table full — no mutation */
    }

    uint32_t i = 0;
    while (i < count) {
        vma_entry_t *e = &table[i];
        uint64_t e_end = e->base + e->len;

        /* No overlap */
        if (e_end <= base || e->base >= end) {
            i++;
            continue;
        }

        /* Already has the target permissions */
        if (e->prot == new_prot) {
            i++;
            continue;
        }

        /* Fully contained */
        if (e->base >= base && e_end <= end) {
            e->prot = new_prot;
            i++;
            continue;
        }

        /* Partial overlap at the start of this entry.
         * PASS 1 reserved a slot for this split; the capacity check below is
         * defensive (propagate, never silently skip — silent-skip here would
         * desync the table from the page protections just changed). */
        if (e->base >= base && e->base < end && e_end > end) {
            if (count >= proc->vma_capacity) {
                return -1;
            }
            /* Split: [e->base..end) gets new_prot, [end..e_end) keeps old */
            {
            uint8_t  ftype = e->type;
            uint32_t fino  = e->file_ino;
            uint32_t fgen  = e->file_gen;
            uint64_t fsize = e->file_size, foff = e->file_off, obase = e->base;
            vma_shift_right(table, count, i + 1);
            count++;
            table[i + 1].base = end;
            table[i + 1].len  = e_end - end;
            table[i + 1].prot = e->prot;
            table[i + 1].type = ftype;
            table[i + 1].file_ino  = fino;
            table[i + 1].file_gen  = fgen;
            table[i + 1].file_size = fsize;
            table[i + 1].file_off  = (ftype == VMA_FILE) ? foff + (end - obase) : 0;
            __builtin_memset(table[i + 1]._pad, 0, sizeof(table[i + 1]._pad));
            e->len  = end - e->base;   /* base unchanged → file_off unchanged */
            e->prot = new_prot;
            }
            i += 2;
            continue;
        }

        /* Partial overlap at the end of this entry.
         * PASS 1 reserved a slot for this split; check is defensive. */
        if (e->base < base && e_end > base && e_end <= end) {
            if (count >= proc->vma_capacity) {
                return -1;
            }
            /* Split: [e->base..base) keeps old, [base..e_end) gets new_prot */
            {
            uint8_t  ftype = e->type;
            uint32_t fino  = e->file_ino;
            uint32_t fgen  = e->file_gen;
            uint64_t fsize = e->file_size, foff = e->file_off, obase = e->base;
            vma_shift_right(table, count, i + 1);
            count++;
            table[i + 1].base = base;
            table[i + 1].len  = e_end - base;
            table[i + 1].prot = new_prot;
            table[i + 1].type = ftype;
            table[i + 1].file_ino  = fino;
            table[i + 1].file_gen  = fgen;
            table[i + 1].file_size = fsize;
            table[i + 1].file_off  = (ftype == VMA_FILE) ? foff + (base - obase) : 0;
            __builtin_memset(table[i + 1]._pad, 0, sizeof(table[i + 1]._pad));
            e->len = base - e->base;   /* base unchanged → file_off unchanged */
            }
            i += 2;
            continue;
        }

        /* Range is entirely within this entry — three-way split.
         * PASS 1 reserved two slots for this split; check is defensive. */
        if (e->base < base && e_end > end) {
            if (count + 2 > proc->vma_capacity) {
                return -1;
            }
            uint32_t old_prot = e->prot;
            uint8_t  old_type = e->type;
            uint32_t fino  = e->file_ino;
            uint32_t fgen  = e->file_gen;
            uint64_t fsize = e->file_size, foff = e->file_off, obase = e->base;
            /* Insert two new entries after this one */
            vma_shift_right(table, count, i + 1);
            count++;
            vma_shift_right(table, count, i + 2);
            count++;
            /* Middle fragment: [base..end) with new_prot */
            table[i + 1].base = base;
            table[i + 1].len  = len;
            table[i + 1].prot = new_prot;
            table[i + 1].type = old_type;
            table[i + 1].file_ino  = fino;
            table[i + 1].file_gen  = fgen;
            table[i + 1].file_size = fsize;
            table[i + 1].file_off  = (old_type == VMA_FILE) ? foff + (base - obase) : 0;
            __builtin_memset(table[i + 1]._pad, 0, sizeof(table[i + 1]._pad));
            /* Right fragment: [end..e_end) with old prot */
            table[i + 2].base = end;
            table[i + 2].len  = e_end - end;
            table[i + 2].prot = old_prot;
            table[i + 2].type = old_type;
            table[i + 2].file_ino  = fino;
            table[i + 2].file_gen  = fgen;
            table[i + 2].file_size = fsize;
            table[i + 2].file_off  = (old_type == VMA_FILE) ? foff + (end - obase) : 0;
            __builtin_memset(table[i + 2]._pad, 0, sizeof(table[i + 2]._pad));
            /* Left fragment: [e->base..base) keeps old (base unchanged) */
            e->len = base - e->base;
            i += 3;
            continue;
        }

        i++;
    }

    *vcnt(proc) = count;
    return 0;
}

int vma_update_prot(struct aegis_process *proc,
                    uint64_t base, uint64_t len, uint32_t new_prot) {
    if (!proc || !proc->vma_table) return 0;
    spinlock_t *lk = vlock(proc);
    irqflags_t fl = spin_lock_irqsave(lk);
    int r = vma_update_prot_nolock(proc, base, len, new_prot);
    spin_unlock_irqrestore(lk, fl);
    return r;
}

void vma_clear(struct aegis_process *proc) {
    /* execve reuses this thread's own table; serialize against any concurrent
     * reader (defensive — a multithreaded exec is unusual but mustn't tear). */
    spinlock_t *lk = vlock(proc);
    irqflags_t fl = spin_lock_irqsave(lk);
    *vcnt(proc) = 0;
    spin_unlock_irqrestore(lk, fl);
}

void vma_clone(struct aegis_process *dst, struct aegis_process *src) {
    vma_entry_t *new_table = (vma_entry_t *)kva_alloc_pages(VMA_TABLE_PAGES);
    uint32_t count = *vcnt(src);

    if (count > 0)
        __builtin_memcpy(new_table, src->vma_table,
                         count * sizeof(vma_entry_t));

    dst->vma_table    = new_table;
    dst->vma_capacity = (uint32_t)VMA_CAPACITY;
    /* Independent copy: fresh header (refcount + count + lock) in the new page's
     * tail; the memcpy above copies only entry bytes and never touches the tail.
     * The new address space gets its own table lock. */
    refcount_init(vma_rc(dst), 1);
    *vcnt(dst) = count;
    { spinlock_t init = SPINLOCK_INIT; vma_hdr(dst)->lock = init; }
}

void vma_share(struct aegis_process *child, struct aegis_process *parent) {
    child->vma_table    = parent->vma_table;
    child->vma_capacity = parent->vma_capacity;
    /* child shares parent's table page → shares the embedded refcount AND the
     * embedded entry count. Do NOT copy a per-process count: a stale copy would
     * truncate this thread's vma_find range against VMAs another thread added. */
    refcount_inc(vma_rc(parent));
}

void vma_free(struct aegis_process *proc) {
    if (!proc->vma_table)
        return;

    /* Drop one reference; the LAST sharer frees the page. */
    if (refcount_dec_and_test(vma_rc(proc)))
        kva_free_pages(proc->vma_table, VMA_TABLE_PAGES);

    proc->vma_table = (vma_entry_t *)0;
}
