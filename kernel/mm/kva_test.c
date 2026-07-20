/* kva_test.c — integrity stress for the kernel VA allocator.
 *
 * Written to chase a corruption seen ONLY on arm64 and ONLY once AF_UNIX ring
 * buffers became 4-page allocations: the Pi 5 panicked during shutdown in
 * fd_table_unref, reading ops->close through a garbage (non-NULL) fds[].ops.
 * That is the signature of two owners holding the same memory, so this test
 * asserts exactly the invariants that would be violated:
 *
 *   1. No two live allocations overlap in VIRTUAL address space.
 *   2. No two live allocations share a PHYSICAL frame (checked per page via
 *      vmm_phys_of, which is what kva_free_pages uses to decide what to hand
 *      back to the PMM — if that resolves wrongly for pages past the first,
 *      the wrong frames get freed and later handed to someone else).
 *   3. Every byte of every live allocation still reads back the poison written
 *      into it — the direct test for "somebody else wrote here".
 *
 * Mixed 1-page and multi-page sizes on purpose: with a 4096-byte ring almost
 * every kva allocation in the GUI path was a single page, so the freelist's
 * carve/coalesce paths were barely exercised. Run with the `kvatest` cmdline
 * flag; it is not part of a normal boot.
 */
#include "kva.h"
#include "vmm.h"
#include "../core/printk.h"
#include <stdint.h>

#define SLOTS      48
#define ROUNDS     400
#define MAX_PAGES  4

typedef struct {
    uint8_t *va;
    uint64_t npages;
    uint32_t poison;
} slot_t;

static slot_t s_slot[SLOTS];

/* Deterministic PRNG — a failure must be replayable. */
static uint32_t s_rng = 0x2f6b1d07u;
static uint32_t
rnd(void)
{
    s_rng ^= s_rng << 13;
    s_rng ^= s_rng >> 17;
    s_rng ^= s_rng << 5;
    return s_rng;
}

static void
fill(slot_t *s)
{
    uint32_t *p = (uint32_t *)s->va;
    uint64_t words = s->npages * 4096u / 4u;
    for (uint64_t i = 0; i < words; i++)
        p[i] = s->poison ^ (uint32_t)i;
}

/* Returns 0 if intact, else the word index that was wrong. */
static uint64_t
check(slot_t *s)
{
    const uint32_t *p = (const uint32_t *)s->va;
    uint64_t words = s->npages * 4096u / 4u;
    for (uint64_t i = 0; i < words; i++)
        if (p[i] != (s->poison ^ (uint32_t)i))
            return i + 1;
    return 0;
}

static int
va_overlaps(const slot_t *a, const slot_t *b)
{
    uint64_t a0 = (uint64_t)(uintptr_t)a->va, a1 = a0 + a->npages * 4096u;
    uint64_t b0 = (uint64_t)(uintptr_t)b->va, b1 = b0 + b->npages * 4096u;
    return a0 < b1 && b0 < a1;
}

/* Any physical frame shared between two live allocations is a hard bug. */
static int
phys_collides(const slot_t *a, const slot_t *b)
{
    for (uint64_t i = 0; i < a->npages; i++) {
        uint64_t pa = vmm_phys_of((uint64_t)(uintptr_t)a->va + i * 4096u);
        for (uint64_t j = 0; j < b->npages; j++)
            if (pa == vmm_phys_of((uint64_t)(uintptr_t)b->va + j * 4096u))
                return 1;
    }
    return 0;
}

void
kva_test_run(void)
{
    int fails = 0;

    printk("[KVATEST] start: %d slots, %d rounds, 1..%d pages\n",
           SLOTS, ROUNDS, MAX_PAGES);

    for (int i = 0; i < SLOTS; i++)
        s_slot[i].va = (uint8_t *)0;

    for (int round = 0; round < ROUNDS && fails == 0; round++) {
        int idx = (int)(rnd() % SLOTS);
        slot_t *s = &s_slot[idx];

        if (s->va) {                      /* live → verify, then free */
            uint64_t bad = check(s);
            if (bad) {
                printk("[KVATEST] FAIL: slot %d (va=0x%lx, %lu pages) corrupted "
                       "at word %lu round %d\n", idx,
                       (unsigned long)(uintptr_t)s->va,
                       (unsigned long)s->npages, (unsigned long)(bad - 1), round);
                fails++;
                break;
            }
            kva_free_pages(s->va, s->npages);
            s->va = (uint8_t *)0;
            continue;
        }

        /* Empty → allocate. Bias toward multi-page: that is the case the
         * 4096-byte ring never produced. */
        uint64_t n = 1 + (rnd() % MAX_PAGES);
        s->va = (uint8_t *)kva_alloc_pages(n);
        if (!s->va) {
            printk("[KVATEST] FAIL: kva_alloc_pages(%lu) returned NULL "
                   "round %d\n", (unsigned long)n, round);
            fails++;
            break;
        }
        s->npages = n;
        s->poison = rnd() | 1u;

        /* Invariants against every other live allocation. */
        for (int j = 0; j < SLOTS && !fails; j++) {
            if (j == idx || !s_slot[j].va) continue;
            if (va_overlaps(s, &s_slot[j])) {
                printk("[KVATEST] FAIL: VA overlap slot %d (0x%lx +%lu) vs "
                       "slot %d (0x%lx +%lu) round %d\n",
                       idx, (unsigned long)(uintptr_t)s->va,
                       (unsigned long)s->npages, j,
                       (unsigned long)(uintptr_t)s_slot[j].va,
                       (unsigned long)s_slot[j].npages, round);
                fails++;
            } else if (phys_collides(s, &s_slot[j])) {
                printk("[KVATEST] FAIL: PHYS collision slot %d (0x%lx +%lu) vs "
                       "slot %d (0x%lx +%lu) round %d\n",
                       idx, (unsigned long)(uintptr_t)s->va,
                       (unsigned long)s->npages, j,
                       (unsigned long)(uintptr_t)s_slot[j].va,
                       (unsigned long)s_slot[j].npages, round);
                fails++;
            }
        }
        if (fails) break;

        fill(s);
    }

    /* Final sweep: everything still live must still be intact. */
    for (int i = 0; i < SLOTS && !fails; i++) {
        if (!s_slot[i].va) continue;
        uint64_t bad = check(&s_slot[i]);
        if (bad) {
            printk("[KVATEST] FAIL: slot %d corrupted at word %lu (final sweep)\n",
                   i, (unsigned long)(bad - 1));
            fails++;
        }
    }
    for (int i = 0; i < SLOTS; i++)
        if (s_slot[i].va) {
            kva_free_pages(s_slot[i].va, s_slot[i].npages);
            s_slot[i].va = (uint8_t *)0;
        }

    if (fails)
        printk("[KVATEST] DONE FAIL (%d)\n", fails);
    else
        printk("[KVATEST] DONE all-pass\n");
}
