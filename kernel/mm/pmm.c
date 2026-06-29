#include "pmm.h"
#include "arch.h"     /* aegis_mem_region_t, arch_mm_region_count/get_regions */
#include "printk.h"
#include "spinlock.h"
#include "kva.h"      /* kva_alloc_pages — full bitmap in pmm_init_late */
#include "fb.h"
#include "stackshot.h" /* print_backtrace_from — double-free sentinel */
#include <stdint.h>
#include <stddef.h>
/* Note: -nostdinc blocks string.h even from GCC freestanding headers.
 * Use a simple loop instead of memset for bitmap initialization.
 * printk has no format support; use local helpers to build strings. */

/* --------------------------------------------------------------------------
 * String formatting helpers (no libc available)
 * -------------------------------------------------------------------------- */

/* Write decimal representation of v into buf (must be at least 21 bytes).
 * Returns pointer past the last character written (not NUL-terminated). */
static char *u64_to_dec(char *buf, uint64_t v)
{
    char tmp[20];
    int  n = 0;
    if (v == 0) {
        *buf++ = '0';
        return buf;
    }
    while (v > 0) {
        tmp[n++] = (char)('0' + (int)(v % 10));
        v /= 10;
    }
    /* tmp holds digits in reverse order */
    for (int i = n - 1; i >= 0; i--)
        *buf++ = tmp[i];
    return buf;
}

/* Append a NUL-terminated literal string src into dst; return ptr past end. */
static char *append_str(char *dst, const char *src)
{
    while (*src)
        *dst++ = *src++;
    return dst;
}

/* --------------------------------------------------------------------------
 * Allocation bitmap — dynamically sized, NO fixed RAM cap
 *
 * 1 bit per 4 KB page, 0 = free / 1 = allocated. The bitmap is sized to the
 * machine's actual RAM, so there is no hard ceiling (it scales like Linux's:
 * a 32 MB bitmap covers 1 TB, 64 MB covers 2 TB, etc.).
 *
 * Bootstrap problem: the PMM needs memory to hold the bitmap, but the bitmap
 * is how the PMM tracks free memory. We solve it in two phases:
 *
 *   1. pmm_init() uses a small STATIC bootstrap bitmap covering the first 4 GB
 *      (PMM_BOOT_PAGES → 128 KB of BSS). That is enough to bring up the VMM and
 *      KVA allocator, whose early allocations all live in low RAM. On a machine
 *      with <= 4 GB this is the whole story.
 *
 *   2. pmm_init_late() — called after kva_init() — allocates the FULL,
 *      RAM-sized bitmap from KVA (higher-half, not the 8 MB kernel-image
 *      window, so it has no size limit), copies the bootstrap state into its
 *      low portion (preserving every allocation made so far, including the
 *      bitmap's own backing pages), frees the high RAM, and switches over.
 *
 * The active bitmap is reached through s_bitmap (a pointer), so all the code
 * below is oblivious to which phase is current. The sparse refcount table is
 * RAM-independent and stays static.
 * -------------------------------------------------------------------------- */
#define PMM_BOOT_GB     4ULL
#define PMM_BOOT_PAGES  (PMM_BOOT_GB * 1024 * 1024 * 1024 / PAGE_SIZE)

/* The DMA-safe boundary: pages below this index have physical addresses
 * < 4 GB and may be handed to devices whose 64-bit addressing we don't want
 * to trust (see pmm_alloc_page_low / kva_alloc_pages_low). */
#define PMM_LOW_PAGES   (4ULL * 1024 * 1024 * 1024 / PAGE_SIZE)

/* Static bootstrap bitmap: covers the first 4 GB (128 KB). Used until
 * pmm_init_late() swaps in the full RAM-sized bitmap. */
static uint8_t pmm_boot_bitmap[PMM_BOOT_PAGES / 8];

/* The active bitmap and its page capacity. Start on the bootstrap bitmap. */
static uint8_t *s_bitmap       = pmm_boot_bitmap;
static uint64_t s_bitmap_pages = PMM_BOOT_PAGES;

/* --------------------------------------------------------------------------
 * Sparse per-page refcount (COW fork + memfd MAP_SHARED)
 *
 * A full byte-per-page refcount array would be 1 MB per 4 GB of RAM (4 MB at
 * 16 GB, 8 MB at 32 GB) — far over the BSS budget. But refcounts are only ever
 * > 1 for the small, transient set of pages that are actively COW-shared after
 * a fork or mapped MAP_SHARED from a memfd. So we store refcounts ONLY for
 * those pages, in a fixed-size open-addressing hash table, and treat any
 * allocated-but-absent page as having the implicit refcount 1. This decouples
 * refcount storage from total RAM size.
 *
 * Semantics: refcount(pg) for an allocated page = (in table ? stored : 1).
 * We remove a page from the table the moment its count drops back to 1, so the
 * table only ever holds pages with refcount >= 2.
 *
 * Tombstone deletion (SLOT_TOMB) keeps lookups correct after removal; inserts
 * reuse tombstones so the table stays healthy under the churn of fork/exec.
 * 64K slots × 9 bytes = 576 KB, independent of RAM — room for 64K
 * simultaneously-shared pages (256 MB of COW/memfd-shared memory, comfortably
 * more than the GUI's window buffers + fork churn).
 *
 * The page-index KEY is uint64, matching the allocation bitmap's uint64 page
 * indices, so COW refcounting is EXACT for any physical page the bitmap can
 * track — there is no aliasing ceiling. (Earlier this key was uint32, which
 * silently truncated page indices >= 2^32: two distinct pages 2^32 apart, or a
 * page that happened to land on index 0xFFFFFFFF/0xFFFFFFFE, would collide with
 * each other or with the empty/tombstone sentinels, corrupting refcounts above
 * 16 TB of RAM. The 64-bit key removes that class of bug at the root: the
 * sentinels 2^64-1 / 2^64-2 correspond to page indices that are physically
 * unreachable, 2^76 bytes.)
 * -------------------------------------------------------------------------- */
#define PMM_REFHASH_SIZE  65536u             /* 64K slots */
/* Page-KEY sentinels stored in s_ref_page[] (a uint64 page index, or one of
 * these). They sit at 2^64-1 / 2^64-2 — page indices for 2^76-byte physical
 * addresses, i.e. physically unreachable, so a real page can never alias them. */
#define SLOT_EMPTY        0xFFFFFFFFFFFFFFFFull
#define SLOT_TOMB         0xFFFFFFFFFFFFFFFEull
/* A SLOT-INDEX "none" sentinel (distinct from the page-key sentinels above).
 * Valid slot indices are 0..PMM_REFHASH_SIZE-1, so PMM_REFHASH_SIZE is an
 * unused, type-correct marker for "no slot chosen yet". */
#define SLOT_NONE         PMM_REFHASH_SIZE
static uint64_t s_ref_page[PMM_REFHASH_SIZE];   /* page index, or SLOT_EMPTY/TOMB */
static uint16_t s_ref_count[PMM_REFHASH_SIZE];  /* refcount (>= 2) for a live slot */

static uint64_t s_total_usable_bytes;   /* raw usable RAM from the memory map */
/* Pages the PMM actually manages: usable RAM within the bitmap's coverage.
 * MemTotal reports this (not raw physical), so RAM beyond the bitmap isn't
 * counted as bogus "used" in /proc/meminfo. */
static uint64_t s_managed_pages;
/* Highest page index in usable RAM (+1) from the memory map — the FULL extent,
 * independent of the current bitmap. pmm_init_late() sizes the full bitmap to
 * this. */
static uint64_t s_ram_max_pages;
/* Highest page the current bitmap can serve (= min(s_ram_max_pages,
 * s_bitmap_pages)). Bounds every scan so a large bitmap doesn't slow a small
 * machine, and confines allocation to the bootstrap range until the full
 * bitmap is live. */
static uint64_t s_scan_max_pages;
/* Next-fit hint (byte index into the bitmap) so allocation doesn't rescan the
 * allocated low region from 0 every time — important once low RAM fills on a
 * big machine. */
static uint64_t s_alloc_hint_byte;

static spinlock_t pmm_lock = SPINLOCK_INIT;

/* _kernel_end is exported by the linker script after .bss.
 * The bitmap array itself is in .bss, so _kernel_end is after it. */
extern char _kernel_end[];

/* --------------------------------------------------------------------------
 * Sparse refcount hash — all helpers run under pmm_lock
 * -------------------------------------------------------------------------- */

static uint32_t refhash_home(uint64_t pg)
{
    /* Fibonacci hash, then fold to table size. */
    return (uint32_t)((pg * 2654435761ull) % PMM_REFHASH_SIZE);
}

/* Return the stored refcount for pg, or 0 if not present (→ implicit 1). */
static uint16_t refhash_get(uint64_t pg)
{
    uint32_t h = refhash_home(pg);
    for (uint32_t n = 0; n < PMM_REFHASH_SIZE; n++) {
        uint32_t j = (h + n) % PMM_REFHASH_SIZE;
        if (s_ref_page[j] == SLOT_EMPTY)
            return 0;                         /* end of probe chain — absent */
        if (s_ref_page[j] == pg)
            return s_ref_count[j];
        /* SLOT_TOMB or other key — keep probing */
    }
    return 0;
}

/* Insert or update pg → count (count >= 2). Reuses tombstones. */
static void refhash_set(uint64_t pg, uint16_t count)
{
    uint32_t h = refhash_home(pg);
    uint32_t first_tomb = SLOT_NONE;
    for (uint32_t n = 0; n < PMM_REFHASH_SIZE; n++) {
        uint32_t j = (h + n) % PMM_REFHASH_SIZE;
        if (s_ref_page[j] == pg) {            /* update in place */
            s_ref_count[j] = count;
            return;
        }
        if (s_ref_page[j] == SLOT_TOMB) {
            if (first_tomb == SLOT_NONE) first_tomb = j;
            continue;
        }
        if (s_ref_page[j] == SLOT_EMPTY) {
            uint32_t slot = (first_tomb != SLOT_NONE) ? first_tomb : j;
            s_ref_page[slot]  = pg;
            s_ref_count[slot] = count;
            return;
        }
    }
    if (first_tomb != SLOT_NONE) {            /* no empty, but a tombstone */
        s_ref_page[first_tomb]  = pg;
        s_ref_count[first_tomb] = count;
        return;
    }
    panic_halt("[PMM] FAIL: refcount hash full (too many shared pages)");
}

/* Remove pg from the table (mark its slot a tombstone). */
static void refhash_remove(uint64_t pg)
{
    uint32_t h = refhash_home(pg);
    for (uint32_t n = 0; n < PMM_REFHASH_SIZE; n++) {
        uint32_t j = (h + n) % PMM_REFHASH_SIZE;
        if (s_ref_page[j] == SLOT_EMPTY)
            return;                           /* absent */
        if (s_ref_page[j] == pg) {
            s_ref_page[j]  = SLOT_TOMB;
            s_ref_count[j] = 0;
            return;
        }
    }
}

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

static void pmm_free_region(uint64_t base, uint64_t len)
{
    /* Align base up to PAGE_SIZE, len down to a page boundary. */
    uint64_t start = (base + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (start >= base + len)
        return;
    uint64_t end = (base + len) & ~(PAGE_SIZE - 1);

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        uint64_t idx = addr / PAGE_SIZE;
        if (idx < s_bitmap_pages)
            s_bitmap[idx / 8] &= (uint8_t)~(1U << (idx % 8));
    }
}

/* Return 1 if the page at addr is fully contained in a usable-RAM region.
 * Rounding mirrors pmm_free_region (region base rounded up, end rounded
 * down), so this answers exactly "did pmm_init's free pass cover this
 * page?" — pages outside usable RAM were never accounted by the PMM and
 * must never be marked free. */
static int pmm_page_in_usable_ram(uint64_t addr)
{
    uint32_t                  nregions = arch_mm_region_count();
    const aegis_mem_region_t *regions  = arch_mm_get_regions();

    for (uint32_t i = 0; i < nregions; i++) {
        uint64_t rstart = (regions[i].base + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        uint64_t rend   = (regions[i].base + regions[i].len) & ~(PAGE_SIZE - 1);
        if (rstart < rend && addr >= rstart && addr + PAGE_SIZE <= rend)
            return 1;
    }
    return 0;
}

static void pmm_reserve_region(uint64_t base, uint64_t len)
{
    /* Align base down, end up — reserve conservatively. */
    uint64_t start = base & ~(PAGE_SIZE - 1);
    uint64_t end   = (base + len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        uint64_t idx = addr / PAGE_SIZE;
        if (idx < s_bitmap_pages)
            s_bitmap[idx / 8] |= (uint8_t)(1U << (idx % 8));
    }
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

void pmm_init(void)
{
    lockrank_register(&pmm_lock, LOCK_RANK_PMM);   /* debug lock-order check */
    /* Step 0: empty the refcount table (every page starts at implicit 1). */
    for (uint32_t i = 0; i < PMM_REFHASH_SIZE; i++) {
        s_ref_page[i]  = SLOT_EMPTY;
        s_ref_count[i] = 0;
    }

    /* Step 1: start with everything reserved (safe default) */
    for (uint64_t i = 0; i < s_bitmap_pages / 8; i++)
        s_bitmap[i] = 0xFF;

    /* Step 2: mark usable RAM as free */
    uint32_t                  nregions = arch_mm_region_count();
    const aegis_mem_region_t *regions  = arch_mm_get_regions();

    uint64_t total_bytes  = 0;
    uint64_t ram_max_page = 0;     /* full extent — sizes the late bitmap */
    for (uint32_t i = 0; i < nregions; i++) {
        /* pmm_free_region only touches pages within the current (bootstrap)
         * bitmap; the rest of RAM is freed by pmm_init_late(). */
        pmm_free_region(regions[i].base, regions[i].len);
        total_bytes += regions[i].len;

        uint64_t end_pg = (regions[i].base + regions[i].len) / PAGE_SIZE;
        if (end_pg > ram_max_page) ram_max_page = end_pg;
    }

    s_total_usable_bytes = total_bytes;
    s_ram_max_pages      = ram_max_page;
    /* Bootstrap phase: only the first PMM_BOOT_PAGES are bitmap-tracked.
     * pmm_init_late() raises this to the full extent. */
    s_scan_max_pages     = (ram_max_page < s_bitmap_pages)
                           ? ram_max_page : s_bitmap_pages;
    /* MemTotal during bootstrap reflects what's tracked so far; recomputed
     * to the full usable total in pmm_init_late(). */
    s_managed_pages      = s_scan_max_pages;
    s_alloc_hint_byte    = 0;

    /* Step 3: re-reserve arch platform ranges (first 1MB on x86) */
    uint32_t                  nreserved = arch_mm_reserved_region_count();
    const aegis_mem_region_t *reserved  = arch_mm_get_reserved_regions();

    for (uint32_t i = 0; i < nreserved; i++)
        pmm_reserve_region(reserved[i].base, reserved[i].len);

    /* Step 4: reserve the kernel image + bitmap (bitmap is in .bss,
     * inside this range).  The kernel image spans from PHYS_BASE to
     * PHYS_BASE + kernel_size, where kernel_size = _kernel_end_VA - VIRT_BASE. */
    pmm_reserve_region(ARCH_KERNEL_PHYS_BASE,
                       (uint64_t)(uintptr_t)_kernel_end - ARCH_KERNEL_VIRT_BASE);

    /* Step 5: report. Bootstrap phase — the full bitmap (and final managed
     * total) is reported by pmm_init_late(). */
    uint64_t mb = s_total_usable_bytes / (1024 * 1024);
    {
        char    buf[160];
        char   *p = buf;
        p = append_str(p, "[PMM] OK: ");
        p = u64_to_dec(p, mb);
        p = append_str(p, "MB usable across ");
        p = u64_to_dec(p, (uint64_t)nregions);
        p = append_str(p, " regions\n");
        *p = '\0';
        printk("%s", buf);
    }
}

/* --------------------------------------------------------------------------
 * pmm_init_late — replace the 4 GB bootstrap bitmap with a full RAM-sized one.
 *
 * Called once, after kva_init(), before pmm_set_alloc_high_pref(1) and before
 * any allocation needs high RAM. On a machine with <= 4 GB this is a no-op.
 * Otherwise it allocates the full bitmap from KVA (higher-half — not the 8 MB
 * kernel-image window, so there is NO size cap), migrates the bootstrap state
 * into its low portion (preserving every allocation made so far, including the
 * new bitmap's own backing pages, which were just allocated from low RAM and
 * are marked used in the bootstrap bitmap), frees the high RAM, and switches.
 * -------------------------------------------------------------------------- */
void pmm_init_late(void)
{
    if (s_ram_max_pages <= s_bitmap_pages)
        return;   /* <= 4 GB: bootstrap bitmap already covers all RAM */

    uint64_t full_pages = s_ram_max_pages;
    uint64_t full_bytes = (full_pages + 7) / 8;
    uint64_t need_pages = (full_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    /* KVA-backed, higher-half: backing frames come from low RAM (high RAM is
     * not yet available), and kva_alloc_pages marks them used in the bootstrap
     * bitmap — so the memcpy below carries that "used" state into the new
     * bitmap. No 8 MB-image limit applies here. */
    uint8_t *big = (uint8_t *)kva_alloc_pages(need_pages);
    if (!big) {
        printk("[PMM] WARN: late bitmap alloc failed; staying at 4GB\n");
        return;
    }

    uint64_t boot_bytes = s_bitmap_pages / 8;

    irqflags_t fl = spin_lock_irqsave(&pmm_lock);

    /* Low 4 GB: exact copy of the bootstrap state (all current allocations). */
    for (uint64_t i = 0; i < boot_bytes; i++)
        big[i] = s_bitmap[i];
    /* High range: start fully reserved... */
    for (uint64_t i = boot_bytes; i < full_bytes; i++)
        big[i] = 0xFF;

    /* ...then free usable RAM in the high range only (never re-touch the low
     * range — it already reflects live allocations). */
    uint32_t                  nregions = arch_mm_region_count();
    const aegis_mem_region_t *regions  = arch_mm_get_regions();
    uint64_t high_free = 0;
    for (uint32_t r = 0; r < nregions; r++) {
        uint64_t start = (regions[r].base + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        uint64_t end   = (regions[r].base + regions[r].len) & ~(PAGE_SIZE - 1);
        uint64_t spg   = start / PAGE_SIZE;
        uint64_t epg   = end   / PAGE_SIZE;
        if (spg < s_bitmap_pages) spg = s_bitmap_pages;   /* high range only */
        if (epg > full_pages)     epg = full_pages;
        for (uint64_t pg = spg; pg < epg; pg++) {
            big[pg / 8] &= (uint8_t)~(1U << (pg % 8));
            high_free++;
        }
    }

    /* Switch over. From here the allocator sees all of RAM. */
    s_bitmap         = big;
    s_bitmap_pages   = full_pages;
    s_scan_max_pages = full_pages;
    s_managed_pages  = s_total_usable_bytes / PAGE_SIZE;
    s_alloc_hint_byte = 0;

    spin_unlock_irqrestore(&pmm_lock, fl);

    {
        char    buf[160];
        char   *p = buf;
        p = append_str(p, "[PMM] OK: full bitmap live, ");
        p = u64_to_dec(p, (s_managed_pages * PAGE_SIZE) / (1024 * 1024));
        p = append_str(p, "MB managed (");
        p = u64_to_dec(p, (high_free * PAGE_SIZE) / (1024 * 1024));
        p = append_str(p, "MB above 4GB)\n");
        *p = '\0';
        printk("%s", buf);
    }
}

/* Prefer high (>=4GB) RAM for general allocations once set — keeps the low
 * (<4GB) pool free for device DMA. OFF during early boot so the first page
 * tables land below 1GB (they're reached through the identity map before the
 * higher-half window allocator exists). pmm_set_alloc_high_pref(1) flips it
 * after vmm_init/kva_init. No effect on a <=4GB machine (no high zone). */
static int s_high_pref;

void pmm_set_alloc_high_pref(int on)
{
    irqflags_t fl = spin_lock_irqsave(&pmm_lock);
    s_high_pref = on ? 1 : 0;
    spin_unlock_irqrestore(&pmm_lock, fl);
}

/* Double-free sentinel gate. OFF by default → no extra serial output, so the
 * exact-match boot oracle is unaffected. Set via the `pmm_debug` cmdline token.
 * Not under pmm_lock: a plain int written once at boot, read in pmm_free_page;
 * a torn read is impossible for an aligned int and the worst case of a stale
 * read is one missed/extra diagnostic line — never a correctness issue. */
static int s_pmm_debug;

void pmm_set_debug(int on)
{
    s_pmm_debug = on ? 1 : 0;
}

/* ── PMM ref/unref accounting (improve-mm T1) ──────────────────────────────
 * Opt-in diagnostic (cmdline `pmm_acct`, OFF by default → exact-match boot
 * oracle unaffected) built for the COW-fork teardown refcount hunt (improve-mm
 * T2 / the comparison doc's "teardown refcount under-count" finding). It keeps a
 * cumulative ledger of every refcount transition and prints a scoreboard at each
 * address-space teardown (vmm_free_user_pml4).
 *
 * Headline signal: `dblfree` — a free of a managed-RAM frame whose bitmap bit is
 * ALREADY clear, i.e. a frame freed one time too many. When the COW under-count
 * bug's extra pmm_free_page lands on an already-freed frame this counter rises;
 * the eager-copy fork path leaves it at zero. A test boots `pmm_acct`, runs a
 * fork->exec->reap loop, and asserts the teardown scoreboard reports dblfree=0.
 *
 * `cons` checks `refs - unrefs == shared_extra`, a cheap internal-consistency
 * invariant on the sparse refcount table (every pmm_ref_page bumps refs and a
 * table slot; every shared-page pmm_free_page bumps unrefs and drops a slot). A
 * MISMATCH means a refcount was mutated outside the pmm_ref_page/pmm_free_page
 * API, or the accounting branches drifted.
 *
 * Honest scope (ties back to the comparison): this CANNOT catch a silent
 * premature free that lands on a still-MAPPED frame without ever hitting an
 * already-clear bit — that needs the per-frame ownership ground truth Aegis
 * lacks today (Serenity's VMObject RefPtr array; see
 * docs/comparisons/serenity/01-memory.md and improve-mm T7). It catches the
 * double-free symptom, leaks (allocs vs frees drift), and table-accounting
 * corruption. Pair with `pmm_debug` (symbolized backtrace at the offending free)
 * to pinpoint a hit.
 *
 * All counters are mutated only under pmm_lock (every call site already holds
 * it), so plain uint64_t is race-free. */
static int      s_pmm_acct;
static uint64_t s_acct_allocs;   /* single-page pmm_alloc_scan successes        */
static uint64_t s_acct_refs;     /* pmm_ref_page increments                     */
static uint64_t s_acct_unrefs;   /* pmm_free_page shared-page decrements (>=2)  */
static uint64_t s_acct_frees;    /* pmm_free_page frees-to-zero                 */
static uint64_t s_acct_dblfree;  /* pmm_free_page of an already-free RAM frame  */

void pmm_set_acct(int on)
{
    s_pmm_acct = on ? 1 : 0;
}

int pmm_acct_enabled(void)
{
    return s_pmm_acct;
}

void pmm_acct_dump(const char *tag)
{
    /* Sum (count-1) over the sparse refcount table = outstanding shared refs.
     * Take pmm_lock so the 64K-slot walk sees a consistent table snapshot. */
    irqflags_t fl = spin_lock_irqsave(&pmm_lock);
    uint64_t shared_extra = 0;
    for (uint32_t i = 0; i < PMM_REFHASH_SIZE; i++) {
        uint64_t k = s_ref_page[i];
        if (k != SLOT_EMPTY && k != SLOT_TOMB && s_ref_count[i] >= 1)
            shared_extra += (uint64_t)s_ref_count[i] - 1u;
    }
    uint64_t allocs = s_acct_allocs, frees = s_acct_frees;
    uint64_t refs   = s_acct_refs,   unrefs = s_acct_unrefs;
    uint64_t dbl    = s_acct_dblfree;
    spin_unlock_irqrestore(&pmm_lock, fl);

    const char *cons = (refs - unrefs == shared_extra) ? "OK" : "MISMATCH";
    printk("[PMMACCT] %s allocs=%lu frees=%lu refs=%lu unrefs=%lu "
           "dblfree=%lu shared_extra=%lu cons=%s\n",
           tag ? tag : "?", allocs, frees, refs, unrefs, dbl, shared_extra, cons);
}

/* Scan the bitmap for a free page with index in [start_pg, end_pg), next-fit
 * via *hint_byte if non-NULL. Marks it allocated. Returns the physical
 * address, or 0 if none. Caller holds pmm_lock. */
static uint64_t pmm_alloc_scan(uint64_t start_pg, uint64_t end_pg,
                               uint64_t *hint_byte)
{
    if (start_pg >= end_pg)
        return 0;
    uint64_t start_byte = start_pg / 8;
    uint64_t end_byte   = (end_pg + 7) / 8;
    uint64_t nbytes     = end_byte - start_byte;

    uint64_t h = 0;
    if (hint_byte) {
        h = *hint_byte;
        if (h < start_byte || h >= end_byte)
            h = start_byte;
        h -= start_byte;                       /* relative to the range */
    }

    for (uint64_t k = 0; k < nbytes; k++) {
        uint64_t rb = h + k;
        if (rb >= nbytes)
            rb -= nbytes;                      /* wrap within the range */
        uint64_t i = start_byte + rb;
        if (s_bitmap[i] == 0xFF)
            continue;
        for (int bit = 0; bit < 8; bit++) {
            if (s_bitmap[i] & (1U << bit))
                continue;
            uint64_t pg = i * 8 + (uint64_t)bit;
            if (pg < start_pg || pg >= end_pg)
                continue;                      /* outside the requested range */
            s_bitmap[i] |= (uint8_t)(1U << bit);
            /* Fresh allocation: implicit refcount 1 (not stored). */
            if (s_pmm_acct) s_acct_allocs++;   /* T1 accounting (pmm_lock held) */
            if (hint_byte)
                *hint_byte = i;
            return pg * PAGE_SIZE;
        }
    }
    return 0;
}

uint64_t pmm_alloc_page(void)
{
    irqflags_t fl = spin_lock_irqsave(&pmm_lock);
    uint64_t low_end = (PMM_LOW_PAGES < s_scan_max_pages)
                       ? PMM_LOW_PAGES : s_scan_max_pages;
    uint64_t phys = 0;

    if (s_high_pref && s_scan_max_pages > PMM_LOW_PAGES) {
        /* Prefer the high zone; fall back to low only under pressure. */
        phys = pmm_alloc_scan(PMM_LOW_PAGES, s_scan_max_pages, &s_alloc_hint_byte);
        if (phys == 0)
            phys = pmm_alloc_scan(0, low_end, NULL);
    } else {
        /* Boot / <=4GB machine: low-first across the managed range. The
         * hint keeps the scan cheap once low RAM fills. */
        phys = pmm_alloc_scan(0, s_scan_max_pages, &s_alloc_hint_byte);
    }

    spin_unlock_irqrestore(&pmm_lock, fl);
    if (phys == 0)
        printk("[PMM] WARN: out of physical memory\n");
    return phys;   /* OOM → 0 (always reserved, unambiguous sentinel) */
}

/* Allocate a page guaranteed below 4 GB — for device DMA buffers (NVMe,
 * virtio) whose physical address is programmed into hardware we don't want to
 * assume is 64-bit-DMA-capable. The low pool is preserved by high-pref
 * general allocation (above), so this stays available. Returns 0 if exhausted. */
uint64_t pmm_alloc_page_low(void)
{
    uint64_t lo = (PMM_LOW_PAGES < s_scan_max_pages)
                  ? PMM_LOW_PAGES : s_scan_max_pages;
    irqflags_t fl = spin_lock_irqsave(&pmm_lock);
    uint64_t phys = pmm_alloc_scan(0, lo, NULL /* no hint: scan from 0 */);
    spin_unlock_irqrestore(&pmm_lock, fl);
    if (phys == 0)
        printk("[PMM] WARN: out of low (<4GB) DMA memory\n");
    return phys;
}

/* Allocate n physically-contiguous pages below 4 GB. First-fit linear scan of
 * the low bitmap for a run of n free pages; marks them all allocated. Returns
 * the base physical address, or 0 if no run exists. Caller-facing contract in
 * pmm.h. */
uint64_t pmm_alloc_contig_low(uint64_t n)
{
    if (n == 0)
        return 0;
    uint64_t lo = (PMM_LOW_PAGES < s_scan_max_pages)
                  ? PMM_LOW_PAGES : s_scan_max_pages;
    irqflags_t fl = spin_lock_irqsave(&pmm_lock);

    uint64_t run = 0, run_start = 0, result = 0;
    for (uint64_t pg = 0; pg < lo; pg++) {
        int used = (s_bitmap[pg / 8] >> (pg % 8)) & 1;
        if (used) {
            run = 0;
            continue;
        }
        if (run == 0)
            run_start = pg;
        if (++run == n) {
            for (uint64_t p = run_start; p < run_start + n; p++)
                s_bitmap[p / 8] |= (uint8_t)(1U << (p % 8));
            result = run_start * PAGE_SIZE;
            break;
        }
    }

    spin_unlock_irqrestore(&pmm_lock, fl);
    if (result == 0)
        printk("[PMM] WARN: no %u contiguous low pages\n", (unsigned)n);
    return result;
}

/*
 * pmm_ref_page — increment refcount of an already-allocated page.
 *
 * Used by COW fork and memfd MAP_SHARED to share a page. Panics if the page is
 * not currently allocated. The per-frame refcount is uint16_t (max 65535):
 * under the kernel's hard caps (AEGIS_MAX_PROCESSES=256 × VMA_CAPACITY mappings
 * per address space) a single frame can be shared at most a few tens of
 * thousands of times, well below 65535, so the overflow guard is an unreachable
 * defensive check rather than a userspace-drivable DoS. (It was a uint8_t: a
 * fork-without-exec bomb to the 256-process cap drove the 255th ref into
 * panic_halt — CVE-class DoS from a baseline-cap process. See secfix M1.)
 */
void pmm_ref_page(uint64_t addr)
{
    if (addr & (PAGE_SIZE - 1))
        panic_halt("[PMM] FAIL: pmm_ref_page called with unaligned addr");
    uint64_t idx = addr / PAGE_SIZE;
    if (idx >= s_scan_max_pages)
        return;    /* MMIO / outside PMM-managed RAM — refcounting N/A */

    irqflags_t fl  = spin_lock_irqsave(&pmm_lock);
    uint8_t    bit = (uint8_t)(1U << (idx % 8));
    if (!(s_bitmap[idx / 8] & bit)) {
        spin_unlock_irqrestore(&pmm_lock, fl);
        panic_halt("[PMM] FAIL: pmm_ref_page on unallocated page");
    }
    uint16_t cur = refhash_get(idx);
    if (cur == 0) cur = 1;                      /* implicit single owner */
    if (cur == 0xFFFF) {
        spin_unlock_irqrestore(&pmm_lock, fl);
        panic_halt("[PMM] FAIL: pmm_ref_page refcount overflow");
    }
    refhash_set(idx, (uint16_t)(cur + 1));      /* now >= 2 → stored */
    if (s_pmm_acct) s_acct_refs++;              /* T1 accounting (pmm_lock held) */
    spin_unlock_irqrestore(&pmm_lock, fl);
}

/*
 * pmm_page_refcount — read the current refcount of an allocated page.
 *
 * Returns the page's reference count: 1 for a normally-allocated page absent
 * from the sparse table (implicit single owner), or the stored count (>= 2)
 * for a shared page. Returns 0 for an address outside PMM-managed RAM (MMIO).
 *
 * Used by the COW write-fault handler to take a reuse-in-place fast path: a
 * COW page whose frame is already singly-owned (the other sharer execve'd or
 * exited, dropping its ref) needs no copy — just clear COW and set writable.
 */
uint16_t pmm_page_refcount(uint64_t addr)
{
    uint64_t idx = addr / PAGE_SIZE;
    if (idx >= s_scan_max_pages)
        return 0;                       /* MMIO / outside managed RAM */
    irqflags_t fl  = spin_lock_irqsave(&pmm_lock);
    uint16_t   cur = refhash_get(idx);
    spin_unlock_irqrestore(&pmm_lock, fl);
    return cur == 0 ? 1 : cur;          /* absent from table → implicit 1 */
}

void pmm_free_page(uint64_t addr)
{
    if (addr & (PAGE_SIZE - 1)) {
        char  buf[80];
        char *p = buf;
        p = append_str(p, "[PMM] FAIL: pmm_free_page called with unaligned addr ");
        p = u64_to_dec(p, addr);
        p = append_str(p, "\n");
        *p = '\0';
        printk("%s", buf);
        panic_halt("[PMM] FAIL: pmm_free_page called with unaligned addr");
    }
    uint64_t idx = addr / PAGE_SIZE;
    if (idx >= s_scan_max_pages) {
        /* Outside PMM-managed RAM (e.g. MMIO framebuffer physical addresses
         * mapped into user space by sys_fb_map). Never allocated by PMM. */
        return;
    }
    irqflags_t fl  = spin_lock_irqsave(&pmm_lock);
    uint8_t    bit = (uint8_t)(1U << (idx % 8));
    if (!(s_bitmap[idx / 8] & bit)) {
        /* Not allocated — MMIO mapped into user space, or a double-free.
         * Silently skip (MMIO pages are legitimately freed at process exit).
         * MMIO physical addresses are already filtered out above (idx >=
         * s_scan_max_pages), so a managed-RAM page that is bitmap-clear here is
         * almost certainly a genuine double-free (or a free of a never-allocated
         * page) — a wrong-physical-frame producer once the frame is recycled. */
        if (s_pmm_acct) s_acct_dblfree++;      /* T1 accounting (pmm_lock held) */
        spin_unlock_irqrestore(&pmm_lock, fl);
        if (s_pmm_debug) {
            /* Diagnostic only (gated OFF by default → oracle-safe). Emit AFTER
             * releasing pmm_lock: printk + the frame-pointer walk must not run
             * under the leaf lock. __builtin_frame_address(0) gives this frame's
             * rbp; print_backtrace_from symbolizes the chain to the caller. */
            printk("[PMM] WARN: double-free / free of unallocated page phys=0x%lx\n",
                   addr);
            print_backtrace_from((uint64_t)(uintptr_t)__builtin_frame_address(0), 12);
        }
        return;
    }
    /* Refcount: only the last owner actually frees the page. An allocated page
     * absent from the table has the implicit refcount 1, so this is the common
     * 1→free path; shared pages (count >= 2) just decrement, and drop out of
     * the table when they return to a single owner. */
    uint16_t cur = refhash_get(idx);
    if (cur <= 1) {
        /* Single (or implicit single) owner → free the page. */
        if (cur == 1)
            refhash_remove(idx);               /* shouldn't be stored, defensive */
        s_bitmap[idx / 8] &= (uint8_t)~bit;
        if (s_pmm_acct) s_acct_frees++;        /* T1 accounting (pmm_lock held) */
    } else {
        uint16_t nv = (uint16_t)(cur - 1);
        if (nv == 1)
            refhash_remove(idx);               /* back to implicit single owner */
        else
            refhash_set(idx, nv);
        if (s_pmm_acct) s_acct_unrefs++;       /* T1 accounting (pmm_lock held) */
    }
    /* A free below the hint creates a free page the next-fit scan would skip;
     * pull the hint back so it's reconsidered. */
    if (idx / 8 < s_alloc_hint_byte)
        s_alloc_hint_byte = idx / 8;
    spin_unlock_irqrestore(&pmm_lock, fl);
}

/*
 * pmm_unreserve_region — release a boot-time reserved physical range back
 * to the allocator (used after the multiboot2 module ramdisk copies).
 *
 * Only pages FULLY contained in [base, base+len) and within usable RAM are
 * freed. Reserved pages are bitmap-set but were never handed out by
 * pmm_alloc, so they are never in the refcount table and are never the target
 * of a live allocation — pmm_alloc only ever returns bitmap-CLEAR pages, so no
 * page inside a still-reserved range can be a live allocation. We therefore
 * clear the bitmap directly; the per-page refcount check the old byte-array
 * version did is redundant under that invariant (and a sparse table can't
 * distinguish a reserved page from an implicit-refcount-1 allocation anyway,
 * but the structural guarantee makes that distinction unnecessary here).
 *
 * Returns the number of pages released.
 */
uint64_t pmm_unreserve_region(uint64_t base, uint64_t len)
{
    if (len == 0 || base + len < base)   /* empty or wrapping range */
        return 0;

    uint64_t start = (base + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uint64_t end   = (base + len) & ~(PAGE_SIZE - 1);
    if (start >= end)
        return 0;

    uint64_t   freed = 0;
    irqflags_t fl    = spin_lock_irqsave(&pmm_lock);
    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        uint64_t idx = addr / PAGE_SIZE;
        if (idx >= s_bitmap_pages)
            break;      /* beyond bitmap coverage — stop */
        if (!pmm_page_in_usable_ram(addr))
            continue;   /* hole/MMIO — PMM never accounted this as RAM */
        uint8_t bit = (uint8_t)(1U << (idx % 8));
        if (!(s_bitmap[idx / 8] & bit))
            continue;   /* already free — never double-free */
        if (refhash_get(idx) != 0)
            continue;   /* defensively skip anything that is COW/memfd shared */
        s_bitmap[idx / 8] &= (uint8_t)~bit;
        if (idx / 8 < s_alloc_hint_byte)
            s_alloc_hint_byte = idx / 8;
        freed++;
    }
    spin_unlock_irqrestore(&pmm_lock, fl);
    return freed;
}

uint64_t
pmm_total_pages(void)
{
    /* Pages the PMM manages (bitmap-tracked). NOT the raw physical total. */
    return s_managed_pages;
}

uint64_t
pmm_free_pages(void)
{
    irqflags_t fl = spin_lock_irqsave(&pmm_lock);
    uint64_t free_count = 0;
    uint64_t nbytes = (s_scan_max_pages + 7) / 8;
    for (uint64_t i = 0; i < nbytes; i++) {
        uint8_t inv = (uint8_t)~s_bitmap[i];
        while (inv) {
            free_count++;
            inv &= (inv - 1);  /* clear lowest set bit */
        }
    }
    spin_unlock_irqrestore(&pmm_lock, fl);
    return free_count;
}
