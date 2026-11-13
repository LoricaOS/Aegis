/*
 * Diagnostic-only 4 KiB identity map. All table pages belong to the loaded
 * image; no firmware RAM is allocated or reclaimed. No block mappings.
 */
#include "probe_mmu.h"

#define PAGE 4096ULL
#define MASK 0x0000fffffffff000ULL
#define AF (1ULL << 10)
#define RO (1ULL << 7)
#define PXN (1ULL << 53)
#define UXN (1ULL << 54)
#define NORMAL (AF | (3ULL << 8) | UXN)
#define DEVICE (AF | (2ULL << 8) | (1ULL << 2) | PXN | UXN)

static uint64_t pool[PROBE_PT_PAGES * 512] __attribute__((aligned(4096)));
static uint64_t physical_base, used, mapped;

const uint64_t *probe_map_pool(void)
{
    return pool;
}

struct range { uint64_t begin, end, attrs; };

static int span(uint64_t base, uint64_t size, uint64_t limit,
                 uint64_t attrs, struct range *out)
{
    if (!base || !size || base >= limit || size > limit - base)
        return 0;
    out->begin = base & ~(PAGE - 1);
    out->end = (base + size + PAGE - 1) & ~(PAGE - 1);
    out->attrs = attrs;
    return 1;
}

static int map_page(uint64_t address, uint64_t attrs)
{
    uint64_t *table = pool;
    for (int level = 0; level < 3; level++) {
        unsigned index = (unsigned)((address >> (39 - level * 9)) & 511);
        if (!table[index]) {
            if (used == PROBE_PT_PAGES)
                return 0;
            table[index] = (physical_base + used * PAGE) | 3;
            used++;
        }
        uint64_t child = table[index] & MASK;
        if ((table[index] & 3) != 3 || child < physical_base ||
            (child - physical_base) / PAGE >= used)
            return 0;
        table = pool + ((child - physical_base) / PAGE) * 512;
    }
    unsigned index = (unsigned)((address >> 12) & 511);
    uint64_t descriptor = address | attrs | 3;
    if (table[index] && table[index] != descriptor)
        return 0;                       /* no conflicting aliases/attributes */
    if (!table[index])
        mapped++;
    table[index] = descriptor;
    return 1;
}

int probe_map_build(const struct probe_map_request *q, struct probe_map_result *r)
{
    if (!r)
        return 0;
    r->root = r->tcr = r->mair = r->tables = r->pages = 0;
    if (!q)
        return 0;
    unsigned granule = (unsigned)((q->mmfr0 >> 28) & 15);
    unsigned pa = (unsigned)(q->mmfr0 & 15);
    /* Known 4 KiB encodings, no LPA2/52-bit descriptor format in this probe. */
    if (granule > 1 || pa > 5)
        return 0;
    unsigned bits = pa == 0 ? 32 : pa == 1 ? 36 : pa == 2 ? 40 :
                    pa == 3 ? 42 : pa == 4 ? 44 : 48;
    uint64_t limit = 1ULL << bits;
    if (!q->image || (q->image & (0x200000 - 1)) ||
        (q->text_end & (PAGE - 1)) || (q->ro_end & (PAGE - 1)) ||
        (q->image_end & (PAGE - 1)) ||
        !(q->image < q->text_end && q->text_end <= q->ro_end &&
          q->ro_end < q->image_end) ||
        (q->table_base & (PAGE - 1)) || q->table_base < q->ro_end ||
        q->image_end > limit || q->table_base > q->image_end ||
        PROBE_PT_PAGES * PAGE > q->image_end - q->table_base ||
        q->dtb_size > 2 * 1024 * 1024 || q->fb_size > 64 * 1024 * 1024)
        return 0;
    struct range ranges[5];
    if (!span(q->image, q->text_end - q->image, limit, NORMAL | RO, &ranges[0]) ||
        !span(q->ro_end, q->image_end - q->ro_end, limit, NORMAL | PXN, &ranges[2]) ||
        !span(q->dtb, q->dtb_size, limit, NORMAL | RO | PXN, &ranges[3]) ||
        !span(q->fb, q->fb_size, limit, DEVICE, &ranges[4]))
        return 0;
    ranges[1].begin = ranges[1].end = q->text_end;
    ranges[1].attrs = NORMAL | RO | PXN;
    if (q->ro_end != q->text_end &&
        !span(q->text_end, q->ro_end - q->text_end, limit,
              NORMAL | RO | PXN, &ranges[1]))
        return 0;
    /* Check page-rounded bounds, not just byte ranges. A page cannot be both
     * normal code/data and device memory, or both RW and RO. */
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < i; j++)
            if (ranges[i].begin < ranges[j].end && ranges[j].begin < ranges[i].end)
                return 0;
    volatile uint64_t *zero = pool;
    for (unsigned i = 0; i < PROBE_PT_PAGES * 512; i++)
        zero[i] = 0;
    physical_base = q->table_base;
    used = 1;
    mapped = 0;
    for (int i = 0; i < 5; i++)
        for (uint64_t va = ranges[i].begin; va < ranges[i].end; va += PAGE)
            if (!map_page(va, ranges[i].attrs))
                return 0;
    r->root = physical_base;
    /* 48-bit TTBR0 VA, 4 KiB, noncacheable walks, TTBR1 disabled, native IPS. */
    r->tcr = 16ULL | (3ULL << 12) | (16ULL << 16) | (1ULL << 23) |
             (2ULL << 30) | ((uint64_t)pa << 32);
    r->mair = 0x0044;                   /* Attr0 normal NC, Attr1 Device-nGnRnE */
    r->tables = used;
    r->pages = mapped;
    return 1;
}
