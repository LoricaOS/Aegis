/* Add only the real kernel's higher-half mappings to the proven low entry
 * map. All tables and the padded kernel footprint belong to the loaded Image.
 * No RAM admission, allocator, peripheral discovery or firmware calls. */
#include "kernel_handoff.h"
#include "probe_mmu.h"
#include "probe_console.h"
#include "kernel_layout.h"
#include "qr_report.h"

#define PAGE 4096ULL
#define MASK 0x0000fffffffff000ULL
#define PT_PAGES 16
#define AF (1ULL << 10)
#define RO (1ULL << 7)
#define XN ((1ULL << 53) | (1ULL << 54))
#define WB (AF | (3ULL << 8) | (2ULL << 2) | (1ULL << 54))

extern const uint8_t apple_kernel_blob[] __attribute__((visibility("hidden")));
extern const uint8_t apple_kernel_blob_end[] __attribute__((visibility("hidden")));
static uint64_t tables[PT_PAGES][512] __attribute__((aligned(4096)));
static struct apple_kernel_handoff handoff;
static unsigned used;
#ifdef APPLE_MEMORY_CHECKPOINT
/* Included in loader image_size, not the kernel ELF or arbitrary DTB RAM. */
static uint8_t memory_arena[APPLE_BOOT_ARENA_SIZE] __attribute__((aligned(4096)));
#endif

static __attribute__((noreturn)) void refused(void)
{
    probe_puts("HALTED - REAL KERNEL BRIDGE REFUSED\n");
    apple_qr_progress("bridge-refused", 0);
    for (;;) __asm__ volatile("wfe");
}

static int page(uint64_t va, uint64_t pa, uint64_t attrs)
{
    uint64_t *table = tables[0];
    uint64_t base = (uintptr_t)tables;
    for (unsigned level = 0; level < 3; level++) {
        unsigned slot = (va >> (39 - level * 9)) & 511;
        if (!table[slot]) {
            if (used == PT_PAGES) return 0;
            table[slot] = (base + used++ * PAGE) | 3;
        }
        uint64_t child = table[slot] & MASK;
        if ((table[slot] & 3) != 3 || child < base || child >= base + used * PAGE)
            return 0;
        table = tables[(child - base) / PAGE];
    }
    unsigned slot = (va >> 12) & 511;
    if (table[slot]) return 0;
    table[slot] = pa | attrs | 3;
    return 1;
}

static uint64_t *identity_leaf(const struct probe_map_request *q, uint64_t address)
{
    uint64_t root;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(root));
    if (root != q->table_base) return 0;
    uint64_t *table = (uint64_t *)(uintptr_t)root;
    for (unsigned level = 0; level < 3; level++) {
        uint64_t descriptor = table[(address >> (39 - 9 * level)) & 511];
        uint64_t child = descriptor & MASK;
        if ((descriptor & 3) != 3 || child < q->table_base ||
            child >= q->table_base + PROBE_PT_PAGES * PAGE)
            return 0;
        table = (uint64_t *)(uintptr_t)child;
    }
    return &table[(address >> 12) & 511];
}

static int remove_blob_identity(const struct probe_map_request *q, uint64_t physical)
{
    for (uint64_t address = physical; address < physical + KERNEL_SIZE; address += PAGE) {
        uint64_t *leaf = identity_leaf(q, address);
        uint64_t expected = address | AF | (3ULL << 8) | RO | XN | 3;
        if (!leaf || *leaf != expected) return 0;
        *leaf = 0;
    }
    return 1;
}

#ifdef APPLE_MEMORY_CHECKPOINT
static int map_owned_arena(const struct probe_map_request *q)
{
    uint64_t base = (uintptr_t)memory_arena;
    if (base < q->ro_end || base > q->image_end ||
        APPLE_BOOT_ARENA_SIZE > q->image_end - base) return 0;
    for (uint64_t off = 0; off < APPLE_BOOT_ARENA_SIZE; off += PAGE) {
        uint64_t *leaf = identity_leaf(q, base + off);
        uint64_t expected = (base + off) | AF | (3ULL << 8) | XN | 3;
        if (!leaf || *leaf != expected) return 0;
        *leaf = 0;
    }
    /* Break before changing the arena from NC to WB. Nothing touches the
     * arena between this break and installation; caches are still off. */
    __asm__ volatile("dsb ishst\ntlbi vmalle1\ndsb ish\nisb" ::: "memory");
    for (uint64_t off = 0; off < APPLE_BOOT_ARENA_SIZE; off += PAGE) {
        uint64_t *leaf = identity_leaf(q, base + off);
        if (!leaf || *leaf) return 0;
        *leaf = (base + off) | WB | XN | 3;
    }
    handoff.loader_phys = q->image;
    handoff.loader_size = q->image_end - q->image;
    handoff.arena = base;
    handoff.arena_size = APPLE_BOOT_ARENA_SIZE;
    apple_qr_memory[0] = base;
    apple_qr_memory[1] = APPLE_BOOT_ARENA_SIZE;
    return 1;
}
#endif

__attribute__((noreturn))
void apple_kernel_bridge(const struct probe_map_request *q, uint64_t tcr)
{
    uint64_t physical = (uintptr_t)apple_kernel_blob;
    uint64_t sctlr, ctr, mair;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    __asm__ volatile("mrs %0, mair_el1" : "=r"(mair));
    uint64_t line = 4ULL << ((ctr >> 16) & 15);
    if ((physical & (PAGE - 1)) ||
        (sctlr & 0x1005) != 1 || mair != 0x44 || line < 16 || line > 2048 ||
        (uint64_t)(apple_kernel_blob_end - apple_kernel_blob) != KERNEL_SIZE ||
        physical < q->text_end || physical > q->ro_end ||
        KERNEL_SIZE > q->ro_end - physical ||
        !(KERNEL_TEXT_SIZE <= KERNEL_RO_SIZE && KERNEL_RO_SIZE < KERNEL_SIZE) ||
        !fdt_boot_framebuffer(&handoff.fb))
        refused();
    used = 1; /* zeroed table pool belongs to the freshly loaded Image */
    for (uint64_t off = 0; off < KERNEL_SIZE; off += PAGE) {
        uint64_t attrs = off < KERNEL_TEXT_SIZE ? WB | RO :
                         off < KERNEL_RO_SIZE ? WB | RO | XN : WB | XN;
        if (!page(KERNEL_BASE + off, physical + off, attrs)) refused();
    }
    handoff.magic = APPLE_KERNEL_HANDOFF_MAGIC;
    handoff.kernel_phys = physical;
    handoff.kernel_size = KERNEL_SIZE;
    handoff.dtb = q->dtb;
    handoff.dtb_size = q->dtb_size;
#ifdef APPLE_TIMER_CHECKPOINT
    handoff.timer_hcr = apple_timer_el2_state[0];
    handoff.timer_gate_before = apple_timer_el2_state[1];
    handoff.timer_gate_after = apple_timer_el2_state[2];
    handoff.timer_cnthctl = apple_timer_el2_state[3];
    for (unsigned i = 0; i < 4; i++) apple_qr_timer[i + 4] = apple_timer_el2_state[i];
#endif
    probe_puts("ENTERING REAL HIGHER-HALF AEGIS KERNEL\n");
    probe_field("KERNEL PHYSICAL", physical);
    probe_field("KERNEL ENTRY", KERNEL_ENTRY);
    apple_qr_progress("bridge-before-cache", 0);
    /* No NC/WB aliases: discard the low RO/XN blob mapping before exposing
     * the WB high mapping. The blob is not accessed through its low address
     * again. Loader code, tables, handoff and stack stay NC; FB stays Device. */
    if (!remove_blob_identity(q, physical)) refused();
#ifdef APPLE_MEMORY_CHECKPOINT
    if (!map_owned_arena(q)) refused();
#endif
    apple_qr_progress("bridge-alias-cleared", 0);
    __asm__ volatile("dsb sy\nmsr mair_el1, %2\nmsr ttbr1_el1, %0\nmsr tcr_el1, %1\nisb\n"
                     "tlbi vmalle1\ndsb sy\nisb"
                     : : "r"((uint64_t)(uintptr_t)tables), "r"(tcr & ~(1ULL << 23)),
                         "r"(mair | (0xffULL << 16))
                     : "memory");
    apple_qr_progress("bridge-high-map-ready", 0);
    /* The native m1n1 handoff cleaned/invalidated caches on shutdown; all
     * subsequent loader stores were uncached. Clean/invalidate stale copies
     * of this owned span and complete NC stores before C=1. CIVAC is valid
     * through RO code mappings; IVAC would require write permission.
     * No set/way operations or maintenance on firmware/device memory. */
    for (uint64_t off = 0; off < KERNEL_SIZE; off += line)
        __asm__ volatile("dc civac, %0" : : "r"(KERNEL_BASE + off) : "memory");
#ifdef APPLE_MEMORY_CHECKPOINT
    for (uint64_t off = 0; off < APPLE_BOOT_ARENA_SIZE; off += line)
        __asm__ volatile("dc civac, %0" : : "r"((uintptr_t)memory_arena + off) : "memory");
#endif
    apple_qr_progress("bridge-lines-invalidated", 0);
    __asm__ volatile("dsb sy\nmsr sctlr_el1, %0\nisb"
                     : : "r"(sctlr | 4ULL) : "memory");
    probe_puts("KERNEL DATA CACHE ON - LOW BLOB ALIAS REMOVED\n");
    apple_qr_progress("bridge-before-kernel", 0);
    ((void (*)(const struct apple_kernel_handoff *))(uintptr_t)KERNEL_ENTRY)(&handoff);
    refused();
}
