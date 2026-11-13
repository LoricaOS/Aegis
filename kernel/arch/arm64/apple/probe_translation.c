#ifdef APPLE_PROBE_TRANSLATION
/*
 * Deliberately separate from shared kernel VM initialization: establish
 * EL1 and a tiny NC/device identity map before an allocator or interrupts.
 */
#include "probe_mmu.h"
#include "probe_console.h"
#include "probe_report.h"
#ifdef APPLE_KERNEL_BRIDGE
#include "qr_report.h"
#endif

extern char apple_probe_start[] __attribute__((visibility("hidden")));
extern void apple_probe_enter_el1(void) __attribute__((noreturn));

volatile struct {
    uint64_t incoming_el, current_el, hcr_before, sctlr_before, sctlr_after;
    uint64_t root, tcr, mair, tables, pages;
    uint64_t code_read, code_write, data_write, dtb_read, dtb_write, fb_write, zero_read;
    uint64_t success;
} apple_probe_translation_report;

static struct probe_map_request request;

static __attribute__((noreturn)) void stop(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) __asm__ volatile("wfe");
}

static uint64_t translate(uint64_t address, int write)
{
    uint64_t par;
    if (write)
        __asm__ volatile("at s1e1w, %1\nisb\nmrs %0, par_el1"
                         : "=r"(par) : "r"(address) : "memory");
    else
        __asm__ volatile("at s1e1r, %1\nisb\nmrs %0, par_el1"
                         : "=r"(par) : "r"(address) : "memory");
    return par;
}

static int identity(uint64_t par, uint64_t address)
{
    return !(par & 1) && (par & 0x0000fffffffff000ULL) == (address & ~4095ULL);
}

void apple_probe_el1_continue(void) __attribute__((noreturn));
void apple_probe_el1_continue(void)
{
    uint64_t el, sctlr;
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(el));
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    apple_probe_translation_report.current_el = el >> 2;
    apple_probe_translation_report.sctlr_before = sctlr;
    if (el != 4 || (sctlr & 5)) {
        probe_puts("HALTED - EL1/OFF CONTRACT FAILED\n");
        stop();
    }
    apple_probe_report.stage = 6;
    probe_puts("EL1 READY - DAIF STILL MASKED\n");
#ifdef APPLE_KERNEL_BRIDGE
    apple_qr_progress("bridge-el1", 0);
#endif
    probe_field("EL1 SCTLR BEFORE", sctlr);
    struct probe_map_result map;
    if (!probe_map_build(&request, &map)) {
        probe_puts("HALTED - MAPPING REQUEST REFUSED\n");
        stop();
    }
    apple_probe_translation_report.root = map.root;
    apple_probe_translation_report.tcr = map.tcr;
    apple_probe_translation_report.mair = map.mair;
    apple_probe_translation_report.tables = map.tables;
    apple_probe_translation_report.pages = map.pages;
    probe_field("ROOT", map.root);
    probe_field("TABLE PAGES", map.tables);
    probe_field("MAPPED PAGES", map.pages);
    probe_field("TCR", map.tcr);
    probe_puts("ENABLING 4K IDENTITY MAP - CACHES OFF\n");
    apple_probe_report.stage = 7;
    /* The pool was written with data cache off. Noncacheable walks and
     * normal-NC image data avoid a cacheable alias across this experiment. */
    sctlr &= ~((1ULL << 12) | 4ULL);
    __asm__ volatile("msr sctlr_el1, %0\nisb\nic iallu\ndsb sy\nisb"
                     : : "r"(sctlr) : "memory");
    __asm__ volatile("dsb sy\nmsr mair_el1, %0\nmsr tcr_el1, %1\n"
                     "msr ttbr0_el1, %2\nmsr ttbr1_el1, xzr\nisb\n"
                     "tlbi vmalle1\ndsb sy\nisb"
                     : : "r"(map.mair), "r"(map.tcr), "r"(map.root) : "memory");
    sctlr |= 1;
    __asm__ volatile("msr sctlr_el1, %0\nisb" : : "r"(sctlr) : "memory");
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    apple_probe_translation_report.sctlr_after = sctlr;
    uint64_t actual_root, actual_tcr, actual_mair;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(actual_root));
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(actual_tcr));
    __asm__ volatile("mrs %0, mair_el1" : "=r"(actual_mair));
    apple_probe_translation_report.root = actual_root;
    apple_probe_translation_report.tcr = actual_tcr;
    apple_probe_translation_report.mair = actual_mair;
    uint64_t code_r = translate(request.image, 0);
    uint64_t code_w = translate(request.image, 1);
    uint64_t data_w = translate(request.table_base, 1);
    uint64_t dtb_r = translate(request.dtb, 0);
    uint64_t dtb_w = translate(request.dtb, 1);
    uint64_t fb_w = translate(request.fb, 1);
    uint64_t zero_r = translate(0, 0);
    apple_probe_translation_report.code_read = code_r;
    apple_probe_translation_report.code_write = code_w;
    apple_probe_translation_report.data_write = data_w;
    apple_probe_translation_report.dtb_read = dtb_r;
    apple_probe_translation_report.dtb_write = dtb_w;
    apple_probe_translation_report.fb_write = fb_w;
    apple_probe_translation_report.zero_read = zero_r;
    probe_field("EL1 SCTLR AFTER", sctlr);
    probe_field("ROOT AFTER", actual_root);
    probe_field("TCR AFTER", actual_tcr);
    probe_field("MAIR AFTER", actual_mair);
    probe_field("CODE READ PAR", code_r);
    probe_field("CODE WRITE PAR", code_w);
    probe_field("DATA WRITE PAR", data_w);
    probe_field("DTB READ PAR", dtb_r);
    probe_field("DTB WRITE PAR", dtb_w);
    probe_field("FB WRITE PAR", fb_w);
    probe_field("ZERO READ PAR", zero_r);
    int good = (sctlr & 0x1005) == 1 && actual_root == map.root &&
               actual_tcr == map.tcr && actual_mair == map.mair &&
               identity(code_r, request.image) &&
               (code_w & 1) && identity(data_w, request.table_base) &&
               identity(dtb_r, request.dtb) && (dtb_w & 1) &&
               identity(fb_w, request.fb) && (zero_r & 1);
    if (!good) {
        probe_puts("HALTED - TRANSLATION SELF-CHECK FAILED\n");
        stop();
    }
    probe_puts("PASS - EL1 / 4K / RO CODE AND DTB\n");
    probe_puts("PASS - ZERO VA UNMAPPED\n");
    probe_puts("NO ALLOCATOR - RESERVATIONS NOT RECLAIMED\n");
#ifdef APPLE_KERNEL_BRIDGE
    probe_puts("LOW MAP VERIFIED - NEXT: KERNEL BRIDGE\n");
#else
    probe_puts("HALTED - MMU ON / CACHES OFF / DAIF MASKED\n");
#endif
    __asm__ volatile("dsb sy" ::: "memory");
    apple_probe_translation_report.success = 1;
    apple_probe_report.stage = 8;
#ifdef APPLE_KERNEL_BRIDGE
    apple_qr_progress("bridge-map-ready", 0);
    extern void apple_kernel_bridge(const struct probe_map_request *, uint64_t)
        __attribute__((noreturn));
    apple_kernel_bridge(&request, map.tcr);
#endif
#ifdef APPLE_PROBE_MEMORY
    extern void apple_probe_memory_begin(const struct probe_map_request *);
    apple_probe_memory_begin(&request);
#endif
#if defined(APPLE_PROBE_TRANSLATION_FAULT_TEST) && APPLE_PROBE_TRANSLATION_FAULT_TEST == 1
    __asm__ volatile("mov x9, #0\n"
                     ".global apple_probe_translation_fault\n"
                     "apple_probe_translation_fault:\n"
                     "ldr xzr, [x9]" : : : "x9", "memory");
#elif defined(APPLE_PROBE_TRANSLATION_FAULT_TEST) && APPLE_PROBE_TRANSLATION_FAULT_TEST == 2
    __asm__ volatile("br %0" : : "r"(request.table_base) : "memory");
#endif
    stop();
}

void apple_probe_translation_begin(const struct probe_map_request *q, uint64_t incoming_el)
{
    request = *q;
    apple_probe_translation_report.incoming_el = incoming_el;
    probe_console_reset();
#ifdef APPLE_KERNEL_BRIDGE
    probe_puts("APPLE BRIDGE - EL1 / BOUNDED 4K MAPPING\n");
#else
    probe_puts("AEGIS V3 - EL1 / BOUNDED 4K TRANSLATION\n");
#endif
    probe_field("INCOMING EL", incoming_el);
    if (incoming_el == 2) {
        uint64_t hcr;
        __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
        apple_probe_translation_report.hcr_before = hcr;
        probe_field("HCR BEFORE", hcr);
        probe_puts("ENTERING CONTROLLED EL1 STATE\n");
        __asm__ volatile("dsb sy" ::: "memory");
        apple_probe_enter_el1();
    }
    apple_probe_el1_continue();
}
#endif
