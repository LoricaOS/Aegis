/*
 * Entry diagnostic: validate identity/simplefb, show the CPU and memory
 * handoff, then halt. No allocation, UART, interrupts, DMA or disk.
 * This deliberately does not call the QEMU/Pi 5 platform initialization.
 */
#include "../fdt.h"
#include <stdint.h>
#include <stddef.h>
#include "probe_console.h"
#include "probe_mmu.h"
#include "probe_report.h"
#ifdef APPLE_KERNEL_BRIDGE
#include "qr_report.h"
#endif

extern char apple_probe_start[] __attribute__((visibility("hidden")));
extern char apple_probe_end[] __attribute__((visibility("hidden")));
uint32_t fdt_ingest(const uint8_t *src, uint32_t avail);

/* Inspectable with a debugger even when no supported framebuffer exists. */
volatile struct apple_probe_boot_report apple_probe_report;

volatile uint64_t apple_probe_fault_active;
volatile struct {
    uint64_t valid, vector, el, esr, elr, far, spsr, sp, boot_stage;
} apple_probe_fault_report;

__attribute__((noreturn))
void apple_probe_exception(uint64_t vector, uint64_t esr, uint64_t elr,
                           uint64_t far, uint64_t spsr, uint64_t sp, uint64_t el)
{
    apple_probe_fault_report.vector = vector;
    apple_probe_fault_report.el = el;
    apple_probe_fault_report.esr = esr;
    apple_probe_fault_report.elr = elr;
    apple_probe_fault_report.far = far;
    apple_probe_fault_report.spsr = spsr;
    apple_probe_fault_report.sp = sp;
    apple_probe_fault_report.boot_stage = apple_probe_report.stage;
    probe_console_fault();
    probe_puts("AEGIS FATAL EXCEPTION\n");
    probe_field("VECTOR", vector);
    probe_field("EL", el);
    probe_field("ESR", esr);
    probe_field("EC", (esr >> 26) & 63);
    probe_field("ELR", elr);
    probe_field("FAR", far);
    probe_puts("FAR MAY BE STALE FOR NON-ADDRESS FAULTS\n");
    probe_field("SPSR", spsr);
    probe_field("SP", sp);
    probe_field("BOOT STAGE", apple_probe_fault_report.boot_stage);
    probe_puts("HALTED - NO EXCEPTION RETURN\n");
#ifdef APPLE_KERNEL_BRIDGE
    apple_qr_progress("bridge-fault", 0);
#endif
    __asm__ volatile("dsb sy" ::: "memory");
    apple_probe_fault_report.valid = 1;
    apple_probe_report.stage = 255;
    for (;;) __asm__ volatile("wfe");
}

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

static int overlaps(uint64_t a, uint64_t n, uint64_t b, uint64_t m)
{
    return a < b + m && b < a + n;
}

void apple_probe_main(const uint8_t *dtb, uint64_t el, uint64_t sctlr)
{
    apple_probe_report.stage = 1;
    apple_probe_report.el = el >> 2;
    apple_probe_report.sctlr = sctlr;
    apple_probe_report.dtb = (uintptr_t)dtb;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(apple_probe_report.mmfr0));
    if (!dtb || ((uintptr_t)dtb & 7) || be32(dtb) != 0xd00dfeed)
        return;
    uint32_t size = be32(dtb + 4);
    if (size < 40 || size > 2 * 1024 * 1024 ||
        (uintptr_t)dtb > UINT64_MAX - size || !fdt_ingest(dtb, size))
        return;
    apple_probe_report.stage = 2;
    if (!fdt_root_compatible("apple,j514s") ||
        !fdt_root_compatible("apple,t6030"))
        return;
    apple_probe_report.stage = 3;
    struct fdt_bootfb fb;
    if (!fdt_boot_framebuffer(&fb))
        return;
    uint64_t image = (uintptr_t)apple_probe_start;
    uint64_t image_size = (uintptr_t)apple_probe_end - image;
    if (overlaps(fb.base, fb.size, image, image_size) ||
        overlaps(fb.base, fb.size, (uintptr_t)dtb, size) ||
        fb.width < 240 || fb.height < 120)
        return;
    apple_probe_report.stage = 4;
    probe_console_init(&fb);
#ifdef APPLE_KERNEL_BRIDGE
    probe_puts("AEGIS APPLE KERNEL BRIDGE - PREPARING EL1\n");
    apple_qr_progress("bridge-entry", 0);
#elif defined(APPLE_PROBE_MEMORY)
    probe_puts("AEGIS NATIVE ENTRY DIAGNOSTIC V4\n");
#elif defined(APPLE_PROBE_TRANSLATION)
    probe_puts("AEGIS NATIVE ENTRY DIAGNOSTIC V3\n");
#else
    probe_puts("AEGIS NATIVE ENTRY DIAGNOSTIC V2\n");
#endif
#ifdef APPLE_KERNEL_BRIDGE
    probe_puts("J514S / T6030 - LOADER STAGE\n");
#else
    probe_puts("J514S / T6030 - NOT THE FULL KERNEL\n");
#endif
    probe_field("EL", apple_probe_report.el);
    probe_field("SCTLR", sctlr);
    probe_field("MMFR0", apple_probe_report.mmfr0);
    probe_field("TGRAN4 RAW", (apple_probe_report.mmfr0 >> 28) & 15);
    probe_field("TGRAN16 RAW", (apple_probe_report.mmfr0 >> 20) & 15);
    probe_field("TGRAN64 RAW", (apple_probe_report.mmfr0 >> 24) & 15);
    probe_puts("RAW FIELDS - NO PAGE SIZE SELECTED\n");
    apple_probe_report.image = image;
    apple_probe_report.image_size = image_size;
    apple_probe_report.dtb_size = size;
    probe_field("IMAGE", image);
    probe_field("IMAGE SIZE", image_size);
    probe_field("DTB", (uintptr_t)dtb);
    probe_field("DTB SIZE", size);
    probe_field("FB BASE", fb.base);
    probe_field("FB STRIDE", fb.stride);
    probe_field("FB WIDTH", fb.width);
    probe_field("FB HEIGHT", fb.height);
    probe_puts(fb.format == FDT_FB_XRGB2101010 ?
               "FB FORMAT=X2R10G10B10\n" : "FB FORMAT=X8R8G8B8\n");
    probe_puts("RAM BANKS BELOW ARE NOT FREE-MEMORY RANGES\n");
    uint64_t base[17], length[17];
    int count = fdt_memory_regions(base, length, 17);
    apple_probe_report.memory_count = (uint64_t)count;
    for (int i = 0; i < count; i++) {
        apple_probe_report.memory_base[i] = base[i];
        apple_probe_report.memory_size[i] = length[i];
        if (i >= 16) {
            probe_puts("RAM LIST TRUNCATED\n");
            break;
        }
        probe_puts("RAM ");
        probe_hex(base[i]);
        probe_puts(" SIZE ");
        probe_hex(length[i]);
        probe_puts("\n");
    }
    probe_puts("RESERVATIONS NOT RECLAIMED - NO ALLOCATOR\n");
#ifdef APPLE_PROBE_TRANSLATION
    probe_puts("ENTRY CAPTURED - PREPARING EL1\n");
#else
    probe_puts("HALTED - MMU OFF / DAIF MASKED\n");
#endif
    __asm__ volatile("dsb sy" ::: "memory");
    apple_probe_report.stage = 5;
#if defined(APPLE_PROBE_FAULT_TEST) && APPLE_PROBE_FAULT_TEST == 1
    __asm__ volatile(".global apple_probe_test_fault\n"
                     "apple_probe_test_fault:\n"
                     "brk #0x41");
#elif defined(APPLE_PROBE_FAULT_TEST) && APPLE_PROBE_FAULT_TEST == 2
    __asm__ volatile(".global apple_probe_test_fault\n"
                     "apple_probe_test_fault:\n"
                     "ldr xzr, [%0]" : : "r"(UINT64_MAX - 4095) : "memory");
#elif defined(APPLE_PROBE_FAULT_TEST) && APPLE_PROBE_FAULT_TEST == 3
    __asm__ volatile("mov x9, #0\n"
                     "mov sp, x9\n"
                     ".global apple_probe_test_fault\n"
                     "apple_probe_test_fault:\n"
                     "brk #0x43" : : : "x9", "memory");
#endif
#ifdef APPLE_PROBE_TRANSLATION
    extern char apple_probe_text_end[] __attribute__((visibility("hidden")));
    extern char apple_probe_ro_end[] __attribute__((visibility("hidden")));
    struct probe_map_request q = {
        image, (uintptr_t)apple_probe_text_end, (uintptr_t)apple_probe_ro_end,
        (uintptr_t)apple_probe_end, (uintptr_t)dtb, size, fb.base, fb.size,
        apple_probe_report.mmfr0, (uintptr_t)probe_map_pool()
    };
    apple_probe_translation_begin(&q, apple_probe_report.el);
#endif
}
