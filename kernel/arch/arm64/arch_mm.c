/*
 * arch_mm.c — arm64 boot memory info. Limine-only: arch_mm_ingest()
 * (called from kernel_main_limine before anything else) adopts the
 * bootinfo; there is no legacy tag parser here.
 */

#include "arch.h"
#include "fb.h"
#include "printk.h"
#include "bootinfo.h"
#include "fdt.h"
#include <stdint.h>
#include <stddef.h>

#define MAX_REGIONS 32

static aegis_mem_region_t regions[MAX_REGIONS];
static uint32_t           region_count;
static uint64_t           s_kern_phys_slide;
static uint64_t           s_early_pv_off;
static uint64_t           s_rsdp_phys;
static uint64_t           s_dtb_phys;
static arch_fb_info_t     s_fb_info;
static uint64_t           s_module_phys, s_module_size;
static uint64_t           s_module2_phys, s_module2_size;
static char               s_cmdline[256];
static uint64_t           s_uart_phys = 0x09000000UL;   /* QEMU virt PL011 default */

/* Reserved: module ranges (reserved at pmm_init, reclaimed by main.c
 * after the ramdisk copy — same lifecycle as x86). Slots filled by
 * ingest; len==0 entries are no-ops. */
static aegis_mem_region_t arm64_reserved[2];

void
arch_mm_ingest(const struct aegis_bootinfo *bi)
{
    s_kern_phys_slide = bi->kern_phys_slide;
    s_early_pv_off    = bi->hhdm_offset;
    s_rsdp_phys       = bi->rsdp_phys;
    s_dtb_phys        = bi->dtb_phys;

    for (uint32_t i = 0; i < bi->usable_count && region_count < MAX_REGIONS; i++) {
        regions[region_count].base = bi->usable[i].base;
        regions[region_count].len  = bi->usable[i].len;
        region_count++;
    }

    uint32_t ci;
    for (ci = 0; ci < sizeof(s_cmdline) - 1 && bi->cmdline[ci]; ci++)
        s_cmdline[ci] = bi->cmdline[ci];
    s_cmdline[ci] = '\0';

    /* Modules: reserve now, count as usable so the post-copy
     * pmm_unreserve_region reclaim genuinely frees them (see the x86
     * arch_mm_ingest comment for the full rationale). */
    s_module_phys = bi->module[0].phys;
    s_module_size = bi->module[0].size;
    if (s_module_size) {
        arm64_reserved[0].base = s_module_phys & ~0xFFFUL;
        arm64_reserved[0].len  = ((s_module_phys + s_module_size + 0xFFF) & ~0xFFFUL)
                                 - arm64_reserved[0].base;
        if (region_count < MAX_REGIONS) {
            regions[region_count] = arm64_reserved[0];
            region_count++;
        }
    }
    s_module2_phys = bi->module[1].phys;
    s_module2_size = bi->module[1].size;
    if (s_module2_size) {
        arm64_reserved[1].base = s_module2_phys & ~0xFFFUL;
        arm64_reserved[1].len  = ((s_module2_phys + s_module2_size + 0xFFF) & ~0xFFFUL)
                                 - arm64_reserved[1].base;
        if (region_count < MAX_REGIONS) {
            regions[region_count] = arm64_reserved[1];
            region_count++;
        }
    }

    /* Framebuffer (32-bpp RGB only, sanitized like the x86 ingest). */
    {
        uint64_t w = bi->fb.width, h = bi->fb.height;
        uint64_t pitch = bi->fb.pitch, addr = bi->fb.addr_phys;
        if (bi->fb.bpp == 32 &&
            w && w <= FB_MAX_WIDTH && h && h <= FB_MAX_HEIGHT &&
            pitch && pitch <= FB_MAX_PITCH && pitch >= w * 4u &&
            addr && pitch * h <= UINT64_MAX - addr) {
            s_fb_info.addr   = addr;
            s_fb_info.pitch  = (uint32_t)pitch;
            s_fb_info.width  = (uint32_t)w;
            s_fb_info.height = (uint32_t)h;
            s_fb_info.bpp    = 32;
            s_fb_info.type   = 1;
        }
    }
}

void arch_mm_init(void *info) { (void)info; }

uint32_t arch_mm_region_count(void)                    { return region_count; }
const aegis_mem_region_t *arch_mm_get_regions(void)    { return regions; }

uint32_t arch_mm_reserved_region_count(void)
{
    return sizeof(arm64_reserved) / sizeof(arm64_reserved[0]);
}

const aegis_mem_region_t *arch_mm_get_reserved_regions(void)
{
    return arm64_reserved;
}

uint64_t arch_get_rsdp_phys(void)      { return s_rsdp_phys; }
uint64_t arch_get_dtb_phys(void)       { return s_dtb_phys; }
uint64_t arch_kern_phys_slide(void)    { return s_kern_phys_slide; }
uint64_t arch_early_pv_off(void)       { return s_early_pv_off; }
const char *arch_get_cmdline(void)     { return s_cmdline; }

int
arch_get_fb_info(arch_fb_info_t *out)
{
    if (!out || s_fb_info.addr == 0) return 0;
    *out = s_fb_info;
    return 1;
}

int
arch_get_module(uint64_t *phys_out, uint64_t *size_out)
{
    if (s_module_phys == 0 || s_module_size == 0)
        return 0;
    *phys_out = s_module_phys;
    *size_out = s_module_size;
    return 1;
}

int
arch_get_module2(uint64_t *phys_out, uint64_t *size_out)
{
    if (s_module2_phys == 0 || s_module2_size == 0)
        return 0;
    *phys_out = s_module2_phys;
    *size_out = s_module2_size;
    return 1;
}

uint64_t arch_mm_get_uart_phys(void) { return s_uart_phys; }

/* Native (non-Limine) boot path -- see arch.h. Mirrors arch_mm_ingest()'s
 * role but with no aegis_bootinfo_t to read: no bootloader memory map, no
 * HHDM. Real hardware address confirmed via this session's own
 * native-boot bring-up (see rpi5-port-research memory) -- not yet DTB-
 * derived (would need fdt_reg_by_compat("arm,pl011", ...) called after
 * fdt_init(), same chicken-and-egg as the memory regions below; hardcoded
 * for now since this is the only board this path targets). */
void
arch_mm_init_native(uint64_t dtb_phys)
{
    s_kern_phys_slide = 0;              /* fixed load address, see linker script */
    s_early_pv_off    = 0;              /* identity-mapped (VA==PA), no HHDM     */
    s_rsdp_phys       = 0;              /* no ACPI on arm64                      */
    s_dtb_phys        = dtb_phys;
    s_cmdline[0]      = '\0';           /* no cmdline source on this path yet    */
    s_uart_phys       = 0x107D001000UL; /* real Pi 5 PL011 (block index 65)      */
}

/* Called after fdt_init() has captured the tree. No-op if Limine already
 * populated regions[] at ingest time (region_count > 0) -- this is purely
 * the native path's memory-map source, since it gets no bootinfo usable[]
 * list. Real Pi 5 RAM is "highly fragmented multi-region" per prior DTB
 * research -- MAX_REGIONS (32) comfortably covers what was seen there.
 *
 * Excludes PA[0, ARCH_KERNEL_PHYS_BASE) from whatever the DTB reports as
 * usable. Two independent reasons, found together during this session's
 * native-boot bring-up (see rpi5-port-research memory):
 *   1. This SoC's real DTB has a /reserved-memory/atf@0 node covering
 *      PA[0, 0x80000) (TF-A's own live memory, `no-map`) that this
 *      simple device_type="memory"-only walk doesn't know to exclude --
 *      allocating into it would corrupt running secure firmware.
 *   2. pmm_alloc_page() treats a returned physical address of exactly 0
 *      as its OOM sentinel ("always reserved" on Limine/x86, where page 0
 *      genuinely is pre-reserved by convention) -- on this path nothing
 *      reserved it, so the very first allocation legitimately returned
 *      PA 0 and was misread as out-of-memory. Excluding this range keeps
 *      page 0 unavailable here too, restoring that invariant, without
 *      touching pmm.c's shared sentinel convention.
 * A real /reserved-memory walk (there are other, smaller entries: cma,
 * nvram@0/1) is a good follow-up but not required to fix either of the
 * above -- both are inside this one excluded range. */
void
arch_mm_populate_regions_from_dtb(void)
{
    if (region_count > 0)
        return;

    uint64_t addrs[MAX_REGIONS], sizes[MAX_REGIONS];
    int n = fdt_memory_regions(addrs, sizes, MAX_REGIONS);
    for (int i = 0; i < n && region_count < MAX_REGIONS; i++) {
        uint64_t base = addrs[i];
        uint64_t size = sizes[i];
        if (base < ARCH_KERNEL_PHYS_BASE) {
            uint64_t cut = ARCH_KERNEL_PHYS_BASE - base;
            if (cut >= size)
                continue;               /* entirely within the excluded range */
            base = ARCH_KERNEL_PHYS_BASE;
            size -= cut;
        }
        if (size == 0)
            continue;
        regions[region_count].base = base;
        regions[region_count].len  = size;
        region_count++;
    }

    /* Firmware-loaded initramfs (config.txt `initramfs <file> ...`): the Pi
     * EEPROM records its RAM range in /chosen. Expose it as module[0] so the
     * existing ramdisk0 root-mount path picks it up, and reserve its pages
     * (they're inside the usable RAM regions above) so the PMM won't hand
     * them out before ramdisk_init copies/claims them. Mirrors the Limine
     * ingest's module[0] handling; main.c reclaims them via
     * pmm_unreserve_region after ramdisk_init, same as the Limine path. */
    {
        uint64_t istart = 0, iend = 0;
        if (fdt_initrd(&istart, &iend) && iend > istart) {
            s_module_phys = istart;
            s_module_size = iend - istart;
            arm64_reserved[0].base = istart & ~0xFFFUL;
            arm64_reserved[0].len  = ((iend + 0xFFF) & ~0xFFFUL) - arm64_reserved[0].base;
            if (region_count < MAX_REGIONS) {
                regions[region_count] = arm64_reserved[0];
                region_count++;
            }
        }
    }
}
