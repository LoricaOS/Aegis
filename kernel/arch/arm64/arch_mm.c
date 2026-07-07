/*
 * arch_mm.c — arm64 boot memory info. Limine-only: arch_mm_ingest()
 * (called from kernel_main_limine before anything else) adopts the
 * bootinfo; there is no legacy tag parser here.
 */

#include "arch.h"
#include "fb.h"
#include "printk.h"
#include "bootinfo.h"
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
