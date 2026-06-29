#include "arch.h"
#include "fb.h"      /* FB_MAX_WIDTH / FB_MAX_HEIGHT / FB_MAX_PITCH */
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

/* --------------------------------------------------------------------------
 * Multiboot2 structures (local to this file)
 * -------------------------------------------------------------------------- */

/* Multiboot2 info header */
typedef struct {
    uint32_t total_size;
    uint32_t reserved;
} mb2_info_t;

/* Multiboot2 tag header */
typedef struct {
    uint32_t type;
    uint32_t size;
} mb2_tag_t;

/* Multiboot2 memory map tag (type 6) */
typedef struct {
    uint32_t type;          /* = 6 */
    uint32_t size;
    uint32_t entry_size;
    uint32_t entry_version;
} mb2_mmap_tag_t;

/* Multiboot2 memory map entry */
typedef struct {
    uint64_t base_addr;
    uint64_t length;
    uint32_t type;          /* 1 = available */
    uint32_t reserved;
} mb2_mmap_entry_t;

#define MB2_TAG_CMDLINE  1
#define MB2_TAG_MODULE   3
#define MB2_TAG_MMAP     6
#define MB2_TAG_FB       8
#define MB2_TAG_ACPI_OLD 14   /* ACPI 1.0 RSDP (32-bit, RSDT) */
#define MB2_TAG_ACPI_NEW 15   /* ACPI 2.0+ RSDP (64-bit, XSDT) */
#define MB2_MEM_AVAIL    1
#define MAX_REGIONS      32

/* Multiboot2 framebuffer info tag (type 8) */
typedef struct {
    uint32_t type;                  /* = 8 */
    uint32_t size;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint8_t  framebuffer_bpp;
    uint8_t  framebuffer_type;      /* 1 = RGB linear */
    uint16_t reserved;
} mb2_fb_tag_t;

/* --------------------------------------------------------------------------
 * Usable RAM regions (type=1 from multiboot2)
 * -------------------------------------------------------------------------- */

static aegis_mem_region_t regions[MAX_REGIONS];
static uint32_t           region_count = 0;
static uint64_t s_rsdp_v1_phys = 0;   /* ACPI 1.0 RSDP (type-14 tag) */
static uint64_t s_rsdp_v2_phys = 0;   /* ACPI 2.0+ RSDP (type-15 tag) */
static arch_fb_info_t s_fb_info;       /* zeroed at startup; addr==0 means absent */
static uint64_t s_module_phys = 0;   /* physical start of first multiboot2 module (rootfs) */
static uint64_t s_module_size = 0;   /* byte size of first module */
static uint64_t s_module2_phys = 0;  /* physical start of second module (ESP image) */
static uint64_t s_module2_size = 0;  /* byte size of second module */
static char s_cmdline[256];          /* kernel command line from GRUB */

/* Two static entries: first 1MB + multiboot2 info region.
 * Slot [1] is filled in arch_mm_init once mb_info address is known.
 * GRUB may place the multiboot2 info above 1MB (in allocatable RAM), so
 * we must reserve those pages before the PMM marks them free.
 * If mb_info is already below 1MB the slot [1] has len=0 and is a no-op. */
static aegis_mem_region_t x86_reserved[4] = {
    { 0x0UL, 0x100000UL },  /* first 1MB: BIOS data, VGA hole, ISA ROMs */
    { 0x0UL, 0x0UL },       /* multiboot2 info — filled by arch_mm_init */
    { 0x0UL, 0x0UL },       /* multiboot2 module 1 (rootfs) — filled by arch_mm_init */
    { 0x0UL, 0x0UL },       /* multiboot2 module 2 (ESP) — filled by arch_mm_init */
};

void arch_mm_init(void *mb_info)
{
    /* SAFETY: mb_info is a physical address equal to the virtual address
     * under Phase 2 identity mapping. Casting to a pointer is safe here.
     * The VMM phase must remap this before switching to higher-half. */
    const mb2_info_t *info = (const mb2_info_t *)mb_info;
    const uint8_t *p   = (const uint8_t *)mb_info + sizeof(mb2_info_t);
    const uint8_t *end = (const uint8_t *)mb_info + info->total_size;

    /* Reserve the multiboot2 info structure so the PMM never reuses its pages.
     * GRUB may place this above 1MB; the inline RSDP (used by acpi_init) would
     * be silently corrupted if a PMM allocation overwrote those pages. */
    x86_reserved[1].base = (uint64_t)(uintptr_t)mb_info;
    x86_reserved[1].len  = info->total_size;

    while (p < end) {
        const mb2_tag_t *tag = (const mb2_tag_t *)p;

        if (tag->type == 0)   /* end tag */
            break;

        if (tag->type == MB2_TAG_CMDLINE) {
            /* Command line tag: type(4) + size(4) + NUL-terminated string */
            const char *str = (const char *)(p + sizeof(mb2_tag_t));
            uint32_t slen = tag->size - (uint32_t)sizeof(mb2_tag_t);
            if (slen > sizeof(s_cmdline) - 1)
                slen = sizeof(s_cmdline) - 1;
            uint32_t ci;
            for (ci = 0; ci < slen && str[ci] != '\0'; ci++)
                s_cmdline[ci] = str[ci];
            s_cmdline[ci] = '\0';
        }

        if (tag->type == MB2_TAG_MMAP) {
            const mb2_mmap_tag_t *mmap = (const mb2_mmap_tag_t *)p;
            const uint8_t *ep  = p + sizeof(mb2_mmap_tag_t);
            const uint8_t *epe = p + mmap->size;

            while (ep < epe && region_count < MAX_REGIONS) {
                const mb2_mmap_entry_t *e = (const mb2_mmap_entry_t *)ep;
                if (e->type == MB2_MEM_AVAIL) {
                    regions[region_count].base = e->base_addr;
                    regions[region_count].len  = e->length;
                    region_count++;
                }
                ep += mmap->entry_size;
            }
        }

        if (tag->type == MB2_TAG_ACPI_NEW && s_rsdp_v2_phys == 0) {
            /* SAFETY: multiboot2 tag stream is identity-mapped (VA==PA) at this
             * point in boot. s_rsdp_v2_phys holds the PA of the inline RSDP v2.
             * Valid until identity map teardown (Phase 7 — already done, but
             * arch_mm_init runs before that; the value is consumed by acpi_init
             * which runs in the same boot phase while the physical address
             * remains accessible via the higher-half mapping). */
            s_rsdp_v2_phys = (uint64_t)(uintptr_t)(p + sizeof(mb2_tag_t));
        }
        if (tag->type == MB2_TAG_ACPI_OLD && s_rsdp_v1_phys == 0) {
            /* SAFETY: same identity-map guarantee as ACPI_NEW above. */
            s_rsdp_v1_phys = (uint64_t)(uintptr_t)(p + sizeof(mb2_tag_t));
        }

        if (tag->type == MB2_TAG_MODULE) {
            /* Module tag: type(4) + size(4) + mod_start(4) + mod_end(4) + string */
            const uint32_t *mod = (const uint32_t *)p;
            uint64_t start = (uint64_t)mod[2];
            uint64_t end_addr = (uint64_t)mod[3];
            if (end_addr > start) {
                if (s_module_phys == 0) {
                    /* First module: rootfs */
                    s_module_phys = start;
                    s_module_size = end_addr - start;
                    x86_reserved[2].base = start & ~0xFFFUL;
                    x86_reserved[2].len  = ((end_addr + 0xFFF) & ~0xFFFUL) - (start & ~0xFFFUL);
                } else if (s_module2_phys == 0) {
                    /* Second module: ESP image */
                    s_module2_phys = start;
                    s_module2_size = end_addr - start;
                    x86_reserved[3].base = start & ~0xFFFUL;
                    x86_reserved[3].len  = ((end_addr + 0xFFF) & ~0xFFFUL) - (start & ~0xFFFUL);
                }
            }
        }

        if (tag->type == MB2_TAG_FB) {
            const mb2_fb_tag_t *fb = (const mb2_fb_tag_t *)p;
            /* Only accept 32-bpp linear (type==1) framebuffers.
             * Some firmwares (notably QEMU + std-vga + OVMF) advertise
             * a 24-bpp GOP which we don't render to; those callers will
             * see sys_fb_map() return ENODEV. Real UEFI hardware
             * generally exposes 32-bpp modes. */
            if (fb->framebuffer_type == 1 && fb->framebuffer_bpp == 32) {
                /* The framebuffer tag is untrusted bootloader input.
                 * Sanitise the geometry at the source (defense in depth —
                 * fb_init() re-checks the same limits) so a corrupt or
                 * malicious tag can never propagate absurd dimensions into
                 * the page-mapping / clear math downstream. All products
                 * are computed in uint64 so they cannot wrap.
                 *
                 * Reject on: zero/oversized width or height; zero/oversized
                 * pitch; pitch too small to hold one 32-bpp scanline; or a
                 * physical extent (addr + pitch*height) that overflows the
                 * 64-bit address space. On any rejection we leave s_fb_info
                 * zeroed (addr == 0), which is exactly the "no framebuffer
                 * tag present" state — arch_get_fb_info() returns 0,
                 * fb_init() bails silently, and the kernel still boots to
                 * serial (Output Law 2). */
                uint64_t w     = fb->framebuffer_width;
                uint64_t h     = fb->framebuffer_height;
                uint64_t pitch = fb->framebuffer_pitch;
                uint64_t addr  = fb->framebuffer_addr;

                if (w == 0 || w > FB_MAX_WIDTH ||
                    h == 0 || h > FB_MAX_HEIGHT ||
                    pitch == 0 || pitch > FB_MAX_PITCH ||
                    pitch < w * 4u ||
                    addr == 0 ||
                    pitch * h > UINT64_MAX - addr) {
                    printk("[FB] WARN: rejecting boot framebuffer tag: "
                           "addr=0x%lx %ux%u pitch=%u bpp=%u\n",
                           addr, fb->framebuffer_width,
                           fb->framebuffer_height, fb->framebuffer_pitch,
                           (uint32_t)fb->framebuffer_bpp);
                } else {
                    s_fb_info.addr   = fb->framebuffer_addr;
                    s_fb_info.pitch  = fb->framebuffer_pitch;
                    s_fb_info.width  = fb->framebuffer_width;
                    s_fb_info.height = fb->framebuffer_height;
                    s_fb_info.bpp    = fb->framebuffer_bpp;
                    s_fb_info.type   = fb->framebuffer_type;
                }
            }
        }

        /* Tags are 8-byte aligned */
        p += (tag->size + 7) & ~7U;
    }

}

uint32_t arch_mm_region_count(void)
{
    return region_count;
}

const aegis_mem_region_t *arch_mm_get_regions(void)
{
    return regions;
}

/* --------------------------------------------------------------------------
 * x86 reserved regions — all platform-specific addresses live here.
 * pmm.c calls this instead of hard-coding any platform address.
 * ARM64's arch_mm.c returns a different (or empty) table.
 * -------------------------------------------------------------------------- */


uint32_t arch_mm_reserved_region_count(void)
{
    return sizeof(x86_reserved) / sizeof(x86_reserved[0]);
}

const aegis_mem_region_t *arch_mm_get_reserved_regions(void)
{
    return x86_reserved;
}

uint64_t arch_get_rsdp_phys(void)
{
    /* Prefer ACPI 2.0+ (XSDT, 64-bit pointers); fall back to 1.0 (RSDT). */
    return (s_rsdp_v2_phys != 0) ? s_rsdp_v2_phys : s_rsdp_v1_phys;
}

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

const char *
arch_get_cmdline(void)
{
    return s_cmdline;
}
