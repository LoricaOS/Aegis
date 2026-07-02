/*
 * kernel/core/limine.c — Limine boot protocol requests + ingest.
 *
 * Arch-neutral: the per-arch entry stub switches onto the kernel's own
 * .bss boot stack and calls limine_boot_entry() while the bootloader's
 * page tables (HHDM + kernel map) are still live. Everything the kernel
 * needs later is COPIED into a static aegis_bootinfo_t here, because the
 * responses live in bootloader-reclaimable memory that becomes unreachable
 * once vmm_init loads the kernel's own tables.
 *
 * Base revision 6 (the aarch64 minimum in current Limine; x86 needs only
 * 3 but the tag is shared): HHDM maps usable/reclaimable/exec+modules/
 * framebuffer (+reserved-mapped/ACPI), RSDP comes back as an HHDM VA
 * (to_phys() below normalizes), and on aarch64 entry is EL1 — or EL2 with
 * VHE when firmware runs at EL2, which QEMU virt (no EL2) never does; the
 * arm64 port currently assumes the EL1 handoff.
 */
#include <stdint.h>
#include <stddef.h>
#include "../include/limine.h"
#include "bootinfo.h"
#include "arch.h"     /* ARCH_KERNEL_VIRT_BASE */

int g_boot_limine = 0;

/* ── Requests ───────────────────────────────────────────────────────────────
 * All in .limine_requests (a writable .data subsection — the bootloader
 * writes the response pointers into these objects), bracketed by the
 * start/end markers per the protocol spec. */
#define LIMINE_REQ __attribute__((used, section(".limine_requests")))

__attribute__((used, section(".limine_requests_start")))
static volatile uint64_t s_start_marker[4] = LIMINE_REQUESTS_START_MARKER;

LIMINE_REQ static volatile uint64_t s_base_revision[3] = LIMINE_BASE_REVISION(6);

LIMINE_REQ static volatile struct limine_memmap_request s_memmap = {
    .id = LIMINE_MEMMAP_REQUEST_ID, .revision = 0, .response = NULL,
};
LIMINE_REQ static volatile struct limine_hhdm_request s_hhdm = {
    .id = LIMINE_HHDM_REQUEST_ID, .revision = 0, .response = NULL,
};
LIMINE_REQ static volatile struct limine_executable_address_request s_kaddr = {
    .id = LIMINE_EXECUTABLE_ADDRESS_REQUEST_ID, .revision = 0, .response = NULL,
};
LIMINE_REQ static volatile struct limine_executable_cmdline_request s_cmdline = {
    .id = LIMINE_EXECUTABLE_CMDLINE_REQUEST_ID, .revision = 0, .response = NULL,
};
LIMINE_REQ static volatile struct limine_module_request s_module = {
    .id = LIMINE_MODULE_REQUEST_ID, .revision = 0, .response = NULL,
};
LIMINE_REQ static volatile struct limine_rsdp_request s_rsdp = {
    .id = LIMINE_RSDP_REQUEST_ID, .revision = 0, .response = NULL,
};
LIMINE_REQ static volatile struct limine_framebuffer_request s_fb = {
    .id = LIMINE_FRAMEBUFFER_REQUEST_ID, .revision = 0, .response = NULL,
};
LIMINE_REQ static volatile struct limine_dtb_request s_dtb = {
    .id = LIMINE_DTB_REQUEST_ID, .revision = 0, .response = NULL,
};

__attribute__((used, section(".limine_requests_end")))
static volatile uint64_t s_end_marker[2] = LIMINE_REQUESTS_END_MARKER;

/* ── Ingest ────────────────────────────────────────────────────────────── */

static aegis_bootinfo_t s_bi;   /* .bss — survives the page-table switch */

/* Bootloader-provided pointers are HHDM virtual addresses; the kernel wants
 * physical. Base revision 3 returns the RSDP as physical already, but be
 * tolerant of either form: anything at/above the HHDM base is a VA. */
static uint64_t
to_phys(uint64_t addr, uint64_t hhdm)
{
    return (hhdm != 0 && addr >= hhdm) ? addr - hhdm : addr;
}

void
limine_boot_entry(void)
{
    g_boot_limine = 1;

    /* If the bootloader doesn't speak base revision 6 it left the tag
     * unmodified. No console exists yet; fail closed by halting. */
    if (!LIMINE_BASE_REVISION_SUPPORTED(s_base_revision))
        for (;;) ;

    uint64_t hhdm = s_hhdm.response ? s_hhdm.response->offset : 0;
    s_bi.hhdm_offset = hhdm;

    if (s_kaddr.response) {
        /* PA(S) = S - virtual_base + physical_base
         *       = S - KERN_VMA + (physical_base - (virtual_base - KERN_VMA)) */
        s_bi.kern_phys_slide = s_kaddr.response->physical_base -
            (s_kaddr.response->virtual_base - ARCH_KERNEL_VIRT_BASE);
    }

    if (s_memmap.response) {
        for (uint64_t i = 0; i < s_memmap.response->entry_count &&
                             s_bi.usable_count < BOOTINFO_MAX_REGIONS; i++) {
            struct limine_memmap_entry *e = s_memmap.response->entries[i];
            if (e->type != LIMINE_MEMMAP_USABLE)
                continue;
            s_bi.usable[s_bi.usable_count].base = e->base;
            s_bi.usable[s_bi.usable_count].len  = e->length;
            s_bi.usable_count++;
        }
    }

    if (s_cmdline.response && s_cmdline.response->cmdline) {
        const char *c = s_cmdline.response->cmdline;
        uint32_t i;
        for (i = 0; i < BOOTINFO_CMDLINE_MAX - 1 && c[i]; i++)
            s_bi.cmdline[i] = c[i];
        s_bi.cmdline[i] = '\0';
    }

    if (s_module.response) {
        for (uint64_t i = 0; i < s_module.response->module_count &&
                             i < BOOTINFO_MAX_MODULES; i++) {
            struct limine_file *f = s_module.response->modules[i];
            s_bi.module[i].phys = to_phys((uint64_t)(uintptr_t)f->address, hhdm);
            s_bi.module[i].size = f->size;
        }
    }

    if (s_rsdp.response)
        s_bi.rsdp_phys = to_phys((uint64_t)(uintptr_t)s_rsdp.response->address, hhdm);
    if (s_dtb.response)
        s_bi.dtb_phys = to_phys((uint64_t)(uintptr_t)s_dtb.response->dtb_ptr, hhdm);

    if (s_fb.response && s_fb.response->framebuffer_count > 0) {
        struct limine_framebuffer *f = s_fb.response->framebuffers[0];
        if (f->memory_model == LIMINE_FRAMEBUFFER_RGB) {
            s_bi.fb.addr_phys = to_phys((uint64_t)(uintptr_t)f->address, hhdm);
            s_bi.fb.pitch  = (uint32_t)f->pitch;
            s_bi.fb.width  = (uint32_t)f->width;
            s_bi.fb.height = (uint32_t)f->height;
            s_bi.fb.bpp    = (uint8_t)f->bpp;
        }
    }

    kernel_main_limine(&s_bi);
    /* UNREACHABLE */
    for (;;) ;
}
