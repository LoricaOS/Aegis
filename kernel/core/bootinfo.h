/*
 * kernel/core/bootinfo.h — arch-neutral boot information.
 *
 * Filled by kernel/core/limine.c (Limine boot protocol path) and consumed
 * by each arch's arch_mm ingest. The multiboot2 path (x86 microvm entry,
 * kernel/arch/x86_64/boot.asm) never builds one of these — it parses the
 * mb2 tag stream directly in arch_mm.c.
 *
 * Everything here is copied out of bootloader-owned memory at entry, so it
 * stays valid after the kernel switches to its own page tables.
 */
#ifndef AEGIS_BOOTINFO_H
#define AEGIS_BOOTINFO_H

#include <stdint.h>

#define BOOTINFO_MAX_REGIONS 64
#define BOOTINFO_MAX_MODULES 2      /* 0 = rootfs, 1 = ESP image */
#define BOOTINFO_CMDLINE_MAX 256

typedef struct {
    uint64_t base;
    uint64_t len;
} bootinfo_region_t;

typedef struct aegis_bootinfo {
    /* VA = PA + hhdm_offset while the bootloader's page tables are live
     * (i.e. until vmm_init loads the kernel's own tables). */
    uint64_t hhdm_offset;

    /* PA(kernel symbol S) = S - ARCH_KERNEL_VIRT_BASE + kern_phys_slide.
     * 0 when the kernel is physically at its linked LMA (multiboot2/GRUB);
     * arbitrary under the Limine protocol (no placement guarantee). */
    uint64_t kern_phys_slide;

    /* Usable RAM (Limine LIMINE_MEMMAP_USABLE). */
    bootinfo_region_t usable[BOOTINFO_MAX_REGIONS];
    uint32_t          usable_count;

    /* Boot modules by config order (rootfs, then ESP image). size==0 → absent. */
    struct { uint64_t phys, size; } module[BOOTINFO_MAX_MODULES];

    char     cmdline[BOOTINFO_CMDLINE_MAX];
    uint64_t rsdp_phys;      /* 0 → absent (base revision 3: physical) */
    uint64_t dtb_phys;       /* 0 → absent (arm64) */

    /* Framebuffer, physical address. addr_phys==0 → absent. Untrusted
     * bootloader input — each arch sanitizes before use (see arch_mm.c). */
    struct {
        uint64_t addr_phys;
        uint32_t pitch, width, height;
        uint8_t  bpp;
    } fb;
} aegis_bootinfo_t;

/* 1 when the kernel entered via the Limine boot protocol. Set before
 * kernel_main_limine runs; 0 on the multiboot2 (microvm) path. */
extern int g_boot_limine;

/* Per-arch continuation: each arch's main file defines this and never
 * returns. Called by limine_boot_entry on the kernel's own boot stack. */
void kernel_main_limine(const aegis_bootinfo_t *bi);

#endif /* AEGIS_BOOTINFO_H */
