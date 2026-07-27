/* pvh.c — Xen PVH direct-boot support (x86-64).
 *
 * MicroVMs (Firecracker, cloud-hypervisor, QEMU `-machine microvm`) run no
 * bootloader: the VMM loads the kernel ELF and jumps straight to a 32-bit
 * entry point named by an ELF note, passing a physical pointer to an
 * hvm_start_info in %ebx (the PVH boot ABI). This is what lets Aegis boot in a
 * microVM at all — Limine and multiboot2 are not spoken there.
 *
 * Two halves live here:
 *   1. The ELF note the VMM scans for (namespace "Xen", type
 *      XEN_ELFNOTE_PHYS32_ENTRY). GAS emits it as a real SHT_NOTE section; the
 *      linker script places it in a PT_NOTE program header, which is where
 *      loaders look. boot.asm's pvh_start is the entry it points at.
 *   2. pvh_boot_ingest(): translate hvm_start_info into the arch-neutral
 *      aegis_bootinfo_t and hand it to arch_mm_ingest — the very same intake
 *      the Limine path uses, so everything downstream is boot-path oblivious.
 *
 * PVH's memory model matches the multiboot2 path (low RAM identity-mapped,
 * kernel at its link address, no HHDM), so hhdm_offset and kern_phys_slide are
 * left 0. Physical pointers from the start_info are dereferenced directly:
 * boot.asm identity-maps the low 1 GB (VA==PA), and VMMs place the start_info,
 * cmdline, and memmap there — exactly as the mb2 path reads its info struct.
 */
#include <stdint.h>
#include "arch.h"        /* arch_mm_ingest */
#include "bootinfo.h"    /* aegis_bootinfo_t, PVH_BOOT_MAGIC, pvh_boot_ingest */

/* The PVH ELF note. n_type 18 = XEN_ELFNOTE_PHYS32_ENTRY; the descriptor is
 * the 32-bit *physical* entry address (pvh_start's link address minus the
 * higher-half base = its LMA). `@note` makes GAS mark the section SHT_NOTE. */
__asm__(
    ".pushsection .note.Xen, \"a\", @note\n"
    ".p2align 2\n"
    ".long 2f - 1f\n"                               /* n_namesz              */
    ".long 4f - 3f\n"                               /* n_descsz             */
    ".long 18\n"                                    /* n_type = PHYS32_ENTRY */
    "1: .asciz \"Xen\"\n"
    "2: .p2align 2\n"
    "3: .long pvh_start - 0xffffffff80000000\n"     /* phys32 entry address  */
    "4: .p2align 2\n"
    ".popsection\n"
);

#define HVM_MEMMAP_TYPE_RAM 1u

/* hvm_start_info + tables, per the Xen PVH boot ABI
 * (xen/include/public/arch-x86/hvm/start_info.h). */
struct hvm_start_info {
    uint32_t magic;             /* PVH_BOOT_MAGIC ("xEn3") */
    uint32_t version;
    uint32_t flags;
    uint32_t nr_modules;
    uint64_t modlist_paddr;
    uint64_t cmdline_paddr;
    uint64_t rsdp_paddr;
    uint64_t memmap_paddr;      /* version >= 1 */
    uint32_t memmap_entries;    /* version >= 1 */
    uint32_t reserved;
};
struct hvm_modlist_entry {
    uint64_t paddr;
    uint64_t size;
    uint64_t cmdline_paddr;
    uint64_t reserved;
};
struct hvm_memmap_table_entry {
    uint64_t addr;
    uint64_t size;
    uint32_t type;              /* 1 = usable RAM */
    uint32_t reserved;
};

/* Low RAM is identity-mapped (VA==PA) here, just like the mb2 info struct. */
static inline const void *phys(uint64_t pa) { return (const void *)(uintptr_t)pa; }

void pvh_boot_ingest(void *start_info)
{
    const struct hvm_start_info *si = start_info;
    static aegis_bootinfo_t bi;   /* zeroed: no HHDM, no phys slide */

    if (!si || si->magic != PVH_BOOT_MAGIC)
        return;                   /* not PVH — empty memmap, caught upstream */

    if (si->cmdline_paddr) {
        const char *c = phys(si->cmdline_paddr);
        uint32_t i;
        for (i = 0; i < sizeof(bi.cmdline) - 1 && c[i]; i++)
            bi.cmdline[i] = c[i];
        bi.cmdline[i] = '\0';
    }

    bi.rsdp_phys = si->rsdp_paddr;

    /* Memory map (present from version 1): type-1 entries are usable RAM.
     * arch_mm_ingest + the x86 reserved table handle low/reserved fixups. */
    if (si->version >= 1 && si->memmap_paddr && si->memmap_entries) {
        const struct hvm_memmap_table_entry *m = phys(si->memmap_paddr);
        for (uint32_t i = 0; i < si->memmap_entries &&
                             bi.usable_count < BOOTINFO_MAX_REGIONS; i++) {
            if (m[i].type != HVM_MEMMAP_TYPE_RAM)
                continue;
            bi.usable[bi.usable_count].base = m[i].addr;
            bi.usable[bi.usable_count].len  = m[i].size;
            bi.usable_count++;
        }
    }

    /* Modules: [0] = rootfs (initrd), matching the mb2/Limine convention. */
    if (si->nr_modules && si->modlist_paddr) {
        const struct hvm_modlist_entry *mods = phys(si->modlist_paddr);
        uint32_t n = si->nr_modules;
        if (n > BOOTINFO_MAX_MODULES)
            n = BOOTINFO_MAX_MODULES;
        for (uint32_t i = 0; i < n; i++) {
            bi.module[i].phys = mods[i].paddr;
            bi.module[i].size = mods[i].size;
        }
    }

    arch_mm_ingest(&bi);
}
