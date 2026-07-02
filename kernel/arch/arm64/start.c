/*
 * start.c — arm64 early bring-up (called from entry.S on the boot stack,
 * bootloader page tables still live).
 *
 * Everything boot.S did in the pre-split arm64 port (EL2→EL1 drop, MMU
 * enable, early translation tables, DTB discovery) is handled by the
 * Limine boot protocol. What remains:
 *
 *  1. Pin MAIR_EL1/TCR_EL1/CPACR_EL1 to known values (base revision 3
 *     leaves them loosely specified; revision 4+ guarantees exactly the
 *     MAIR we program, so the executing mappings' attributes don't move).
 *  2. Hand off to the shared limine_boot_entry() (kernel/core/limine.c).
 *  3. After the bootinfo ingest, map the PL011 through a tiny static
 *     TTBR0 identity map so printk works before vmm_init builds the real
 *     kernel tables (Limine's restrictive HHDM maps no device MMIO).
 */

#include "arch.h"
#include "bootinfo.h"
#include <stdint.h>

void limine_boot_entry(void);
void serial_set_base(volatile void *va);

/* MAIR: Attr0 = 0xFF Normal WB (Limine's own value — the kernel is
 * executing through Attr0 mappings right now), Attr1 = Device-nGnRE,
 * Attr2 = Normal Non-Cacheable (framebuffer/WC). */
#define MAIR_VALUE 0x00000000004404FFUL

void
arm64_early_entry(void)
{
    uint64_t parange, tcr;

    /* CPACR_EL1.FPEN = 0b11 (bits [21:20]): FP/SIMD usable at EL0 and EL1
     * without trapping. Required so ctx_switch.S can save/restore the V
     * registers and so EL0 user code (musl's NEON memcpy) runs without a
     * trap. ZEN stays 0 (no SVE on the reference cortex-a72). */
    __asm__ volatile("msr cpacr_el1, %0" : : "r"(3UL << 20));
    __asm__ volatile("isb");
    __asm__ volatile("msr mair_el1, %0" : : "r"(MAIR_VALUE));

    __asm__ volatile("mrs %0, ID_AA64MMFR0_EL1" : "=r"(parange));
    parange &= 0xF;
    if (parange > 5)
        parange = 5;                                  /* cap at 48-bit PA */

    /* T0SZ=16, TTBR0 4K WB-cached inner-shareable walks (EPD0=0);
     * T1SZ=16, TG1=4K — identical geometry to Limine's handoff state. */
    tcr = 16UL                        /* T0SZ  */
        | (1UL << 8) | (1UL << 10)    /* IRGN0/ORGN0 = WB */
        | (3UL << 12)                 /* SH0 = inner */
        | (16UL << 16)                /* T1SZ  */
        | (1UL << 24) | (1UL << 26)   /* IRGN1/ORGN1 = WB */
        | (3UL << 28)                 /* SH1 = inner */
        | (2UL << 30)                 /* TG1 = 4K */
        | (parange << 32);            /* IPS */
    __asm__ volatile(
        "msr tcr_el1, %0\n\t"
        "isb\n\t"
        "tlbi vmalle1\n\t"
        "dsb ish\n\t"
        "isb"
        : : "r"(tcr) : "memory");

    limine_boot_entry();
    /* UNREACHABLE */
    for (;;)
        arch_halt();
}

/* ── Early device identity map (TTBR0) ─────────────────────────────────────
 * One 1GB Device block covering PA [0..1GB) — the whole QEMU-virt MMIO
 * window — mapped at VA==PA through TTBR0, which Limine leaves free.
 * Lives only until vmm_init loads the real tables (which replace TTBR0
 * with the empty user table and provide the permanent device window at
 * ARCH_DMAP_BASE). */

static uint64_t early_l0[512] __attribute__((aligned(4096)));
static uint64_t early_l1[512] __attribute__((aligned(4096)));

#define EARLY_BLOCK_DEVICE ((1UL << 0) | (1UL << 10) | (1UL << 2) | \
                            (1UL << 53) | (1UL << 54))
                            /* valid block | AF | AttrIdx1 | PXN | UXN */

void
arm64_map_early_uart(void)
{
    uint64_t slide = arch_kern_phys_slide();
    uint64_t l0_phys = (uint64_t)(uintptr_t)early_l0
                       - ARCH_KERNEL_VIRT_BASE + slide;
    uint64_t l1_phys = (uint64_t)(uintptr_t)early_l1
                       - ARCH_KERNEL_VIRT_BASE + slide;

    early_l1[0] = 0UL | EARLY_BLOCK_DEVICE;          /* PA 0, 1GB block */
    early_l0[0] = l1_phys | 3UL;                     /* table */

    __asm__ volatile(
        "dsb ishst\n\t"
        "msr ttbr0_el1, %0\n\t"
        "tlbi vmalle1\n\t"
        "dsb ish\n\t"
        "isb"
        : : "r"(l0_phys) : "memory");

    serial_set_base((volatile void *)0x09000000UL);  /* PL011 via idmap */
}
