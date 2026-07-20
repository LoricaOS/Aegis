/*
 * linker-pi5-native.ld — links the REAL Aegis kernel with
 * kernel/arch/arm64/native/boot_probe.S as entry (native, non-Limine,
 * non-UEFI Pi 5 boot), instead of the milestone-1..3 standalone probe
 * (see linker-pi5-probe.ld, kept separate/unchanged for that regression
 * target).
 *
 * Two-region split identical to linker-pi5-probe.ld's (see that file's
 * header comment for the KERN_LMA=0x200000 rationale, confirmed via
 * real firmware's own "Kernel relocated to 0x200000" boot log):
 *   .text.boot — VMA=LMA=KERN_LMA. boot_probe.S's entry, EL2->EL1 drop,
 *                page tables, MMU enable. Runs pre-MMU, identity-mapped.
 *   (everything else) — VMA=KERN_VMA (matches ARCH_KERNEL_VIRT_BASE +
 *                ARCH_KERNEL_PHYS_BASE exactly, kernel/arch/arm64/arch.h
 *                -- the real kernel's own vmm_init() maps itself at this
 *                same VA later, so no relocation is needed when TTBR1
 *                gets replaced), LMA packed right after .text.boot.
 *
 * Section layout for the high half mirrors tools/linker-arm64.ld (the
 * Limine build's linker script) section-for-section -- .text/.rodata
 * (+ __ex_table)/.data/.bss -- so the same kernel source compiles to the
 * same shape regardless of which boot path links it.
 */

KERN_LMA  = 0x200000;
KERN_VMA  = 0xFFFFFFFF80000000 + KERN_LMA;
VA_OFF    = KERN_VMA - KERN_LMA;

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS
{
    . = KERN_LMA;
    .text.boot : { KEEP(*(.text.boot)) }

    . = ALIGN(4096);
    _post_boot = .;
    . = KERN_VMA + (_post_boot - KERN_LMA);

    .text : AT(ADDR(.text) - VA_OFF) { *(.text .text.*) }

    .rodata : AT(ADDR(.rodata) - VA_OFF) {
        *(.rodata .rodata.*)
        . = ALIGN(8);
        PROVIDE(__start_ex_table = .);
        KEEP(*(__ex_table))
        PROVIDE(__stop_ex_table = .);
    }

    .data : AT(ADDR(.data) - VA_OFF) { *(.data .data.*) }

    /* Real .bss (SHT_NOBITS via `(NOLOAD)`) -- see boot_probe.S's own
     * page-table/stack comments and probe_entry_c.c's header comment for
     * why this matters here: the flat `objcopy -O binary` Image loader
     * has no NOBITS concept, so boot_probe.S's .Lhigh runs a runtime zero
     * loop over [_bss_start, _bss_end) before calling into any C code
     * that touches a static (which, at this scale -- pmm/vmm/fdt/gic/
     * sched/... -- is most of the kernel). */
    .bss (NOLOAD) : AT(ADDR(.bss) - VA_OFF) {
        . = ALIGN(8);
        _bss_start = .;
        *(COMMON)
        *(.bss .bss.*)
        . = ALIGN(8);
        _bss_end = .;
    }

    _kernel_end = .;

    /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame) }
}
