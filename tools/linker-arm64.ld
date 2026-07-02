OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(limine_start)

/* arm64 boots ONLY via the Limine protocol: no multiboot header, no
   low-VMA boot stub. The image's physical placement comes from Limine
   (executable-address response → arch_kern_phys_slide). PHYS_BASE is
   just the link-time offset of the first section. */
PHYS_BASE = 0x200000;
KERN_VMA  = 0xFFFFFFFF80000000;

SECTIONS
{
    . = KERN_VMA + PHYS_BASE;

    .text   : AT(ADDR(.text)   - KERN_VMA) { *(.text .text.*) }
    .rodata : AT(ADDR(.rodata) - KERN_VMA) {
        *(.rodata .rodata.*)
        /* Exception table (uaccess fixups) — empty on arm64 for now but
         * the shared linkage expects the bounds symbols. */
        . = ALIGN(8);
        PROVIDE(__start_ex_table = .);
        KEEP(*(__ex_table))
        PROVIDE(__stop_ex_table = .);
    }
    .data   : AT(ADDR(.data)   - KERN_VMA) {
        *(.data .data.*)
        . = ALIGN(8);
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    }

    .bss : AT(ADDR(.bss) - KERN_VMA) {
        *(COMMON)
        *(.bss .bss.*)
    }

    _kernel_end = .;
}
