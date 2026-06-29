OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHYS_BASE = 0x100000;
KERN_VMA  = 0xFFFFFFFF80000000;

SECTIONS
{
    . = PHYS_BASE;

    /* .multiboot must land within the first 8KB so GRUB locates it
       per the multiboot2 spec. VMA = LMA = physical. */
    .multiboot : { KEEP(*(.multiboot)) }

    /* .text.boot contains the 32-bit boot stub, GDT, and physical-mode
       trampoline. Must run at physical addresses — VMA = LMA. */
    .text.boot  : { *(.text.boot) }

    /* Relocate all remaining sections to the higher half.
       VMA = KERN_VMA + offset; LMA = physical (AT directive). */
    . += KERN_VMA;

    .text   : AT(ADDR(.text)   - KERN_VMA) { *(.text .text.*) }
    .rodata : AT(ADDR(.rodata) - KERN_VMA) {
        *(.rodata .rodata.*)
        /* Exception table: {fault_pc, fixup_pc} pairs for fault-tolerant
         * uaccess (copy_*_user). The #PF handler (isr_dispatch) looks up a
         * faulting kernel RIP here and redirects to the fixup instead of
         * panicking — makes copy_*_user safe against an unmapped user buffer
         * (e.g. a sibling munmap during a blocking syscall). 8-byte aligned;
         * KEEP so --gc-sections can't drop it. */
        . = ALIGN(8);
        PROVIDE(__start_ex_table = .);
        KEEP(*(__ex_table))
        PROVIDE(__stop_ex_table = .);
    }
    .data   : AT(ADDR(.data)   - KERN_VMA) { *(.data .data.*) }

    .bss : AT(ADDR(.bss) - KERN_VMA) {
        *(COMMON)
        *(.bss .bss.*)
    }

    _kernel_end = .;   /* higher-half virtual address */
}

/* The kernel image + BSS must fit in pd_hi[0..3] = the first 8 MB of the
 * higher half. The VMM mapped-window lives at KERN_VMA + 0x800000 (pd_hi[4],
 * see vmm.c VMM_WINDOW_VA) and the KVA allocator at +0xA00000 (pd_hi[5]); if
 * BSS grows past the window base it silently corrupts the window PT's VA range
 * — historically a debugging-session-eating class of bug. Make it a link
 * error instead. Raise the window/KVA placement (vmm.c) AND this bound together
 * if the kernel ever legitimately needs more than 8 MB of image+BSS. */
ASSERT(_kernel_end <= KERN_VMA + 0x800000,
       "kernel image+BSS exceeds 8MB (pd_hi[0..3]); the VMM window at KERN_VMA+0x800000 would be overrun")
