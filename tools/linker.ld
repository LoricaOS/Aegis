OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
/* ELF entry = the Limine boot protocol path (64-bit handoff). The
   multiboot2/microvm path enters at _start via the mb2 header's
   entry-address tag, which stores _start's PHYSICAL address. */
ENTRY(limine_start)

PHYS_BASE = 0x100000;
KERN_VMA  = 0xFFFFFFFF80000000;

/* Every section carries a higher-half VMA (the Limine protocol rejects
   lower-half executables) with LMA = VMA - KERN_VMA, so multiboot2
   loaders still place the image physically at PHYS_BASE. Under the
   Limine protocol the image may land at ANY physical base — the kernel
   reads the executable-address response and keeps a phys slide. */

SECTIONS
{
    . = KERN_VMA + PHYS_BASE;

    /* .multiboot must land within the first 32KB of the image so GRUB
       locates it per the multiboot2 spec — keep it first. .text.boot is
       the 32-bit mb2 entry + trampoline (executes at physical). */
    .boot : AT(ADDR(.boot) - KERN_VMA) {
        KEEP(*(.multiboot))
        *(.text.boot)
    }

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
    .data   : AT(ADDR(.data)   - KERN_VMA) {
        *(.data .data.*)
        /* Limine boot protocol requests (kernel/core/limine.c). Writable:
         * the bootloader stores response pointers into these objects.
         * Bracketed by the protocol's start/end markers. */
        . = ALIGN(8);
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    }

    .bss : AT(ADDR(.bss) - KERN_VMA) {
        *(COMMON)
        *(.bss .bss.*)
    }

    _kernel_end = .;   /* higher-half virtual address */
}

/* The kernel image + BSS must fit in the first 8 MB of the higher half.
 * The VMM mapped-window lives at KERN_VMA + 0x800000 (see vmm.c
 * VMM_WINDOW_VA) and the KVA allocator at +0xA00000; if BSS grows past the
 * window base it silently corrupts the window PT's VA range — historically
 * a debugging-session-eating class of bug. Make it a link error instead.
 * Raise the window/KVA placement (vmm.c) AND this bound together if the
 * kernel ever legitimately needs more than 8 MB of image+BSS. */
ASSERT(_kernel_end <= KERN_VMA + 0x800000,
       "kernel image+BSS exceeds 8MB (pd_hi[0..3]); the VMM window at KERN_VMA+0x800000 would be overrun")
