OUTPUT_ARCH(aarch64)
ENTRY(apple_probe_start)
SECTIONS
{
    . = 0;
    .text : { KEEP(*(.text.boot)) KEEP(*(.text.vectors)) *(.text .text.*) }
    . = ALIGN(DEFINED(apple_probe_translation_begin) ? 4096 : 1);
    apple_probe_text_end = .;
    .rodata : { *(.rodata .rodata.*) }
    . = ALIGN(DEFINED(apple_probe_translation_begin) ? 4096 : 1);
    apple_probe_ro_end = .;
    .data : { *(.data .data.*) }
    . = ALIGN(16);
    __bss_start = .;
    .bss (NOLOAD) : {
        *(.bss .bss.*) *(COMMON)
        . = ALIGN(16);
        apple_probe_fault_stack_bottom = .;
        . += 16384;
        apple_probe_fault_stack_top = .;
        apple_probe_stack_bottom = .;
        . += 16384;
    }
    . = ALIGN(DEFINED(apple_probe_translation_begin) ? 4096 : 16);
    apple_probe_end = .;
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
    /* No absolute pointer tables or dynamic relocation machinery. */
    .got : { *(.got .got.* .igot.*) }
    ASSERT(SIZEOF(.got) == 0, "unexpected GOT in relocatable probe")
    ASSERT((apple_probe_vectors & 2047) == 0, "unaligned vector table")
    ASSERT(apple_probe_vectors_end - apple_probe_vectors == 2048, "bad vector table size")
    ASSERT(apple_probe_end < (DEFINED(apple_kernel_bridge) ? 0x1800000 : 0x200000),
           "entry image exceeds bounded footprint")
}
