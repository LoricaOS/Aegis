/* Same higher-half kernel address as the normal ARM64 build; section
 * boundaries are page aligned for the native bridge's W^X mappings. */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(apple_kernel_start)
KERN_VMA = 0xFFFFFFFF80000000;
PHDRS { text PT_LOAD FLAGS(5); ro PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); }
SECTIONS {
    . = KERN_VMA + 0x200000;
    apple_kernel_base = .;
    .text : AT(ADDR(.text) - KERN_VMA) { *(.text .text.*) } :text
    . = ALIGN(4096);
    apple_kernel_text_end = .;
    .rodata : AT(ADDR(.rodata) - KERN_VMA) {
        *(.rodata .rodata.*)
        . = ALIGN(8);
        __start_ex_table = .;
        KEEP(*(__ex_table))
        __stop_ex_table = .;
    } :ro
    . = ALIGN(4096);
    apple_kernel_ro_end = .;
    .data : AT(ADDR(.data) - KERN_VMA) {
        *(.data .data.*)
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :data
    . = ALIGN(16);
    .bss (NOLOAD) : { *(COMMON) *(.bss .bss.*) } :data
    . = ALIGN(4096);
    _kernel_end = .;
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
    ASSERT(_kernel_end - apple_kernel_base < 0x1000000, "checkpoint kernel too large")
}
