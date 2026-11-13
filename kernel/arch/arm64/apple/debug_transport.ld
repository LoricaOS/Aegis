OUTPUT_ARCH(aarch64)
ENTRY(debug_transport_start)
PHDRS { text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
    . = 0;
    .text : { *(.text) } :text
    ASSERT(. <= 0x4000, "debug text exceeds stage-2 page")
    . = 0x4000;
    .data : { *(.data) } :data
    ASSERT(. == 0x4020, "debug report layout changed")
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
