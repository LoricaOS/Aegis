ENTRY(_start)
PHDRS { text PT_LOAD FILEHDR PHDRS FLAGS(5); }
SECTIONS {
    . = 0x400000 + SIZEOF_HEADERS;
    .text : { *(.text*) *(.rodata*) } :text
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
ASSERT(. < 0x401000, "bounded EL0 fixture must fit one RX page")
