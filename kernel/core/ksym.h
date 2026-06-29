#ifndef AEGIS_KSYM_H
#define AEGIS_KSYM_H

#include <stdint.h>

/* ksym_lookup — resolve a kernel code address to the nearest preceding symbol.
 * Returns the symbol name and sets *off to (addr - symbol_base), or NULL if no
 * symbol table is available / the address is out of range.  Used by the
 * backtrace printer to emit "func+0x<off>" instead of bare hex.
 *
 * The table is generated at build time from the linked kernel (tools/gen-ksyms)
 * and embedded as a trailing rodata blob; if that blob is absent (or empty)
 * this returns NULL and callers fall back to hex addresses. */
const char *ksym_lookup(uint64_t addr, uint64_t *off);

#endif /* AEGIS_KSYM_H */
