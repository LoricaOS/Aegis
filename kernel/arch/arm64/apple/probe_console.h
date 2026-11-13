#ifndef AEGIS_APPLE_PROBE_CONSOLE_H
#define AEGIS_APPLE_PROBE_CONSOLE_H

#include "../fdt.h"

/* Only the diagnostic's validated simplefb may be passed here. */
void probe_console_init(const struct fdt_bootfb *fb);
void probe_console_fault(void);
void probe_console_reset(void);
void probe_puts(const char *text);
void probe_hex(uint64_t value);
void probe_field(const char *name, uint64_t value);
void probe_console_draw_qr(const uint8_t *matrix, unsigned modules);
void probe_console_rebase(uint64_t mapped_base); /* same validated surface */

#endif
