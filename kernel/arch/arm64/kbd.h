#ifndef AEGIS_KBD_H
#define AEGIS_KBD_H

#include <stdint.h>

/* Console input on arm64 = PL011 RX (uart_pl011.c). Same interface as the
 * x86 PS/2 kbd.h so kernel/fs/kbd_vfs.c + procfs are arch-oblivious. */

void kbd_init(void);
char kbd_read(void);
int  kbd_poll(char *out);
int  kbd_has_data(void);

/* Foreground process group for signal delivery (sys_setfg / tty). */
void kbd_set_tty_pgrp(uint32_t pgid);
uint32_t kbd_get_tty_pgrp(void);

/* Like kbd_read() but returns '\0' with *interrupted=1 if a signal is
 * pending for the current process. */
char kbd_read_interruptible(int *interrupted);

/* Inject a character into the input ring (serial RX path). */
void kbd_inject(char c);

/* /proc/kbdstat plumbing — arm64 has one source (serial) and no i8042. */
void kbd_stats_get(uint32_t *ps2, uint32_t *usb, uint32_t *serial);
#define KBD_I8042_ABSENT 0
void kbd_i8042_get(uint8_t *cfg, uint8_t *state);

#endif /* AEGIS_KBD_H */
