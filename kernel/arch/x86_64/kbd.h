#ifndef AEGIS_KBD_H
#define AEGIS_KBD_H

#include <stdint.h>

/* Initialize PS/2 keyboard. Unmasks IRQ1.
 * Prints [KBD] OK: PS/2 keyboard ready. */
void kbd_init(void);

/* Called by isr_dispatch on vector 0x21.
 * Reads scancode from port 0x60, converts to ASCII, pushes to ring buffer.
 * Break codes (bit 7 set) and 0xE0 extended scancodes are silently dropped. */
void kbd_handler(void);

/* Process one PS/2 Scan Code Set 1 byte (E0 prefix, break bit, shift/ctrl/alt,
 * make-code → ASCII).  Used by the PS/2 ISR and by the Hyper-V synthetic
 * keyboard (hv_kbd.c), which has no i8042 and reconstructs the set-1 byte
 * stream from VMBus keystroke events. */
void kbd_feed_scancode(uint8_t sc);

/* Blocking read — spins until a character is available in the ring buffer. */
char kbd_read(void);

/* Non-blocking read. Returns 1 and writes to *out if a char is available.
 * Returns 0 if the buffer is empty. */
int kbd_poll(char *out);

/* Non-destructive check: returns 1 if the keyboard ring buffer has data,
 * 0 if empty. Does NOT consume the character. Used by VFS .poll(). */
int kbd_has_data(void);

/* Register the foreground process group for signal delivery.
 * Called by the shell via sys_setfg (syscall 360) before waitpid.
 * Call with pgid=0 to clear (no foreground process group). */
void kbd_set_tty_pgrp(uint32_t pgid);

/* Return the current foreground process group ID.
 * Returns 0 if no foreground process group. */
uint32_t kbd_get_tty_pgrp(void);

/* Like kbd_read() but returns '\0' and sets *interrupted=1 if a signal
 * is pending for the current process. Returns the character otherwise. */
char kbd_read_interruptible(int *interrupted);

/* Inject an ASCII character from USB HID into the keyboard ring buffer.
 * Called from usb_hid_process_report() in interrupt context (PIT ISR path).
 * Shares the PS/2 ring buffer; zero bytes are silently dropped. */
void kbd_usb_inject(uint8_t ascii);

/* Inject a byte received over the serial console (COM1) into the keyboard
 * ring buffer. Called from serial_rx_handler() in interrupt context.
 * Shares the PS/2 ring buffer; zero bytes are silently dropped. */
void kbd_inject(char c);

/* Input-source event counters (PS/2 IRQ1 bytes, USB HID reports, serial RX
 * bytes). Exposed via /proc/kbdstat for on-screen input diagnostics. */
void kbd_stats_get(uint32_t *ps2, uint32_t *usb, uint32_t *serial);

/* i8042 bring-up outcome — also exposed via /proc/kbdstat. */
#define KBD_I8042_ABSENT   0  /* no responsive controller */
#define KBD_I8042_DEV_OK   1  /* configured; device reset (0xFF→BAT) passed */
#define KBD_I8042_DEV_F4   2  /* configured; reset refused but 0xF4 ACKed */
#define KBD_I8042_DEV_NONE 3  /* configured; no device on port 1 (USB-only) */
#define KBD_I8042_CFG_FAIL 4  /* controller present but config unreadable */
void kbd_i8042_get(uint8_t *cfg, uint8_t *state);

#endif /* AEGIS_KBD_H */
