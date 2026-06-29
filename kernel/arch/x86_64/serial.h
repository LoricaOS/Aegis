#ifndef SERIAL_H
#define SERIAL_H

/* Internal to kernel/arch/x86_64/ — not included from kernel/core/ */

/* Initialize COM1 at 115200 8N1. Prints [SERIAL] OK line on success.
 * Must be called before any other serial function. */
void serial_init(void);

/* Write a single character to COM1. Spins until transmit buffer empty. */
void serial_write_char(char c);

/* Write a null-terminated string to COM1. */
void serial_write_string(const char *s);

/* Enable interrupt-driven COM1 receive (IRQ4). Call after pic_init.
 * Injects received bytes into the keyboard ring so the console/tty reads
 * serial input identically to PS/2 keystrokes. */
void serial_rx_init(void);

/* IRQ4 (vector 0x24) handler: drain the COM1 RX FIFO into the input ring. */
void serial_rx_handler(void);

#endif
