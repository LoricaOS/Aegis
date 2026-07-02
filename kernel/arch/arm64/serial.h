#ifndef ARM64_SERIAL_H
#define ARM64_SERIAL_H

/* PL011 serial (uart_pl011.c). */
void serial_init(void);
void serial_putc(char c);
void serial_write_string(const char *s);
void serial_set_base(volatile void *va);

#endif /* ARM64_SERIAL_H */
