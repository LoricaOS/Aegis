#ifndef VGA_H
#define VGA_H

/* Internal to kernel/arch/x86_64/ — not included from kernel/core/.
 * vga_available is declared in arch.h for use by printk. */

/* Set to 1 by vga_init() on success. Checked by printk via arch.h. */
extern int vga_available;

/* Initialize VGA text mode 80x25. Clears screen, sets vga_available=1,
 * prints [VGA] OK line. Must be called after serial_init(). */
void vga_init(void);

/* Write a single character to the VGA text buffer. Handles \n. */
void vga_write_char(char c);

/* Write a null-terminated string to the VGA text buffer. */
void vga_write_string(const char *s);

/* Write a single character with full cursor tracking, scrolling, and
 * interrupt-flag preservation (pushfq/popfq). Use this for interactive
 * output. vga_write_string routes through vga_putchar. */
void vga_putchar(char c);

#endif
