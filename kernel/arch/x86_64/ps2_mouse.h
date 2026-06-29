/* ps2_mouse.h — PS/2 auxiliary port mouse driver */
#ifndef AEGIS_PS2_MOUSE_H
#define AEGIS_PS2_MOUSE_H

/* Initialize PS/2 mouse on the i8042 auxiliary port.
 * Enables IRQ12. Prints [MOUSE] OK line. */
void ps2_mouse_init(void);

/* IRQ12 handler — reads byte from port 0x60, assembles 3-byte packets,
 * injects mouse events into the shared ring buffer. */
void ps2_mouse_handler(void);

#endif /* AEGIS_PS2_MOUSE_H */
