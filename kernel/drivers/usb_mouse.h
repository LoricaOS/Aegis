/* usb_mouse.h — USB HID boot-protocol mouse driver
 *
 * Parses 3-byte HID boot reports into mouse_event_t structs.
 * Delivers events via a ring buffer read by /dev/mouse.
 */
#ifndef USB_MOUSE_H
#define USB_MOUSE_H

#include <stdint.h>

/* Mouse event delivered to userspace via /dev/mouse read().
 * 7 bytes packed — userspace reads in multiples of sizeof(mouse_event_t). */
typedef struct __attribute__((packed)) {
    uint8_t  buttons;   /* bit 0=left, bit 1=right, bit 2=middle */
    int16_t  dx;        /* X delta (positive = right) */
    int16_t  dy;        /* Y delta (positive = down) */
    int16_t  scroll;    /* wheel delta (+up/−down); 0 if no wheel */
} mouse_event_t;

/* Process an incoming HID boot-protocol mouse report (3+ bytes).
 * Called from xhci_poll() in ISR context (PIT tick). */
void usb_mouse_process_report(const uint8_t *data, uint32_t len);

/* Non-blocking poll: copy one event into *out if available.
 * Returns 1 if an event was copied, 0 if ring buffer is empty. */
int mouse_poll(mouse_event_t *out);

/* Blocking read: sleep until at least one event is available, then copy it.
 * Called from VFS read path in syscall context. */
void mouse_read_blocking(mouse_event_t *out);

/* Inject a mouse event from any source (PS/2, USB, etc.) into the
 * shared ring buffer. Called from ISR context. */
void mouse_inject(uint8_t buttons, int16_t dx, int16_t dy);

/* Same, with a wheel delta (IntelliMouse PS/2). mouse_inject() is the
 * scroll=0 wrapper, so the USB boot-protocol path stays untouched. */
void mouse_inject_scroll(uint8_t buttons, int16_t dx, int16_t dy,
                         int16_t scroll);

#endif /* USB_MOUSE_H */
