/* usb_hid.h — USB HID boot-protocol keyboard driver
 *
 * Parses 8-byte HID boot reports and converts to ASCII.
 * Injects keystrokes into PS/2 keyboard ring buffer.
 */
#ifndef USB_HID_H
#define USB_HID_H

#include <stdint.h>

/* HID boot-protocol report: 8 bytes
 * [0] modifier keys (bitfield)
 * [1] reserved
 * [2..7] key codes (HID usage IDs, 0 = no key) */
typedef struct __attribute__((packed)) {
    uint8_t modifier;
    uint8_t reserved;
    uint8_t keys[6];
} usb_hid_report_t;

/* Modifier key bits */
#define HID_MOD_LCTRL   (1u << 0)
#define HID_MOD_LSHIFT  (1u << 1)
#define HID_MOD_LALT    (1u << 2)
#define HID_MOD_LGUI    (1u << 3)
#define HID_MOD_RCTRL   (1u << 4)
#define HID_MOD_RSHIFT  (1u << 5)
#define HID_MOD_RALT    (1u << 6)
#define HID_MOD_RGUI    (1u << 7)

/* Process an incoming HID boot-protocol report.
 * Compares with previous report to detect key press/release events.
 * Calls kbd_usb_inject() for newly pressed keys. */
void usb_hid_process_report(const uint8_t *data, uint32_t len);

#endif /* USB_HID_H */
