/* usb_hid.c — USB HID boot-protocol keyboard driver */
#include "usb_hid.h"
#include "printk.h"

/* Forward declaration — implemented in kbd.c (Phase 22 Task 4) */
void kbd_usb_inject(uint8_t ascii);

/* Previous report for detecting key press/release transitions */
static usb_hid_report_t s_prev_report;

/* HID usage ID → ASCII (unshifted). Index = HID usage ID. */
static const char hid_to_ascii[128] = {
    [0x04] = 'a', [0x05] = 'b', [0x06] = 'c', [0x07] = 'd',
    [0x08] = 'e', [0x09] = 'f', [0x0A] = 'g', [0x0B] = 'h',
    [0x0C] = 'i', [0x0D] = 'j', [0x0E] = 'k', [0x0F] = 'l',
    [0x10] = 'm', [0x11] = 'n', [0x12] = 'o', [0x13] = 'p',
    [0x14] = 'q', [0x15] = 'r', [0x16] = 's', [0x17] = 't',
    [0x18] = 'u', [0x19] = 'v', [0x1A] = 'w', [0x1B] = 'x',
    [0x1C] = 'y', [0x1D] = 'z',
    [0x1E] = '1', [0x1F] = '2', [0x20] = '3', [0x21] = '4',
    [0x22] = '5', [0x23] = '6', [0x24] = '7', [0x25] = '8',
    [0x26] = '9', [0x27] = '0',
    [0x28] = '\r',  /* Enter */
    [0x29] = 0x1B,  /* Escape */
    [0x2A] = 127,   /* Backspace → DEL (0x7F) */
    [0x2B] = '\t',  /* Tab */
    [0x2C] = ' ',   /* Space */
    [0x2D] = '-', [0x2E] = '=', [0x2F] = '[', [0x30] = ']',
    [0x31] = '\\', [0x33] = ';', [0x34] = '\'', [0x35] = '`',
    [0x36] = ',', [0x37] = '.', [0x38] = '/',
};

/* HID usage ID → ASCII (shifted) */
static const char hid_to_ascii_shift[128] = {
    [0x04] = 'A', [0x05] = 'B', [0x06] = 'C', [0x07] = 'D',
    [0x08] = 'E', [0x09] = 'F', [0x0A] = 'G', [0x0B] = 'H',
    [0x0C] = 'I', [0x0D] = 'J', [0x0E] = 'K', [0x0F] = 'L',
    [0x10] = 'M', [0x11] = 'N', [0x12] = 'O', [0x13] = 'P',
    [0x14] = 'Q', [0x15] = 'R', [0x16] = 'S', [0x17] = 'T',
    [0x18] = 'U', [0x19] = 'V', [0x1A] = 'W', [0x1B] = 'X',
    [0x1C] = 'Y', [0x1D] = 'Z',
    [0x1E] = '!', [0x1F] = '@', [0x20] = '#', [0x21] = '$',
    [0x22] = '%', [0x23] = '^', [0x24] = '&', [0x25] = '*',
    [0x26] = '(', [0x27] = ')',
    [0x28] = '\r', [0x29] = 0x1B, [0x2A] = '\b', [0x2B] = '\t',
    [0x2C] = ' ',
    [0x2D] = '_', [0x2E] = '+', [0x2F] = '{', [0x30] = '}',
    [0x31] = '|', [0x33] = ':', [0x34] = '"', [0x35] = '~',
    [0x36] = '<', [0x37] = '>', [0x38] = '?',
};

void usb_hid_process_report(const uint8_t *data, uint32_t len)
{
    uint32_t i, j;
    uint8_t shift;
    uint8_t ctrl;

    /* (The per-report [KBD-DBG] diagnostic that lived here was removed
     * with the 1.1.1 regression closed; /proc/kbdstat carries the USB
     * delivery counter. The open USB Ctrl+Alt+I gap is tracked in
     * TODO.md and doesn't need per-report serial spam to debug.) */
    if (len < 8) return;

    const usb_hid_report_t *report = (const usb_hid_report_t *)data;
    shift = (report->modifier & (HID_MOD_LSHIFT | HID_MOD_RSHIFT)) != 0;
    ctrl  = (report->modifier & (HID_MOD_LCTRL  | HID_MOD_RCTRL))  != 0;

    /* Find newly pressed keys (in current report but not in previous) */
    for (i = 0; i < 6; i++) {
        uint8_t key = report->keys[i];
        if (key == 0) continue;

        /* Check if this key was already pressed in previous report */
        int already_pressed = 0;
        for (j = 0; j < 6; j++) {
            if (s_prev_report.keys[j] == key) {
                already_pressed = 1;
                break;
            }
        }
        if (already_pressed) continue;

        /* Arrow keys → emit ANSI ESC [ A/B/C/D triplet
         * (matches PS/2 driver's handling of E0-prefixed arrows). */
        char arrow = 0;
        switch (key) {
        case 0x4F: arrow = 'C'; break;  /* right arrow */
        case 0x50: arrow = 'D'; break;  /* left arrow  */
        case 0x51: arrow = 'B'; break;  /* down arrow  */
        case 0x52: arrow = 'A'; break;  /* up arrow    */
        }
        if (arrow) {
            kbd_usb_inject(0x1B);
            kbd_usb_inject('[');
            kbd_usb_inject((uint8_t)arrow);
            continue;
        }

        /* New key press — translate to ASCII */
        char ascii = 0;
        if (ctrl && key >= 0x04 && key <= 0x1D) {
            /* Ctrl+a through Ctrl+z → ASCII 1–26 */
            ascii = (char)(key - 0x04 + 1);
        } else if (key < 128) {
            ascii = shift ? hid_to_ascii_shift[key] : hid_to_ascii[key];
        }

        if (ascii != 0)
            kbd_usb_inject((uint8_t)ascii);
    }

    /* Save current report */
    s_prev_report.modifier = report->modifier;
    s_prev_report.reserved = report->reserved;
    for (i = 0; i < 6; i++) s_prev_report.keys[i] = report->keys[i];
}
