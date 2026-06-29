/* ps2_mouse.c — PS/2 auxiliary port mouse driver
 *
 * Initializes the i8042 auxiliary (mouse) port and handles IRQ12.
 * Parses standard 3-byte PS/2 mouse packets and injects events
 * into the shared mouse ring buffer via mouse_inject().
 *
 * PS/2 mouse packet format (3 bytes):
 *   Byte 0: [YO XO YS XS 1 MB RB LB]
 *     bits 0-2: left/right/middle buttons
 *     bits 4-5: X/Y sign bits
 *     bits 6-7: X/Y overflow (discard packet if set)
 *   Byte 1: X movement (unsigned, sign in byte 0 bit 4)
 *   Byte 2: Y movement (unsigned, sign in byte 0 bit 5)
 *
 * Y axis: PS/2 convention is positive = up, but Aegis (and USB HID)
 * uses positive = down. We negate Y before injecting.
 */
#include "arch.h"
#include "pic.h"
#include "printk.h"
#include "usb_mouse.h"

#define KBD_DATA    0x60
#define KBD_STATUS  0x64
#define KBD_CMD     0x64

/* Wait until the i8042 input buffer is empty (bit 1 of status = 0).
 * Must be clear before writing to port 0x60 or 0x64. */
static void
i8042_wait_write(void)
{
    uint32_t timeout = 100000;
    while (timeout--) {
        if (!(inb(KBD_STATUS) & 0x02))
            return;
    }
}

/* Wait until the i8042 output buffer is full (bit 0 of status = 1).
 * Must be set before reading from port 0x60. */
static void
i8042_wait_read(void)
{
    uint32_t timeout = 100000;
    while (timeout--) {
        if (inb(KBD_STATUS) & 0x01)
            return;
    }
}

/* Send a command byte to the i8042 controller (port 0x64). */
static void
i8042_cmd(uint8_t cmd)
{
    i8042_wait_write();
    outb(KBD_CMD, cmd);
}

/* Send a byte to the mouse (via i8042 auxiliary port).
 * Sends 0xD4 command to i8042, then the data byte to port 0x60.
 * Returns the ACK byte (0xFA on success). */
static uint8_t
mouse_write(uint8_t data)
{
    i8042_cmd(0xD4);         /* next byte goes to auxiliary device */
    i8042_wait_write();
    outb(KBD_DATA, data);
    i8042_wait_read();
    return inb(KBD_DATA);   /* read ACK (0xFA) */
}

/* Packet assembly state. s_packet_len is 3 for a plain PS/2 mouse, 4 once
 * IntelliMouse (wheel) mode is negotiated — byte 3 then carries the Z delta. */
static uint8_t s_packet[4];
static int     s_byte_index = 0;
static int     s_packet_len = 3;

/* Set the mouse sample rate (0xF3 <rate>). Used both normally and as the
 * "knock sequence" 200,100,80 that asks a wheel mouse to reveal itself. */
static void
mouse_set_sample_rate(uint8_t rate)
{
    mouse_write(0xF3);
    mouse_write(rate);
}

/* Try to switch the mouse into IntelliMouse (Z-wheel) mode. The magic
 * sample-rate knock (200,100,80) makes a wheel mouse report device id 0x03
 * and start sending 4-byte packets. Returns the resulting device id. */
static uint8_t
mouse_enable_wheel(void)
{
    mouse_set_sample_rate(200);
    mouse_set_sample_rate(100);
    mouse_set_sample_rate(80);
    /* Read device id (0xF2 → ACK + id). */
    mouse_write(0xF2);
    i8042_wait_read();
    return inb(KBD_DATA);
}

void
ps2_mouse_init(void)
{
    /* Enable the auxiliary PS/2 port */
    i8042_cmd(0xA8);         /* enable auxiliary port */

    /* Read the controller configuration byte */
    i8042_cmd(0x20);         /* read config byte */
    i8042_wait_read();
    uint8_t config = inb(KBD_DATA);

    /* Enable auxiliary port interrupt (bit 1) and clear disable bit (bit 5) */
    config |= 0x02;          /* enable IRQ12 */
    config &= ~0x20;         /* clear "disable auxiliary port" */

    /* Write back config */
    i8042_cmd(0x60);         /* write config byte */
    i8042_wait_write();
    outb(KBD_DATA, config);

    /* Reset mouse — send 0xFF, expect 0xFA (ACK) + 0xAA (self-test pass) + 0x00 (device ID) */
    mouse_write(0xFF);
    i8042_wait_read();
    (void)inb(KBD_DATA);    /* 0xAA self-test */
    i8042_wait_read();
    (void)inb(KBD_DATA);    /* 0x00 device ID */

    /* Set defaults (0xF6) */
    mouse_write(0xF6);

    /* Negotiate the scroll wheel. A wheel mouse answers the magic knock with
     * device id 0x03 and switches to 4-byte packets; anything else stays
     * 3-byte. QEMU's PS/2 mouse supports this. */
    uint8_t id = mouse_enable_wheel();
    if (id == 0x03) {
        s_packet_len = 4;
        printk("[MOUSE] OK: PS/2 wheel mouse (IntelliMouse, 4-byte packets)\n");
    } else {
        s_packet_len = 3;
    }

    /* Enable data reporting (0xF4) */
    mouse_write(0xF4);

    /* Unmask IRQ12 */
    pic_unmask(12);

    printk("[MOUSE] OK: PS/2 mouse ready\n");
}

void
ps2_mouse_handler(void)
{
    uint8_t data = inb(KBD_DATA);

    /* Byte 0 must have bit 3 set (always-1 bit in PS/2 protocol).
     * If not, we're out of sync — reset to byte 0. */
    if (s_byte_index == 0 && !(data & 0x08)) {
        return;  /* discard, wait for valid byte 0 */
    }

    s_packet[s_byte_index++] = data;

    if (s_byte_index < s_packet_len)
        return;  /* wait for more bytes */

    /* Full packet received — parse it */
    s_byte_index = 0;

    uint8_t flags = s_packet[0];

    /* Discard if overflow bits set (bits 6 or 7) */
    if (flags & 0xC0)
        return;

    /* Buttons: bit 0 = left, bit 1 = right, bit 2 = middle */
    uint8_t buttons = flags & 0x07;

    /* X delta: unsigned byte with sign in flags bit 4 */
    int16_t dx = (int16_t)s_packet[1];
    if (flags & 0x10)
        dx = dx - 256;  /* sign-extend: 0x10 set means negative */

    /* Y delta: unsigned byte with sign in flags bit 5.
     * PS/2: positive = up. Aegis: positive = down. Negate. */
    int16_t dy = (int16_t)s_packet[2];
    if (flags & 0x20)
        dy = dy - 256;
    dy = -dy;  /* invert for screen coordinates */

    /* Z (wheel) delta: byte 3 low nibble, 4-bit two's complement
     * (IntelliMouse). PS/2 reports +1 per notch scrolled DOWN, so negate
     * to match "positive = up". Only present in 4-byte mode. */
    int16_t scroll = 0;
    if (s_packet_len == 4) {
        int8_t z = (int8_t)(s_packet[3] & 0x0F);
        if (z & 0x08) z |= (int8_t)0xF0;  /* sign-extend 4-bit */
        scroll = (int16_t)(-z);
    }

    mouse_inject_scroll(buttons, dx, dy, scroll);
}
