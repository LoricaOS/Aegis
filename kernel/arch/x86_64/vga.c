#include "vga.h"
#include "serial.h"
#include "arch.h"   /* outb, uint8_t, uint16_t, uint64_t */

/*
 * VGA text-mode driver — x86_64 higher-half kernel.
 *
 * The physical VGA framebuffer is at 0xB8000.  After Phase 3 the kernel
 * runs at 0xFFFFFFFF80000000, so the correct virtual address is:
 *   0xFFFFFFFF80000000 + 0xB8000 = 0xFFFFFFFF800B8000
 * The identity map [0..4MB) is still active, so 0xB8000 also works for
 * now, but we use the higher-half address exclusively so this driver
 * survives identity-map teardown in Phase 4.
 */

#define VGA_PHYS    0xFFFFFFFF800B8000UL
#define VGA_COLS    80
#define VGA_ROWS    25
#define VGA_ATTR    0x07    /* light grey on black */

int vga_available = 0;

static int s_row = 0;
static int s_col = 0;

/* ANSI CSI escape-sequence state machine — mirrors fb.c. */
static int  s_esc_state = 0;
static char s_esc_buf[16];
static int  s_esc_len   = 0;

/* vga_cell — encode a character + attribute as a 16-bit VGA cell. */
static inline uint16_t
vga_cell(char c, uint8_t attr)
{
    return (uint16_t)((uint8_t)c) | ((uint16_t)attr << 8);
}

/* vga_set_cursor — program the CRTC hardware text cursor position.
 * Uses port I/O to CGA/VGA CRTC registers 0x3D4/0x3D5.
 * Only called when vga_available is set, ensuring CRTC is initialised. */
static void
vga_set_cursor(int row, int col)
{
    uint16_t pos = (uint16_t)(row * VGA_COLS + col);
    outb(0x3D4, 0x0F); outb(0x3D5, (uint8_t)(pos & 0xFF));
    outb(0x3D4, 0x0E); outb(0x3D5, (uint8_t)((pos >> 8) & 0xFF));
}

static void
_vga_clear_screen(void)
{
    volatile uint16_t *vga = (volatile uint16_t *)VGA_PHYS;
    int i;
    for (i = 0; i < VGA_ROWS * VGA_COLS; i++)
        vga[i] = vga_cell(' ', VGA_ATTR);
    s_row = 0;
    s_col = 0;
    if (vga_available)
        vga_set_cursor(0, 0);
}

static void
_vga_dispatch_csi(char cmd)
{
    if (cmd == 'J') {
        if (s_esc_len == 1 && s_esc_buf[0] == '2')
            _vga_clear_screen();
    } else if (cmd == 'H' || cmd == 'f') {
        int row = 0, col = 0, i = 0;
        while (i < s_esc_len && s_esc_buf[i] >= '0' && s_esc_buf[i] <= '9')
            row = row * 10 + (s_esc_buf[i++] - '0');
        if (row > 0) row--;
        if (i < s_esc_len && s_esc_buf[i] == ';') {
            i++;
            while (i < s_esc_len && s_esc_buf[i] >= '0' && s_esc_buf[i] <= '9')
                col = col * 10 + (s_esc_buf[i++] - '0');
            if (col > 0) col--;
        }
        s_row = (row < VGA_ROWS) ? row : VGA_ROWS - 1;
        s_col = (col < VGA_COLS) ? col : VGA_COLS - 1;
        if (vga_available)
            vga_set_cursor(s_row, s_col);
    }
}

/* vga_scroll — shift rows 1-24 up to rows 0-23, clear the bottom row. */
static void
vga_scroll(void)
{
    volatile uint16_t *vga = (volatile uint16_t *)VGA_PHYS;
    int r, c;
    for (r = 0; r < VGA_ROWS - 1; r++)
        for (c = 0; c < VGA_COLS; c++)
            vga[r * VGA_COLS + c] = vga[(r + 1) * VGA_COLS + c];
    /* Clear bottom row */
    for (c = 0; c < VGA_COLS; c++)
        vga[(VGA_ROWS - 1) * VGA_COLS + c] = vga_cell(' ', VGA_ATTR);
    s_row = VGA_ROWS - 1;
}

void
vga_putchar(char c)
{
    /*
     * Save and restore RFLAGS.IF around VGA buffer writes.
     * - Before IDT is installed: IF=0; popfq restores 0, no spurious
     *   interrupt fires.
     * - In ISR context: IF=0; same as above.
     * - In task context: IF=1; restored to 1 after the write, so
     *   interrupts are re-enabled exactly where they were.
     */
    uint64_t flags;
    __asm__ volatile ("pushfq; cli; popq %0" : "=r"(flags) : : "memory");

    /* ANSI CSI state machine */
    if (s_esc_state == 1) {
        if (c == '[') {
            s_esc_state = 2;
            s_esc_len   = 0;
        } else {
            s_esc_state = 0;
        }
        __asm__ volatile ("pushq %0; popfq" : : "r"(flags) : "memory");
        return;
    }
    if (s_esc_state == 2) {
        if ((c >= '0' && c <= '9') || c == ';') {
            if (s_esc_len < 15)
                s_esc_buf[s_esc_len++] = c;
            __asm__ volatile ("pushq %0; popfq" : : "r"(flags) : "memory");
            return;
        }
        s_esc_state          = 0;
        s_esc_buf[s_esc_len] = '\0';
        _vga_dispatch_csi(c);
        __asm__ volatile ("pushq %0; popfq" : : "r"(flags) : "memory");
        return;
    }
    if (c == '\033') {
        s_esc_state = 1;
        __asm__ volatile ("pushq %0; popfq" : : "r"(flags) : "memory");
        return;
    }

    volatile uint16_t *vga = (volatile uint16_t *)VGA_PHYS;

    if (c == '\n') {
        s_col = 0;
        s_row++;
    } else if (c == '\r') {
        s_col = 0;
    } else if (c == '\b') {
        if (s_col > 0) {
            s_col--;
            vga[s_row * VGA_COLS + s_col] = vga_cell(' ', VGA_ATTR);
        }
    } else {
        vga[s_row * VGA_COLS + s_col] = vga_cell(c, VGA_ATTR);
        s_col++;
        if (s_col >= VGA_COLS) {
            s_col = 0;
            s_row++;
        }
    }

    if (s_row >= VGA_ROWS)
        vga_scroll();

    /* Only program the CRTC cursor after vga_init() has succeeded. */
    if (vga_available)
        vga_set_cursor(s_row, s_col);

    __asm__ volatile ("pushq %0; popfq" : : "r"(flags) : "memory");
}

void
vga_init(void)
{
    volatile uint16_t *vga = (volatile uint16_t *)VGA_PHYS;
    int i;
    /* Clear entire screen */
    for (i = 0; i < VGA_ROWS * VGA_COLS; i++)
        vga[i] = vga_cell(' ', VGA_ATTR);
    s_col = 0;
    s_row = 0;
    vga_available = 1;

    /* Enable hardware text cursor — underline style (scanlines 13-15).
     * GRUB may have disabled it; re-enable via CRTC registers 0x0A/0x0B. */
    outb(0x3D4, 0x0A); outb(0x3D5, 0x0D);  /* cursor start scanline 13 */
    outb(0x3D4, 0x0B); outb(0x3D5, 0x0F);  /* cursor end scanline 15 */
    vga_set_cursor(0, 0);

    /* Print directly — printk is not yet up at this point */
    vga_write_string("[VGA] OK: text mode 80x25\n");
    serial_write_string("[VGA] OK: text mode 80x25\n");
}

void
vga_write_char(char c)
{
    vga_putchar(c);
}

void
vga_write_string(const char *s)
{
    while (*s)
        vga_putchar(*s++);
}
