/*
 * Tiny polled diagnostic sink, shared by normal entry and fatal exceptions.
 * No allocator, libc, interrupts or device driver. Original 5x7 glyphs.
 */
#include "probe_console.h"
#include <stdint.h>
#if defined(APPLE_KERNEL_BRIDGE) || defined(AEGIS_APPLE_CHECKPOINT)
#include "qrcodegen.h"
uint32_t apple_probe_qr_rect[4];
#endif

char apple_probe_console_text[8192];
uint64_t apple_probe_console_length;

static struct fdt_bootfb surface;
static uint32_t panel_w, panel_h, scale, column, row, white;
static int ready;

static const uint8_t glyphs[128][7] = {
    ['A']={14,17,17,31,17,17,17}, ['B']={30,17,17,30,17,17,30},
    ['C']={14,17,16,16,16,17,14}, ['D']={30,17,17,17,17,17,30},
    ['E']={31,16,16,30,16,16,31}, ['F']={31,16,16,30,16,16,16},
    ['G']={14,17,16,23,17,17,14}, ['H']={17,17,17,31,17,17,17},
    ['I']={31,4,4,4,4,4,31}, ['J']={7,2,2,2,2,18,12},
    ['K']={17,18,20,24,20,18,17}, ['L']={16,16,16,16,16,16,31},
    ['M']={17,27,21,21,17,17,17}, ['N']={17,25,21,19,17,17,17},
    ['O']={14,17,17,17,17,17,14}, ['P']={30,17,17,30,16,16,16},
    ['Q']={14,17,17,17,21,18,13}, ['R']={30,17,17,30,20,18,17},
    ['S']={15,16,16,14,1,1,30}, ['T']={31,4,4,4,4,4,4},
    ['U']={17,17,17,17,17,17,14}, ['V']={17,17,17,17,17,10,4},
    ['W']={17,17,17,21,21,21,10}, ['X']={17,17,10,4,10,17,17},
    ['Y']={17,17,10,4,4,4,4}, ['Z']={31,1,2,4,8,16,31},
    ['0']={14,17,19,21,25,17,14}, ['1']={4,12,4,4,4,4,14},
    ['2']={14,17,1,2,4,8,31}, ['3']={30,1,1,14,1,1,30},
    ['4']={2,6,10,18,31,2,2}, ['5']={31,16,16,30,1,1,30},
    ['6']={14,16,16,30,17,17,14}, ['7']={31,1,2,4,8,8,8},
    ['8']={14,17,17,14,17,17,14}, ['9']={14,17,17,15,1,1,14},
    ['=']={0,0,31,0,31,0,0}, ['-']={0,0,0,31,0,0,0},
    [':']={0,4,4,0,4,4,0}, ['.']={0,0,0,0,0,4,4},
    ['/']={1,2,2,4,8,8,16}, ['?']={14,17,1,2,4,0,4},
    ['(']={2,4,8,8,8,4,2}, [')']={8,4,2,2,2,4,8},
};

static void pixel(uint32_t x, uint32_t y, uint32_t color)
{
    volatile uint32_t *p = (volatile uint32_t *)(uintptr_t)surface.base;
    p[(uint64_t)(y + 16) * (surface.stride / 4) + x + 16] = color;
}

static void clear_panel(void)
{
    column = row = 0;
    if (ready)
        for (uint32_t y = 0; y < panel_h; y++)
            for (uint32_t x = 0; x < panel_w; x++)
                pixel(x, y, 0);
}

#if defined(APPLE_KERNEL_BRIDGE) || defined(AEGIS_APPLE_CHECKPOINT)
void probe_console_draw_qr(const uint8_t *matrix, unsigned modules)
{
    /* Separate right-hand box; never overwrite text or exceed the validated
     * framebuffer. Four-module white quiet zone on every edge. */
    if (!ready || !matrix || modules < 21 || modules > 177) return;
    unsigned x0 = panel_w + 32, extent = modules + 8, zoom = 8;
    if (x0 >= surface.width - 32) return;
    unsigned available = surface.width - 32 - x0;
    while (zoom >= 2 && (extent * zoom > available || extent * zoom > panel_h)) zoom--;
    if (zoom < 2) return; /* small synthetic displays retain text only */
    for (unsigned y = 0; y < extent * zoom; y++)
        for (unsigned x = 0; x < extent * zoom; x++) {
            int mx = (int)(x / zoom) - 4, my = (int)(y / zoom) - 4;
            int dark = mx >= 0 && my >= 0 && mx < (int)modules && my < (int)modules &&
                       qrcodegen_getModule(matrix, mx, my);
            pixel(x0 + x, y, dark ? 0 : white);
        }
    apple_probe_qr_rect[0] = x0 + 16;
    apple_probe_qr_rect[1] = 16;
    apple_probe_qr_rect[2] = apple_probe_qr_rect[3] = extent * zoom;
}
#endif

void probe_console_init(const struct fdt_bootfb *fb)
{
    surface = *fb;
    panel_w = fb->width - 32;
    panel_h = fb->height - 32;
    if (panel_w > 1400) panel_w = 1400;
    if (panel_h > 1100) panel_h = 1100;
    scale = fb->width >= 1600 && fb->height >= 900 ? 4 : 1;
    white = fb->format == FDT_FB_XRGB2101010 ? 0x3fffffff : 0xffffff;
    ready = 1;
    clear_panel();
}

void probe_console_fault(void)
{
    /* Keep the append-only RAM transcript, but put the fatal report at the
     * top of the panel so even a small framebuffer can show it. */
    clear_panel();
}

void probe_console_reset(void)
{
    clear_panel();
}

void probe_console_rebase(uint64_t mapped_base)
{
    /* Bootstrap-only: caller has prepared the identical Device framebuffer
     * mapping and must not print between rebasing and switching tables. */
    surface.base = mapped_base;
}

static void putc(char c)
{
    if (apple_probe_console_length < sizeof(apple_probe_console_text) - 1) {
        apple_probe_console_text[apple_probe_console_length++] = c;
        apple_probe_console_text[apple_probe_console_length] = 0;
    }
    if (!ready)
        return;
    if (c == '\n') {
        column = 0;
        row++;
        return;
    }
    if (column >= panel_w / (6 * scale)) {
        column = 0;
        row++;
    }
    if (row >= panel_h / (8 * scale))
        return;                         /* bounded clipping; no scrolling */
    unsigned ch = (unsigned char)c;
    if (ch >= 'a' && ch <= 'z') ch -= 'a' - 'A';
    if (ch >= 128) ch = '?';
    for (uint32_t y = 0; y < 8 * scale; y++)
        for (uint32_t x = 0; x < 6 * scale; x++) {
            uint32_t bit = x / scale, line = y / scale;
            int on = bit < 5 && line < 7 &&
                     (glyphs[ch][line] & (1u << (4 - bit)));
            pixel(column * 6 * scale + x, row * 8 * scale + y, on ? white : 0);
        }
    column++;
}

void probe_puts(const char *text)
{
    while (*text) putc(*text++);
}

void probe_hex(uint64_t value)
{
    probe_puts("0X");
    for (int shift = 60; shift >= 0; shift -= 4)
        putc("0123456789ABCDEF"[(value >> shift) & 15]);
}

void probe_field(const char *name, uint64_t value)
{
    probe_puts(name);
    probe_puts("=");
    probe_hex(value);
    probe_puts("\n");
}
