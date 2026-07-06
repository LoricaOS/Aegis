/* kernel/drivers/panic_screen.c — Panic bluescreen + boot splash rendering.
 *
 * This file is #include'd from fb.c — it is NOT a separate compilation unit.
 * It uses fb.c's static framebuffer state (s_fb_va, s_fb_width, s_fb_height,
 * s_pitch_px, s_fb_locked, fb_available) directly.
 *
 * Extracted from fb.c to keep the framebuffer terminal code separate from
 * the panic/splash rendering code.
 */

#include "terminus20.h"
#include "logo_panic.h"
#include "logo_boot.h"
#include "pvpanic.h"

/* ── Panic Bluescreen ──────────────────────────────────────────────────── */

#define PANIC_BG    0x001133AAu   /* deep blue */
#define PANIC_FG    0x00FFFFFFu   /* white */
#define PANIC_TITLE 0x00FFFFFFu   /* white title */
#define PANIC_DIM   0x00AABBCCu   /* dimmed text for secondary info */
#define PANIC_FONT_W 10
#define PANIC_FONT_H 20

static void
_panic_draw_char(uint32_t px_x, uint32_t px_y, char c, uint32_t fg)
{
    const uint8_t *glyph = &font_terminus[(uint8_t)c * PANIC_FONT_H * 2];
    uint32_t row, col;
    for (row = 0; row < PANIC_FONT_H; row++) {
        uint16_t bits = ((uint16_t)glyph[row * 2] << 8) | glyph[row * 2 + 1];
        for (col = 0; col < PANIC_FONT_W; col++) {
            uint32_t color = (bits & (0x8000u >> col)) ? fg : PANIC_BG;
            uint32_t idx = (px_y + row) * s_pitch_px + (px_x + col);
            s_fb_va[idx] = color;
        }
    }
}

static void
_panic_draw_string(uint32_t *px_x, uint32_t px_y, const char *s, uint32_t fg)
{
    while (*s) {
        if (*px_x + PANIC_FONT_W > s_fb_width)
            break;
        _panic_draw_char(*px_x, px_y, *s, fg);
        *px_x += PANIC_FONT_W;
        s++;
    }
}

#ifdef __x86_64__
/* _panic_draw_hex is only consumed by panic_bluescreen which is
 * x86-64-only. Keep the helper under the same guard to avoid
 * -Wunused-function when ARM64 includes this file via fb.c. */
static void
_panic_draw_hex(uint32_t *px_x, uint32_t px_y, uint64_t val, uint32_t fg)
{
    char buf[19]; /* "0x" + 16 hex digits + NUL */
    buf[0] = '0';
    buf[1] = 'x';
    int i;
    for (i = 15; i >= 0; i--) {
        uint8_t nib = (uint8_t)(val & 0xF);
        buf[2 + i] = (nib < 10) ? ('0' + nib) : ('a' + nib - 10);
        val >>= 4;
    }
    buf[18] = '\0';
    _panic_draw_string(px_x, px_y, buf, fg);
}
#endif /* __x86_64__ */

/* Blit a white-on-transparent logo (8-bit coverage mask) onto the framebuffer,
 * alpha-blended over bg. `scale` box-averages a scale*scale source block per
 * output pixel (scale=1 full size, scale=2 half, ...) so one full-res mask
 * serves any display size. The art is greyscale, so a single coverage byte per
 * pixel reproduces it: out = white*cov + bg*(255-cov). */
static void
_blit_logo_cov(const unsigned char *cov, uint32_t logo_w, uint32_t logo_h,
               uint32_t dst_x, uint32_t dst_y, uint32_t bg, uint32_t scale)
{
    uint32_t bg_r = (bg >> 16) & 0xFF;
    uint32_t bg_g = (bg >> 8)  & 0xFF;
    uint32_t bg_b =  bg        & 0xFF;
    uint32_t ow = logo_w / scale, oh = logo_h / scale;
    uint32_t y, x;
    for (y = 0; y < oh; y++) {
        if (dst_y + y >= s_fb_height) break;
        for (x = 0; x < ow; x++) {
            if (dst_x + x >= s_fb_width) break;
            /* box-average the scale*scale source block */
            uint32_t sum = 0, n = 0, yy, xx;
            for (yy = 0; yy < scale; yy++)
                for (xx = 0; xx < scale; xx++) {
                    sum += cov[(y * scale + yy) * logo_w + (x * scale + xx)];
                    n++;
                }
            uint32_t a = sum / n;
            if (a == 0) continue;  /* fully transparent */
            uint32_t r, g, b;
            if (a >= 255) {
                r = g = b = 255;   /* pure white */
            } else {
                r = (255 * a + bg_r * (255 - a)) / 255;
                g = (255 * a + bg_g * (255 - a)) / 255;
                b = (255 * a + bg_b * (255 - a)) / 255;
            }
            uint32_t idx = (dst_y + y) * s_pitch_px + (dst_x + x);
            s_fb_va[idx] = (r << 16) | (g << 8) | b;
        }
    }
}

/* Draw a string in the Terminus font, writing ONLY lit pixels (transparent
 * background) so it composites cleanly over the boot splash's fill. */
static void
_splash_draw_string(uint32_t px_x, uint32_t px_y, const char *s, uint32_t fg)
{
    while (*s) {
        const uint8_t *glyph = &font_terminus[(uint8_t)*s * PANIC_FONT_H * 2];
        uint32_t row, col;
        for (row = 0; row < PANIC_FONT_H; row++) {
            uint16_t bits = ((uint16_t)glyph[row * 2] << 8) | glyph[row * 2 + 1];
            for (col = 0; col < PANIC_FONT_W; col++) {
                if (!(bits & (0x8000u >> col)))
                    continue;
                uint32_t X = px_x + col, Y = px_y + row;
                if (X < s_fb_width && Y < s_fb_height)
                    s_fb_va[Y * s_pitch_px + X] = fg;
            }
        }
        px_x += PANIC_FONT_W;
        s++;
    }
}

/* panic_bluescreen is x86-64 only — the parameter list mirrors the
 * x86-64 cpu_state_t fields that kernel/arch/x86_64/idt.c passes in.
 * ARM64 will grow its own bluescreen path when the port needs one.
 * See fb.h for the declaration guard. */
#ifdef __x86_64__
void
panic_bluescreen(uint64_t vector, uint64_t rip, uint64_t error_code,
                 uint64_t cr2, uint64_t rsp, uint64_t rbp,
                 uint64_t rax, uint64_t rbx)
{
    pvpanic_signal_panic();   /* notify host (no-op if no pvpanic device) */
    if (!fb_available || s_fb_va == (void *)0)
        goto halt;

    /* Take over the framebuffer unconditionally */
    s_fb_locked = 0;

    /* Fill screen with blue */
    {
        uint32_t total = s_fb_height * s_pitch_px;
        uint32_t i;
        for (i = 0; i < total; i++)
            s_fb_va[i] = PANIC_BG;
    }

    /* Layout: centered content block */
    uint32_t margin_x = 60;
    uint32_t y = 60;
    uint32_t x;

    /* Logo in top-left */
    _blit_logo_cov(logo_panic_cov, LOGO_PANIC_W, LOGO_PANIC_H,
                    margin_x, y, PANIC_BG, 1);
    y += LOGO_PANIC_H + PANIC_FONT_H;

    /* Title */
    x = margin_x;
    _panic_draw_string(&x, y, "Aegis ran into a problem and needs to stop.", PANIC_TITLE);
    y += PANIC_FONT_H * 2;

    /* Exception info */
    x = margin_x;
    _panic_draw_string(&x, y, "Exception: ", PANIC_DIM);
    {
        const char *name = "unknown";
        switch (vector) {
        case  0: name = "#DE divide error"; break;
        case  6: name = "#UD invalid opcode"; break;
        case  8: name = "#DF double fault"; break;
        case 13: name = "#GP general protection"; break;
        case 14: name = "#PF page fault"; break;
        }
        _panic_draw_string(&x, y, name, PANIC_FG);
    }
    y += PANIC_FONT_H + 4;

    /* RIP */
    x = margin_x;
    _panic_draw_string(&x, y, "RIP:    ", PANIC_DIM);
    _panic_draw_hex(&x, y, rip, PANIC_FG);
    y += PANIC_FONT_H + 4;

    /* Error code */
    x = margin_x;
    _panic_draw_string(&x, y, "Error:  ", PANIC_DIM);
    _panic_draw_hex(&x, y, error_code, PANIC_FG);
    y += PANIC_FONT_H + 4;

    /* CR2 (for page faults) */
    if (vector == 14) {
        x = margin_x;
        _panic_draw_string(&x, y, "CR2:    ", PANIC_DIM);
        _panic_draw_hex(&x, y, cr2, PANIC_FG);
        y += PANIC_FONT_H + 4;
    }

    /* RSP */
    x = margin_x;
    _panic_draw_string(&x, y, "RSP:    ", PANIC_DIM);
    _panic_draw_hex(&x, y, rsp, PANIC_FG);
    y += PANIC_FONT_H + 4;

    /* RBP */
    x = margin_x;
    _panic_draw_string(&x, y, "RBP:    ", PANIC_DIM);
    _panic_draw_hex(&x, y, rbp, PANIC_FG);
    y += PANIC_FONT_H + 4;

    /* RAX, RBX */
    x = margin_x;
    _panic_draw_string(&x, y, "RAX:    ", PANIC_DIM);
    _panic_draw_hex(&x, y, rax, PANIC_FG);
    y += PANIC_FONT_H + 4;

    x = margin_x;
    _panic_draw_string(&x, y, "RBX:    ", PANIC_DIM);
    _panic_draw_hex(&x, y, rbx, PANIC_FG);
    y += PANIC_FONT_H * 2;

    /* Hint */
    x = margin_x;
    _panic_draw_string(&x, y, "Resolve addresses: make sym ADDR=<rip>", PANIC_DIM);
    y += PANIC_FONT_H + 4;
    x = margin_x;
    _panic_draw_string(&x, y, "This information is also on the serial console.", PANIC_DIM);

halt:
    arch_disable_irq();
    for (;;)
        arch_halt();
}
#endif /* __x86_64__ */

/* ── panic_halt — simple text BSOD for kernel assertion failures ──────── */

void
panic_halt(const char *msg)
{
    pvpanic_signal_panic();   /* notify host (no-op if no pvpanic device) */
    if (!fb_available || s_fb_va == (void *)0)
        goto phalt;

    s_fb_locked = 0;

    /* Fill screen with blue */
    {
        uint32_t total = s_fb_height * s_pitch_px;
        uint32_t i;
        for (i = 0; i < total; i++)
            s_fb_va[i] = PANIC_BG;
    }

    uint32_t margin_x = 60;
    uint32_t y = 60;
    uint32_t x;

    /* Logo */
    _blit_logo_cov(logo_panic_cov, LOGO_PANIC_W, LOGO_PANIC_H,
                    margin_x, y, PANIC_BG, 1);
    y += LOGO_PANIC_H + PANIC_FONT_H;

    /* Title */
    x = margin_x;
    _panic_draw_string(&x, y, "Aegis ran into a problem and needs to stop.", PANIC_TITLE);
    y += PANIC_FONT_H * 2;

    /* Message — split on newlines */
    x = margin_x;
    const char *p = msg;
    while (*p) {
        if (*p == '\n') {
            y += PANIC_FONT_H + 4;
            x = margin_x;
            p++;
            continue;
        }
        if (x + PANIC_FONT_W <= s_fb_width) {
            _panic_draw_char(x, y, *p, PANIC_FG);
            x += PANIC_FONT_W;
        }
        p++;
    }

    y += PANIC_FONT_H * 2;
    x = margin_x;
    _panic_draw_string(&x, y, "This information is also on the serial console.", PANIC_DIM);

phalt:
    arch_disable_irq();
    for (;;)
        arch_halt();
}

/* ── Boot Splash ───────────────────────────────────────────────────────── */

/* Must match THEME_SURFACE in user/lib/glyph/glyph_theme.h (Bastion's bg) so
 * the boot splash → greeter handoff has no color jump. Kernel can't include the
 * userland token header, so the value is mirrored here — keep them in sync. */
#define SPLASH_BG 0x001B2230u  /* == THEME_SURFACE */
#define SPLASH_LOGO_SCALE 2    /* boot logo shown at 1/2 the mask resolution */

void
fb_boot_splash(void)
{
    if (!fb_available || s_fb_va == (void *)0)
        return;

    /* Fill screen with dark background */
    {
        uint32_t total = s_fb_height * s_pitch_px;
        uint32_t i;
        for (i = 0; i < total; i++)
            s_fb_va[i] = SPLASH_BG;
    }

    /* Logo drawn at half size, with the "Capability-Secured" tagline below it;
     * the logo + gap + text group is vertically centered. */
    const char *tag = "Capability-Secured";
    uint32_t dw = LOGO_BOOT_W / SPLASH_LOGO_SCALE;   /* on-screen logo size */
    uint32_t dh = LOGO_BOOT_H / SPLASH_LOGO_SCALE;
    uint32_t tw = (uint32_t)(sizeof("Capability-Secured") - 1) * PANIC_FONT_W;
    uint32_t gap = 18;
    uint32_t group_h = dh + gap + PANIC_FONT_H;

    uint32_t top = s_fb_height / 2 - group_h / 2;
    uint32_t lx  = s_fb_width / 2 - dw / 2;
    uint32_t ly  = top;
    uint32_t tx  = s_fb_width / 2 - tw / 2;
    uint32_t ty  = ly + dh + gap;

    _blit_logo_cov(logo_boot_cov, LOGO_BOOT_W, LOGO_BOOT_H,
                   lx, ly, SPLASH_BG, SPLASH_LOGO_SCALE);
    _splash_draw_string(tx, ty, tag, 0x00E6EAF0u);  /* soft white */

    /* No lock — printk_quiet already suppresses FB output in graphical
     * mode. The splash persists until Bastion paints over it. */
}

void
fb_boot_splash_end(void)
{
    /* No-op — splash draws without locking, printk_quiet handles
     * FB output suppression. Nothing to unlock or clear. */
    (void)0;
}
