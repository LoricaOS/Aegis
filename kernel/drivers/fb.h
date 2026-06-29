/* kernel/drivers/fb.h — Linear framebuffer character terminal.
 *
 * Requires arch_mm_init() to have run (multiboot2 tag parsed) and
 * vmm_init() + kva_init() to have run (needed for page mapping).
 *
 * fb_init() maps the hardware framebuffer into kernel KVA and initialises
 * the embedded 8×16 font renderer.  After fb_init(), fb_putchar() may be
 * called from printk() on every character.
 */
#ifndef FB_H
#define FB_H

#include <stdint.h>

/* Upper bounds on the framebuffer geometry reported by the boot tag.
 * The multiboot2/Limine framebuffer tag is untrusted input. A garbage
 * or malicious tag with huge width/height/pitch makes pitch*height wrap
 * a uint32 (under-mapping the FB, then over-clearing it). These caps are
 * deliberately generous — 8K (7680x4320) fits comfortably — but bound the
 * worst case to FB_MAX_PITCH*FB_MAX_HEIGHT == 1 GiB, well inside uint64.
 *
 * Shared with the boot-tag parser in kernel/arch/x86_64/arch_mm.c so that
 * the source-side sanitisation (defense in depth) and fb_init()'s own
 * validation agree on a single set of limits. */
#define FB_MAX_WIDTH   16384u
#define FB_MAX_HEIGHT  16384u
#define FB_MAX_PITCH   (FB_MAX_WIDTH * 4u)   /* 65536 bytes/scanline */

/* fb_init — detect framebuffer from arch_get_fb_info(), map it, clear screen.
 * No-op (silent) if no framebuffer was provided by GRUB. */
void fb_init(void);

/* fb_putchar — render one ASCII character to the framebuffer terminal.
 * Only callable after fb_init().  Ignores the call if fb_available == 0. */
void fb_putchar(char c);

/* fb_write_string — render a NUL-terminated string. */
void fb_write_string(const char *s);

/* fb_check_amd — log a diagnostic if an AMD iGPU is present but
 * fb_available == 0 (no UEFI GOP framebuffer was provided by GRUB).
 * Must be called AFTER pcie_init() so the device table is populated.
 * No-op if fb_available == 1 (framebuffer already working) or no AMD GPU. */
void fb_check_amd(void);

/* fb_available — set to 1 by fb_init() on success; 0 otherwise.
 * Checked by printk() before calling fb_write_string(). */
extern int fb_available;

/* fb_get_phys_info — return framebuffer physical address, width, height, pitch.
 * Returns 1 on success, 0 if no framebuffer available.
 * Used by sys_fb_map to map FB into userspace. */
int fb_get_phys_info(uint64_t *phys_out, uint32_t *width_out,
                     uint32_t *height_out, uint32_t *pitch_out);

/* fb_lock_compositor — suppress kernel text output to the framebuffer.
 * Called by sys_fb_map when a user compositor maps the FB. */
void fb_lock_compositor(void);

/* fb_heartbeat — toggle a small pixel block in the top-left corner.
 * Called from sched_tick. If this stops blinking, IRQs are disabled. */
void fb_heartbeat(void);

/* fb_boot_splash — display the Aegis logo centered on a dark background.
 * Called once during early boot, after fb_init(). Locks FB output so
 * printk goes to serial only while the splash is visible. */
void fb_boot_splash(void);

/* fb_boot_splash_end — clear the splash and unlock FB for normal output.
 * Called when boot is complete, right before starting user processes. */
void fb_boot_splash_end(void);

/* panic_halt — take over framebuffer, display a text message on blue screen,
 * and halt. For kernel assertion failures (vmm, pmm, sched, etc.).
 * Supports newlines in the message. Never returns. */
void panic_halt(const char *msg);

/* panic_bluescreen — take over the framebuffer and display a panic screen.
 * Draws a blue background with Terminus font showing exception details.
 * Halts the CPU (arch_disable_irq + arch_halt). Never returns.
 * Safe to call from ISR context with IRQs disabled.
 *
 * Arch isolation note (2026-04-12): the parameter list uses x86-64
 * register names (rip/cr2/rsp/rbp/rax/rbx) because the only callers
 * are the x86-64 IDT dispatcher in kernel/arch/x86_64/idt.c. Gated
 * behind __x86_64__ so ARM64 builds neither see the declaration nor
 * link against the definition. When ARM64 grows its own bluescreen
 * path, add a parallel arm64-specific function or refactor to a
 * neutral `struct isr_frame *`. */
#ifdef __x86_64__
void panic_bluescreen(uint64_t vector, uint64_t rip, uint64_t error_code,
                      uint64_t cr2, uint64_t rsp, uint64_t rbp,
                      uint64_t rax, uint64_t rbx);
#endif

#endif /* FB_H */
