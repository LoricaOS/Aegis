/* fb_stub.c — compiled only when CONFIG_FB is off (see Makefile).
 *
 * The console path (printk) checks fb_available before ever touching the
 * framebuffer, so with fb_available = 0 the kernel logs to serial/VGA only.
 * These stubs satisfy the console / compositor / panic / screenshot symbols the
 * rest of the tree references, so a headless build links without the ~80 KB
 * framebuffer driver. Everything reports "no framebuffer". */
#include <stdint.h>
#include "printk.h"

/* panic_halt / panic_bluescreen live in fb.c (they render a panic screen). With
 * no framebuffer they must still do the important half — report and halt — over
 * serial, so these are REAL, not no-ops. */
void panic_halt(const char *msg) {
    printk("\n[PANIC] %s\n", msg ? msg : "?");
    for (;;) __asm__ volatile ("cli; hlt");
}
#ifdef __x86_64__
void panic_bluescreen(uint64_t vector, uint64_t rip, uint64_t error_code,
                      uint64_t cr2, uint64_t rsp, uint64_t rbp,
                      uint64_t rax, uint64_t rbx) {
    printk("\n[PANIC] fault vector=%lu rip=0x%lx err=0x%lx cr2=0x%lx\n",
           vector, rip, error_code, cr2);
    (void)rsp; (void)rbp; (void)rax; (void)rbx;
    for (;;) __asm__ volatile ("cli; hlt");
}
#endif

int  fb_available = 0;
void fb_init(void) {}
void fb_putchar(char c) { (void)c; }
void fb_write_string(const char *s) { (void)s; }
void fb_check_amd(void) {}
void fb_boot_splash(void) {}
void fb_boot_splash_end(void) {}
void fb_lock_compositor(void) {}
void fb_heartbeat(void) {}
int  fb_get_phys_info(uint64_t *phys, uint32_t *w, uint32_t *h, uint32_t *pitch)
     { (void)phys; (void)w; (void)h; (void)pitch; return -1; }
