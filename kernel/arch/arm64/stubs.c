/*
 * stubs.c — arm64 stand-ins for symbols shared code links against whose
 * real providers are x86-only drivers. Each is a fail-closed no-op: absent
 * hardware reads as "no device", never as fake success.
 */

#include "arch.h"
#include "printk.h"
#include "ksym.h"
#include "../../sched/waitq.h"
#include "../../drivers/usb_mouse.h"
#include <stdint.h>

/* ── Backtrace (kernel/core/stackshot.h) ───────────────────────────────────
 * AAPCS64 frame records have the same layout as x86 -fno-omit-frame-pointer
 * frames: [fp+0] = previous fp, [fp+8] = return address (lr). */
void
print_backtrace_from(uint64_t fp, int max)
{
    for (int i = 0; i < max; i++) {
        if (fp < 0xFFFFFFFF80000000ULL || (fp & 7ULL))
            break;
        uint64_t retaddr = ((uint64_t *)fp)[1];
        if (retaddr < 0xFFFFFFFF80000000ULL || retaddr == 0)
            break;
        uint64_t off = 0;
        const char *sym = ksym_lookup(retaddr, &off);
        if (sym)
            printk("    [%u] 0x%lx %s+0x%lx\n", i, retaddr, sym, off);
        else
            printk("    [%u] 0x%lx\n", i, retaddr);
        fp = ((uint64_t *)fp)[0];
    }
}

/* ── pvpanic (kernel/drivers/panic_screen.c) — QEMU x86 ISA device ─────── */
void pvpanic_signal_panic(void) {}

/* ── /dev/mouse (kernel/fs/initrd.c) — no pointer device on arm64 v1 ───── */
waitq_t g_mouse_waiters = WAITQ_INIT;

int
mouse_poll(mouse_event_t *out)
{
    (void)out;
    return 0;
}

/* ── virtio-gpu (kernel/syscall/sys_disk.c fb syscalls) — not ported ───── */
int virtio_gpu_active(void) { return 0; }
void virtio_gpu_flush(void) {}

uint8_t *
virtio_gpu_framebuffer(uint32_t *w, uint32_t *h, uint32_t *pitch)
{
    (void)w; (void)h; (void)pitch;
    return 0;
}
