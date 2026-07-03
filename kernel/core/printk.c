#include <stdarg.h>
#include <stdint.h>
#include "arch.h"
#include "printk.h"
#include "spinlock.h"
#include "fb.h"
#ifdef __x86_64__
/* Per-line decoration reads the originating CPU (LAPIC id) and uptime (PIT
 * ticks).  These are inherently arch-specific; gated so non-x86 builds (which
 * have no SMP userland yet) compile to cpu=0/ts=0 and never decorate. */
#include "lapic.h"
#include "pit.h"
#endif

/*
 * printk — route formatted output to all available output sinks.
 *
 * Law 1: serial is written unconditionally (if serial_init was called).
 * Law 2: VGA is written only if vga_available is set by vga_init().
 *        VGA failure never silences serial.
 *
 * Supported conversions: %s %c %u %lu %x %lx %%
 * No dynamic allocation. No VLAs. Stack buffer for integer formatting only.
 *
 * printk_lock serialises output so two CPUs (or an ISR and a thread) cannot
 * interleave characters.  IRQs are saved/restored around the lock.
 */

static spinlock_t printk_lock = SPINLOCK_INIT;
static int printk_quiet = 0;  /* 1 = suppress VGA+FB in printk, serial only */
static int printk_decorate = 0; /* 1 = prefix each kernel line with [cpuN t..] */
static int s_at_bol = 1;        /* serial cursor is at beginning of line */

/* ── Kernel log ring buffer ─────────────────────────────────────────────
 * 64KB circular buffer; oldest data silently overwritten when full.
 * Written under printk_lock so no separate lock needed.
 * klog_read() copies in order (oldest → newest); when the caller's buffer
 * is smaller than the log it returns the TAIL (newest bytes) — that is
 * what /proc/dmesg wants from a 4KB procfs generation buffer. */
#define KLOG_SIZE  (64u * 1024u)
static char     klog_buf[KLOG_SIZE];
static uint32_t klog_head = 0;   /* next write position */
static uint32_t klog_used = 0;   /* bytes in buffer (capped at KLOG_SIZE) */

static void
klog_putc(char c)
{
    klog_buf[klog_head] = c;
    klog_head = (klog_head + 1u) % KLOG_SIZE;
    if (klog_used < KLOG_SIZE)
        klog_used++;
}

uint32_t
klog_read(char *buf, uint32_t bufsz)
{
    irqflags_t flags = spin_lock_irqsave(&printk_lock);
    uint32_t len = klog_used < bufsz ? klog_used : bufsz;
    /* Copy the last len bytes: if the destination is smaller than the
     * log contents, the oldest bytes are dropped, not the newest. */
    uint32_t start = (KLOG_SIZE + klog_head - len) % KLOG_SIZE;
    for (uint32_t i = 0; i < len; i++)
        buf[i] = klog_buf[(start + i) % KLOG_SIZE];
    spin_unlock_irqrestore(&printk_lock, flags);
    return len;
}

void
printk_set_quiet(int q)
{
    printk_quiet = q;
}

int
printk_get_quiet(void)
{
    return printk_quiet;
}

static const char *fmt_uint64(uint64_t val, int base, char *buf, int buflen);

/* emit_raw_char — write one byte to every sink (log ring + serial, plus
 * VGA/FB if available and not quiet).  No beginning-of-line decoration: this
 * is the low-level sink writer used both for normal output and for the
 * decoration prefix itself (so the prefix never recurses). */
static void
emit_raw_char(char c)
{
    klog_putc(c);
    char buf[2];
    buf[0] = c;
    buf[1] = '\0';
    serial_write_string(buf);
    if (!printk_quiet && vga_available) {
        vga_write_string(buf);
    }
    if (!printk_quiet && fb_available) {
        fb_write_string(buf);
    }
}

/* emit_decoration — write the per-line "[cpuN t<sec>.<cs>] " prefix using the
 * raw sink writer.  Called from emit_char at beginning-of-line when decoration
 * is enabled.  Uses pit_ticks() (10 ms/tick → sec = ticks/100, cs = ticks%100)
 * and lapic_id() for the originating CPU.  Both arch-specific (x86 only). */
static void
emit_decoration(void)
{
    unsigned cpu = 0;
    uint64_t ticks = 0;
#ifdef __x86_64__
    cpu   = (unsigned)lapic_id();
    ticks = pit_ticks();
#endif
    uint64_t sec = ticks / 100u;
    unsigned cs  = (unsigned)(ticks % 100u);
    char nb[24];
    emit_raw_char('[');
    emit_raw_char('c'); emit_raw_char('p'); emit_raw_char('u');
    for (const char *p = fmt_uint64(cpu, 10, nb, (int)sizeof(nb)); *p; p++)
        emit_raw_char(*p);
    emit_raw_char(' '); emit_raw_char('t');
    for (const char *p = fmt_uint64(sec, 10, nb, (int)sizeof(nb)); *p; p++)
        emit_raw_char(*p);
    emit_raw_char('.');
    emit_raw_char((char)('0' + (cs / 10)));
    emit_raw_char((char)('0' + (cs % 10)));
    emit_raw_char(']'); emit_raw_char(' ');
}

/* Emit a single character to all active output sinks, inserting the decoration
 * prefix at the start of each line when enabled.  s_at_bol tracks serial-line
 * position (shared with printk_emit_bytes, all under printk_lock). */
static void
emit_char(char c)
{
    if (s_at_bol && printk_decorate && c != '\n')
        emit_decoration();
    emit_raw_char(c);
    s_at_bol = (c == '\n');
}

/* Emit a null-terminated string, character-by-character so beginning-of-line
 * decoration applies uniformly (numbers and %s args route through here too). */
static void
emit_string(const char *s)
{
    if (s == (void *)0)
        s = "(null)";
    while (*s)
        emit_char(*s++);
}

/*
 * fmt_uint64 — convert a uint64_t to decimal or hex digits in buf.
 * buf must be at least 21 bytes for decimal, 17 bytes for hex.
 * Returns pointer to the first digit (within buf).
 * base must be 10 or 16.
 */
static const char *
fmt_uint64(uint64_t val, int base, char *buf, int buflen)
{
    static const char digits[] = "0123456789abcdef";
    int i = buflen - 1;

    buf[i] = '\0';
    i--;

    if (val == 0) {
        buf[i] = '0';
        return &buf[i];
    }

    while (val > 0 && i >= 0) {
        buf[i] = digits[val % (uint64_t)base];
        val /= (uint64_t)base;
        i--;
    }

    return &buf[i + 1];
}

void
printk(const char *fmt, ...)
{
    va_list ap;
    /* 24 bytes: enough for UINT64_MAX in decimal (20 digits) + NUL,
     * or for 16 hex digits + NUL.  No VLA. */
    char numbuf[24];
    irqflags_t flags = spin_lock_irqsave(&printk_lock);

    va_start(ap, fmt);

    while (*fmt != '\0') {
        if (*fmt != '%') {
            emit_char(*fmt);
            fmt++;
            continue;
        }

        /* We have a '%' — advance past it and inspect the next char. */
        fmt++;
        if (*fmt == '\0') {
            /* Trailing lone '%' — emit it and stop. */
            emit_char('%');
            break;
        }

        switch (*fmt) {
        case '%':
            emit_char('%');
            break;

        case 'c': {
            /* char is promoted to int through va_arg. */
            int c = va_arg(ap, int);
            emit_char((char)c);
            break;
        }

        case 's': {
            const char *s = va_arg(ap, const char *);
            emit_string(s);
            break;
        }

        case 'u': {
            uint32_t v = va_arg(ap, uint32_t);
            const char *p = fmt_uint64((uint64_t)v, 10, numbuf, (int)sizeof(numbuf));
            emit_string(p);
            break;
        }

        case 'i':
        case 'd': {
            int v = va_arg(ap, int);
            uint64_t u = (uint64_t)v;
            if (v < 0) { emit_char('-'); u = -(uint64_t)v; }
            const char *p = fmt_uint64(u, 10, numbuf, (int)sizeof(numbuf));
            emit_string(p);
            break;
        }

        case 'x': {
            uint32_t v = va_arg(ap, uint32_t);
            const char *p = fmt_uint64((uint64_t)v, 16, numbuf, (int)sizeof(numbuf));
            emit_string(p);
            break;
        }

        case 'l': {
            /* Expect 'u' or 'x' after 'l'. */
            fmt++;
            if (*fmt == 'u') {
                uint64_t v = va_arg(ap, uint64_t);
                const char *p = fmt_uint64(v, 10, numbuf, (int)sizeof(numbuf));
                emit_string(p);
            } else if (*fmt == 'd') {
                int64_t v = va_arg(ap, int64_t);
                uint64_t u = (uint64_t)v;
                if (v < 0) { emit_char('-'); u = -(uint64_t)v; }
                const char *p = fmt_uint64(u, 10, numbuf, (int)sizeof(numbuf));
                emit_string(p);
            } else if (*fmt == 'x') {
                uint64_t v = va_arg(ap, uint64_t);
                const char *p = fmt_uint64(v, 16, numbuf, (int)sizeof(numbuf));
                emit_string(p);
            } else {
                /* Unknown %l? — emit literally. */
                emit_char('%');
                emit_char('l');
                if (*fmt != '\0') {
                    emit_char(*fmt);
                } else {
                    /* fmt now points at NUL; the outer loop will exit. */
                    va_end(ap);
                    spin_unlock_irqrestore(&printk_lock, flags);
                    return;
                }
            }
            break;
        }

        default:
            /* Unknown conversion — emit the '%' and the specifier literally. */
            emit_char('%');
            emit_char(*fmt);
            break;
        }

        fmt++;
    }

    va_end(ap);
    spin_unlock_irqrestore(&printk_lock, flags);
}

void
printk_set_decorate(int on)
{
    printk_decorate = on;
}

void
printk_emit_bytes(const char *buf, uint32_t len, int allow_screen)
{
    irqflags_t flags = spin_lock_irqsave(&printk_lock);
    for (uint32_t i = 0; i < len; i++) {
        char c = buf[i];
        /* Deliberately NOT mirrored into the kernel log ring (klog_putc):
         * this path carries USERSPACE /dev/console output, which is not
         * kernel log content.  Storing it polluted /proc/dmesg with
         * unprefixed userspace lines (e.g. shell/daemon stdout) so the tail
         * snapshot could begin on a non-"[SUBSYS]" line.  /proc/dmesg is the
         * KERNEL ring only (matching Linux dmesg semantics); userspace output
         * still reaches serial/VGA/FB below.  Kernel printk continues to call
         * klog_putc via emit_raw_char. */
        char b[2];
        b[0] = c;
        b[1] = '\0';
        serial_write_string(b);
        if (allow_screen && !printk_quiet && vga_available)
            vga_write_string(b);
        if (allow_screen && !printk_quiet && fb_available)
            fb_putchar(c);
        s_at_bol = (c == '\n');
    }
    spin_unlock_irqrestore(&printk_lock, flags);
}

void
warn_print(const char *msg, const char *file, unsigned line)
{
    printk("[WARN] %s at %s:%u\n", msg, file, line);
}

void
panic_assert_fail(const char *cond, const char *file, unsigned line)
{
    unsigned cpu = 0;
#ifdef __x86_64__
    cpu = (unsigned)lapic_id();
#endif
    printk("[ASSERT] FAIL: %s at %s:%u cpu%u\n", cond, file, line, cpu);
    for (;;) {
        arch_disable_irq();
        arch_halt();
    }
}
