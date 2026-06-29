#ifndef AEGIS_PRINTK_H
#define AEGIS_PRINTK_H

#include <stdint.h>

/* printk — route formatted output to serial and VGA.
 * Supports: %s (string), %c (char), %u (uint32_t), %lu (uint64_t),
 *           %x (hex uint32_t), %lx (hex uint64_t), %% (literal %). */
void printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* printk_set_quiet — suppress VGA+FB output in printk, serial only.
 * Console device (user output) bypasses this via direct serial+fb writes. */
void printk_set_quiet(int q);
int  printk_get_quiet(void);

/* klog_read — copy up to bufsz bytes of the kernel log ring buffer into buf,
 * oldest → newest.  If the log holds more than bufsz bytes, the TAIL (newest
 * bytes) is returned.  Returns the number of bytes written.  Takes
 * printk_lock internally — do not call from a path that holds it. */
uint32_t klog_read(char *buf, uint32_t bufsz);

/* printk_emit_bytes — write a raw byte buffer to the console sinks (serial,
 * plus VGA/FB if allow_screen and not quiet) under printk_lock.  This is the
 * ONE serialized path to the console: the user /dev/console writer routes
 * through here so userspace output can no longer interleave character-by-
 * character with kernel printk on another CPU (the SMP serial-garble bug).
 * No CPU/timestamp decoration is added.  Unlike kernel printk, this does NOT
 * write to the kernel log ring (klog) — /proc/dmesg holds kernel log lines
 * only, so userspace console output never pollutes it. */
void printk_emit_bytes(const char *buf, uint32_t len, int allow_screen);

/* printk_set_decorate — when on, every kernel printk LINE is prefixed with
 * "[cpuN t<sec>.<cs>] " (originating CPU + uptime).  Default OFF so single-CPU
 * boots (and the boot oracle) are byte-identical to before.  SMP bring-up
 * turns it on automatically once more than one CPU is online, so concurrent
 * AP output is attributable instead of an unreadable interleave. */
void printk_set_decorate(int on);

/* ── Runtime assertions (KASSERT / WARN_ONCE) ───────────────────────────────
 * KASSERT(cond): on failure, print "[ASSERT] FAIL: <cond> at file:line cpuN"
 * and halt via panic_assert_fail (never returns).  Use for invariants whose
 * violation means the kernel is already corrupt.
 * WARN_ONCE(cond, msg): if cond, print "[WARN] <msg> at file:line" exactly
 * once per site and CONTINUE.  Use for "shouldn't happen but survivable". */
void panic_assert_fail(const char *cond, const char *file, unsigned line)
    __attribute__((noreturn));
void warn_print(const char *msg, const char *file, unsigned line);

#define KASSERT(cond)                                                   \
    do {                                                                \
        if (__builtin_expect(!(cond), 0))                               \
            panic_assert_fail(#cond, __FILE__, __LINE__);               \
    } while (0)

#define WARN_ONCE(cond, msg)                                            \
    do {                                                                \
        static int _warned_ = 0;                                        \
        if (__builtin_expect((cond) && !_warned_, 0)) {                 \
            _warned_ = 1;                                               \
            warn_print((msg), __FILE__, __LINE__);                      \
        }                                                               \
    } while (0)

#endif /* AEGIS_PRINTK_H */
