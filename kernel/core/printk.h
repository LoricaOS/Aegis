#ifndef AEGIS_PRINTK_H
#define AEGIS_PRINTK_H

#include <stdint.h>

/* printk — route formatted output to serial and VGA.
 * Supports: %s (string), %c (char), %u (uint32_t), %lu (uint64_t),
 *           %x (hex uint32_t), %lx (hex uint64_t), %% (literal %). */
void printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* pr_dbg — diagnostic / bring-up logging. Compiles to NOTHING in normal builds;
 * build with -DAEGIS_DEBUG (e.g. `make iso EXTRA_CFLAGS=-DAEGIS_DEBUG`) to
 * restore the chatty per-subsystem boot diagnostics: MMU/VMM bring-up steps,
 * PCIe/RP1 register dumps, USB enumeration traces, and the like. The argument
 * list is still type-checked in release builds (the compiler sees the call and
 * dead-code-eliminates it), so a gated print can't silently bit-rot.
 *
 * Rule of thumb for what stays a plain printk vs. becomes pr_dbg:
 *   printk  — errors, WARN/panic, and the one-line-per-subsystem "OK:"
 *             milestones that make up the normal (clean) boot log.
 *   pr_dbg  — everything whose value is "I'm debugging THIS subsystem": step
 *             traces, hex/register dumps, per-iteration loop spam.
 *
 * ARGUMENTS MUST BE SIDE-EFFECT-FREE. The release form below is
 * `if (0) printk(...)`: the compiler still type-checks the call and then
 * dead-code-eliminates it, so ANYTHING in the argument list — an MMIO read, a
 * function call, an increment — does NOT happen in a release build. That bit
 * this repo on the Pi 5: several volatile register read-backs lived inside
 * pr_dbg arguments (a DWC3_GCTL read that forces the posted write to complete,
 * USBSTS reads including one right after the EP0 doorbell), so release and
 * -DAEGIS_DEBUG builds issued DIFFERENT hardware sequences on exactly the path
 * with the open USB timing bug. Hoist the read into a local and pass the
 * local. */
#ifdef AEGIS_DEBUG
#define pr_dbg(...) printk(__VA_ARGS__)
#else
#define pr_dbg(...) do { if (0) printk(__VA_ARGS__); } while (0)
#endif

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
