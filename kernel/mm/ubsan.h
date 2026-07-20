#ifndef AEGIS_UBSAN_H
#define AEGIS_UBSAN_H

/* UBSAN — Undefined Behavior Sanitizer.
 *
 * Only built when the kernel is compiled with UBSAN=1 (see the Makefile), which
 * turns on -fsanitize=undefined.  The compiler then emits a __ubsan_handle_*
 * call wherever it cannot prove a signed overflow, an over-wide shift, a
 * misaligned/null pointer access, a divide overflow, or a sizeable
 * out-of-bounds index is impossible.  Each is reported with file:line:col and a
 * backtrace, then execution continues (report-and-continue, like KASAN).
 *
 * UBSAN and KASAN cover disjoint bug classes — UB in arithmetic/pointers vs.
 * out-of-bounds addressing — but are separate builds: their instrumentation
 * together overruns the 8MB kernel image window, so don't enable both at once. */

#ifdef UBSAN

void ubsan_init(void);              /* enable reporting — call once console is up */
unsigned ubsan_report_count(void);  /* reports since boot (0 = clean)             */

#else  /* !UBSAN — compiled-out no-ops so callers need no #ifdef */

static inline void ubsan_init(void) {}
static inline unsigned ubsan_report_count(void) { return 0; }

#endif /* UBSAN */

#endif /* AEGIS_UBSAN_H */
