#ifndef AEGIS_KASAN_H
#define AEGIS_KASAN_H

/* KASAN — Kernel Address Sanitizer (globals/BSS coverage).
 *
 * Only built when the kernel is compiled with KASAN=1 (see the Makefile), which
 * turns on -fsanitize=kernel-address.  The compiler then emits an __asan_load
 * or __asan_store call before every memory access and lays a redzone
 * around every static/global object; those redzones are registered at boot by
 * constructors this file runs.  A read or write that lands in a redzone (an
 * out-of-bounds access on a static array — the fd tables, the s_tcp[] table,
 * the BSS ring buffers) is reported with a backtrace.
 *
 * Scope, deliberately: the kernel IMAGE window only ([_kernel start, +8MB] —
 * where .data/.bss live).  The kva page heap is NOT covered: it unmaps on free,
 * so a use-after-free there already faults at the MMU.  Coverage can be widened
 * to the heap later (see kasan.c). */

#ifdef KASAN

void kasan_init(void);       /* map shadow, run global ctors — call after kva_init */
unsigned kasan_report_count(void);   /* number of reports since boot (0 = clean) */

#else  /* !KASAN — compiled-out no-ops so callers need no #ifdef */

static inline void kasan_init(void) {}
static inline unsigned kasan_report_count(void) { return 0; }

#endif /* KASAN */

#endif /* AEGIS_KASAN_H */
