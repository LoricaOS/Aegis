#ifndef SHIM_ARCH_H
#define SHIM_ARCH_H
#include <stdint.h>
/* Host stand-ins for the arch primitives the real spinlock.h and the net stack
 * need. The fuzzer is single-threaded, so IRQ save/restore is a no-op and the
 * REAL ticket spinlock is used uncontended — meaning this harness exercises the
 * genuine locking code but cannot find concurrency bugs. */
extern uint64_t g_fake_ticks;
static inline void     arch_pause(void) { }
static inline unsigned long arch_irq_save(void) { return 0; }
static inline void     arch_irq_restore(unsigned long f) { (void)f; }
static inline uint64_t arch_get_ticks(void) { return g_fake_ticks; }
static inline void     arch_wait_for_irq(void) { g_fake_ticks++; }
static inline void     arch_enable_irq(void) { }
static inline void     arch_disable_irq(void) { }
static inline const char *arch_get_cmdline(void) { return ""; }
/* ext2's block cache ages entries against the TSC. A fixed nominal frequency
 * and a monotonic counter keep that deterministic for the fuzzer. */
static inline uint64_t arch_tsc_hz(void)     { return 1000000000ull; }
static inline uint64_t arch_get_cycles(void) { return ++g_fake_ticks; }
/* uaccess.h builds copy_from_user/copy_to_user on this. There is no user space
 * in the harness, so it is a plain copy; returns bytes NOT copied. */
static inline uint64_t __uaccess_copy(void *dst, const void *src, uint64_t len)
{ __builtin_memcpy(dst, src, (unsigned long)len); return 0; }
#endif
