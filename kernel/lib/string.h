/* kernel/lib/string.h — freestanding byte-wise memory primitives shared
 * across the kernel.
 *
 * Replaces the ~20 per-subsystem private copies (_ip_memcpy, _tcp_memcpy,
 * nv_memcpy, st_memcpy, vm_memcpy, _mf_memset, …) that each re-implemented the
 * same byte loop. Named kmem* — NOT memcpy/memset — deliberately: the x86_64
 * kernel builds -ffreestanding without a libc, and the arm64 port already
 * defines real `memcpy`/`memset` symbols (kernel/arch/arm64/stubs.c) that the
 * compiler may emit calls to; keeping a distinct name avoids any collision or
 * accidental builtin lowering.
 */
#ifndef KERNEL_LIB_STRING_H
#define KERNEL_LIB_STRING_H

#include <stddef.h>

void *kmemcpy(void *dst, const void *src, size_t n);
void *kmemset(void *dst, int val, size_t n);
int   kmemcmp(const void *a, const void *b, size_t n);

#endif /* KERNEL_LIB_STRING_H */
