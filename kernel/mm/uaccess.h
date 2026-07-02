#ifndef UACCESS_H
#define UACCESS_H

#include "arch.h"
#include <stdint.h>

/* copy_from_user / copy_to_user — byte copy between user and kernel space.
 *
 * Callers SHOULD still validate [ptr, ptr+len) with user_ptr_valid() first
 * (it also faults in lazy demand-paged pages, which the raw copy cannot). But
 * the copy is now FAULT-TOLERANT: the user-touching instruction is registered
 * in the kernel exception table (__ex_table), so if the user page is unmapped
 * at copy time — e.g. a sibling thread (CLONE_VM) munmap'd the buffer during a
 * blocking syscall, the validate-then-block-then-copy TOCTOU class — the #PF
 * handler (isr_dispatch) redirects to a fixup instead of panic_halt()ing the
 * kernel. A ring-0 fault on a user buffer can no longer take the system down.
 *
 * Both return the number of bytes NOT copied (0 == full success), the Linux
 * convention. The return type changed from void to uint64_t; existing callers
 * that ignore it are unaffected (C discards the value), and callers that want
 * true EFAULT semantics on a partial copy can now check it. stac/clac are
 * handled inside __uaccess_copy, so there is no function call between them. */

#ifdef __x86_64__
/* x86: real exception-table-backed primitive in arch_smap.c. */
static inline uint64_t
copy_from_user(void *dst, const void *src, uint64_t len)
{
    return __uaccess_copy(dst, src, len);
}

static inline uint64_t
copy_to_user(void *dst, const void *src, uint64_t len)
{
    return __uaccess_copy(dst, src, len);
}
#elif defined(__aarch64__)
/* ARM64: exception-table-backed byte copy in uaccess.S. A fault on the
 * user side (e.g. a sibling munmap during a blocking syscall) is caught by
 * arm64_fault_el1 and redirected to the fixup instead of panicking. */
uint64_t arm64_uaccess_copy(void *dst, const void *src, uint64_t len);

static inline uint64_t
copy_from_user(void *dst, const void *src, uint64_t len)
{
    return arm64_uaccess_copy(dst, src, len);
}

static inline uint64_t
copy_to_user(void *dst, const void *src, uint64_t len)
{
    return arm64_uaccess_copy(dst, src, len);
}
#else
/* Other arches: plain copy, no fault fixup. */
static inline uint64_t
copy_from_user(void *dst, const void *src, uint64_t len)
{
    __builtin_memcpy(dst, src, len);
    return 0;
}

static inline uint64_t
copy_to_user(void *dst, const void *src, uint64_t len)
{
    __builtin_memcpy(dst, src, len);
    return 0;
}
#endif

#endif /* UACCESS_H */
