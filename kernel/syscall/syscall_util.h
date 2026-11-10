#ifndef SYSCALL_UTIL_H
#define SYSCALL_UTIL_H

#include <stdint.h>
#include "arch.h"

/* Snapshot checks, not a pin: every copy must still check its residual.
 * Kernel tasks (no user address space) retain range-only semantics. */
int uaccess_range_mapped(uint64_t addr, uint64_t len);
/* prot: 0 = any access, 1 = read, 2 = write (PROT_* bit values). */
int uaccess_range_accessible(uint64_t addr, uint64_t len, uint32_t prot);

/* user_ptr_valid — return 1 if [addr, addr+len) lies entirely within the
 * canonical user address space AND has some access permission.
 * For len=0, validates that addr itself is a canonical user address (does
 * NOT unconditionally pass — a kernel addr with len=0 still returns 0).
 * Overflow-safe: addr <= USER_ADDR_MAX - len avoids addr+len wraparound.
 *
 * Lazy VMAs need not have PTEs yet. copy_*_user faults can populate them,
 * break COW, or return a nonzero residual on failure. Validation is only a
 * snapshot, including across blocking calls and concurrent munmap/mprotect.
 * This directionless compatibility check rejects PROT_NONE, not read-only
 * outputs. New copy sites should use the directional checks below. */
static inline int
user_ptr_valid(uint64_t addr, uint64_t len)
{
    if (!(len <= USER_ADDR_MAX && addr <= USER_ADDR_MAX - len))
        return 0;
    return uaccess_range_mapped(addr, len);
}

static inline int
user_ptr_readable(uint64_t addr, uint64_t len)
{
    if (!(len <= USER_ADDR_MAX && addr <= USER_ADDR_MAX - len))
        return 0;
    return uaccess_range_accessible(addr, len, 1);
}

static inline int
user_ptr_writable(uint64_t addr, uint64_t len)
{
    if (!(len <= USER_ADDR_MAX && addr <= USER_ADDR_MAX - len))
        return 0;
    return uaccess_range_accessible(addr, len, 2);
}

/* ── Negative-errno return helpers (TRY-style propagation) ────────────────
 * Syscall handlers return uint64_t carrying either a value or a negative errno
 * encoded as SYS_ERR(e) == (uint64_t)-(int64_t)e (aegis_errno.h). Internal
 * helpers return SIGNED results (negative == -errno). These make the
 * value<->error conversion and error-propagation explicit and uniform,
 * replacing hand-written `(uint64_t)(int64_t)rc` casts and `if (rc < 0) return`
 * chains scattered across the handlers.
 *
 * Pure standard C — NO GNU statement expressions ({ ... }). The kernel uses
 * none, and house style (CLAUDE.md: no compiler extensions without #ifdef +
 * comment) forbids them, so there is no value-yielding TRY(); SC_PROPAGATE is a
 * do/while(0) statement and value-carrying sites use sc_ret() explicitly. */

/* sc_is_err — 1 if a uint64_t syscall return encodes a negative errno.
 * Mirrors Linux IS_ERR_VALUE: the top 4096 values are the error band. Aegis
 * errnos are all < 256, so this never misclassifies a real return — valid
 * returns (user pointers, byte counts, fds) are all far below (uint64_t)-4095. */
static inline int
sc_is_err(uint64_t rc)
{
    return rc >= (uint64_t)-4095;
}

/* sc_ret — normalize a SIGNED helper result to the uint64_t syscall ABI.
 * A negative value is reinterpreted as the encoded errno; a non-negative value
 * passes through unchanged. Replaces the repeated `(uint64_t)(int64_t)rc`
 * (an `int` argument promotes to int64_t first, so it sign-extends correctly). */
static inline uint64_t
sc_ret(int64_t rc)
{
    return (uint64_t)rc;
}

/* SC_PROPAGATE — early-return the encoded errno when a SIGNED helper result is
 * negative, otherwise fall through (the success value is discarded). For the
 * common "do a sub-step; bail on failure" chain. Single statement (do/while). */
#define SC_PROPAGATE(expr)                                  \
    do {                                                    \
        int64_t _sc_r = (expr);                             \
        if (_sc_r < 0)                                      \
            return (uint64_t)_sc_r;                         \
    } while (0)

#endif /* SYSCALL_UTIL_H */
