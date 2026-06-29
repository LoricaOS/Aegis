#ifndef AEGIS_UACCESS_USER_H
#define AEGIS_UACCESS_USER_H
/*
 * uaccess_user.h — the validate+copy macros that bind a user-pointer check to
 * its copy so they can never disagree.
 *
 * THE BUG THIS PREVENTS (highest-SAFETY payoff of the Tier-1 set):
 * copy_from_user / copy_to_user (uaccess.h) have NO fault-fixup table. A
 * kernel-mode #PF on an unmapped user pointer is UNRECOVERABLE — it panics the
 * kernel. So every copy MUST be preceded by user_ptr_valid() over the SAME
 * range. The hand-written idiom is:
 *     if (!user_ptr_valid((uint64_t)p, sizeof(x))) return SYS_ERR(EFAULT);
 *     copy_from_user(&x, p, sizeof(x));
 * which appears ~111× (user_ptr_valid) / ~118× (copy_*_user) across syscall/.
 * Two independent `len` arguments that MUST match is a latent footgun: a copy
 * whose length silently exceeds its validated length is a panic primitive. The
 * macros derive ONE length from `sizeof(*(dst))` so the two cannot drift.
 *
 * This is a companion header to uaccess.h (copy_from_user/copy_to_user) and
 * syscall_util.h (user_ptr_valid); it pulls both in and adds the bound forms.
 * It depends on aegis_errno.h for SYS_ERR(EFAULT) — include order does not
 * matter (all are include-guarded #define/inline headers). Include as
 * "../mm/uaccess_user.h" from syscall/ TUs (add -Ikernel/mm if not already on
 * the path — most syscall TUs already include uaccess.h).
 *
 * (The migration spec's preferred end-state is to FOLD these into uaccess.h
 * itself once errno is centralised, so there is one uaccess header. They live
 * in a companion header first so the errno sweep and this thread stay in
 * disjoint files; merging the two headers is a trivial follow-up. See
 * docs/growing-pains-tier1-migration-spec.md §3.)
 *
 * TWO FLAVOURS, and WHY:
 *
 *   COPY_FROM_USER / COPY_TO_USER  — the returning form. On a bad pointer they
 *     execute `return SYS_ERR(EFAULT);` from the ENCLOSING function. Use ONLY
 *     where that early return frees nothing and skips no cleanup — i.e. the
 *     pointer check is the first thing the syscall does, before allocating a
 *     kva buffer / taking a lock / opening an fd. This covers the large
 *     majority of sites (a scalar struct copied in at entry, a result copied
 *     out at exit with nothing else held).
 *
 *   copy_from_user_checked / copy_to_user_checked — the non-returning form.
 *     Returns true on success, false on a bad pointer, and does NOT return from
 *     the caller. Use at any site that has ALREADY acquired a resource that the
 *     error path must release (kva_free_pages, fd close, spin_unlock,
 *     refcount_dec): the hidden `return` of the macro form would LEAK it. The
 *     caller writes the cleanup explicitly:
 *         if (!copy_to_user_checked(uptr, &x)) { kva_free_pages(buf,1);
 *                                                return SYS_ERR(EFAULT); }
 *     This is the "hidden return" trap the migration spec calls out; classify
 *     every converted site into returning-vs-checked before touching it.
 *
 * All forms validate EXACTLY sizeof(*(dst)) / sizeof(*(src)) bytes — they are
 * for FIXED-SIZE objects (a struct, a scalar). For variable-length copies
 * (a user-supplied count, a path string) keep the explicit
 * user_ptr_valid(p, n) + copy_*_user(...) form; do NOT contort these macros
 * with a length argument (that reintroduces the two-length footgun they exist
 * to remove). The spec lists which sites stay explicit.
 */
#include "uaccess.h"               /* copy_from_user / copy_to_user        */
#include "../syscall/syscall_util.h"  /* user_ptr_valid                    */
#include "../include/aegis_errno.h"   /* SYS_ERR, EFAULT                   */
#include <stdint.h>
#include <stdbool.h>

/*
 * COPY_FROM_USER(dst, uptr) — validate [uptr, uptr+sizeof(*dst)) and copy that
 * many bytes from user space into *dst. On a bad pointer, returns
 * SYS_ERR(EFAULT) from the enclosing function. `dst` must be a typed pointer
 * (sizeof(*(dst)) is the copy length); `uptr` is the user address (any
 * integer/pointer type — cast through uintptr_t).
 */
#define COPY_FROM_USER(dst, uptr)                                              \
    do {                                                                      \
        if (!user_ptr_valid((uint64_t)(uintptr_t)(uptr), sizeof(*(dst))))     \
            return SYS_ERR(EFAULT);                                           \
        copy_from_user((dst), (const void *)(uintptr_t)(uptr),                \
                       sizeof(*(dst)));                                       \
    } while (0)

/*
 * COPY_TO_USER(uptr, src) — validate [uptr, uptr+sizeof(*src)) and copy that
 * many bytes from *src out to user space. On a bad pointer, returns
 * SYS_ERR(EFAULT) from the enclosing function. `src` must be a typed pointer.
 */
#define COPY_TO_USER(uptr, src)                                               \
    do {                                                                      \
        if (!user_ptr_valid((uint64_t)(uintptr_t)(uptr), sizeof(*(src))))     \
            return SYS_ERR(EFAULT);                                           \
        copy_to_user((void *)(uintptr_t)(uptr), (src), sizeof(*(src)));       \
    } while (0)

/*
 * copy_from_user_checked / copy_to_user_checked — non-returning variants.
 * Validate sizeof(*dst)/sizeof(*src) bytes; return true and perform the copy on
 * success, or return false WITHOUT copying (and without returning from the
 * caller) on a bad pointer. For sites holding a resource the error path must
 * free — the caller supplies the cleanup. Static inline, type-checked via the
 * typed pointer; `uptr` cast through uintptr_t.
 */
static inline bool
copy_from_user_checked_(void *dst, uint64_t uptr, uint64_t n)
{
    if (!user_ptr_valid(uptr, n))
        return false;
    copy_from_user(dst, (const void *)(uintptr_t)uptr, n);
    return true;
}

static inline bool
copy_to_user_checked_(uint64_t uptr, const void *src, uint64_t n)
{
    if (!user_ptr_valid(uptr, n))
        return false;
    copy_to_user((void *)(uintptr_t)uptr, src, n);
    return true;
}

/* Sizeof-binding wrappers so call sites never pass a length (same anti-drift
 * guarantee as the macro forms). */
#define copy_from_user_checked(dst, uptr) \
    copy_from_user_checked_((dst), (uint64_t)(uintptr_t)(uptr), sizeof(*(dst)))
#define copy_to_user_checked(uptr, src) \
    copy_to_user_checked_((uint64_t)(uintptr_t)(uptr), (src), sizeof(*(src)))

#endif /* AEGIS_UACCESS_USER_H */
