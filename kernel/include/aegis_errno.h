#ifndef AEGIS_ERRNO_H
#define AEGIS_ERRNO_H
/*
 * aegis_errno.h — the one errno table + the syscall-return encoder.
 *
 * Aegis syscalls return errors the Linux/musl way: a NEGATIVE errno value in
 * the return register, which musl's syscall wrapper turns into errno + -1. In
 * C that means `return (uint64_t)-(int64_t)EFAULT;`. Before this header that
 * expression appeared ~345 times across 17 files, almost always as a BARE
 * MAGIC NUMBER — `-(int64_t)14`, `-(int64_t)22`, `-(int64_t)12` — with only
 * ENOCAP (130) consistently named. The same value meant different things to a
 * reader depending on file, and there was no single place to look up a number.
 *
 * Worse, the few symbolic errno #defines were SCATTERED and DUPLICATED:
 *   - cap/cap.h            ENOCAP 130
 *   - syscall/sys_impl.h   ERANGE 34, EBADF 9, ENOTDIR 20  (under #ifndef)
 *   - syscall/sys_io.c     EISDIR 21    \  the SAME macro
 *   - fs/initrd.c          EISDIR 21    /  defined in two files
 *   - fs/ext2_internal.h   EINVAL 22
 * Two independent EISDIR 21 definitions is exactly the drift this prevents.
 *
 * This header is the SINGLE source of truth. Values are the Linux asm-generic
 * numbers (what the codebase already used and what musl expects on the wire —
 * do NOT renumber). The migration deletes every scattered #define above and
 * replaces the magic numbers with these names + SYS_ERR().
 *
 * Pure #define header — no types, no code, safe to include anywhere (kernel C
 * and the Rust FFI side both already speak these numbers). Include as
 * "../include/aegis_errno.h" or add -Ikernel/include.
 */

/*
 * SYS_ERR(e) — encode errno `e` as the negative value a syscall returns in a
 * uint64_t register. Replaces every hand-written `(uint64_t)-(int64_t)N`.
 *   return SYS_ERR(EFAULT);   // was: return (uint64_t)-(int64_t)14;
 * The double cast is load-bearing: negate as a signed 64-bit value, THEN
 * reinterpret the bit pattern as unsigned, so the sign bits are all set (musl
 * checks `ret >= -4095UL`). Parenthesise `(e)` so SYS_ERR(a ? b : c) works.
 */
#define SYS_ERR(e) ((uint64_t)-(int64_t)(e))

/* ── Linux asm-generic errno numbers (the values already in use) ─────────── */
/* Only the values that actually appear in the tree are listed; add more from
 * the Linux table as needed, never invent Aegis-local numbers. The trailing
 * comment on each is its occurrence-count hint from the 2026-06-15 sweep, to
 * help reviewers spot the high-traffic ones. */

#define EPERM            1   /* Operation not permitted            (~25) */
#define ENOENT           2   /* No such file or directory           (~4) */
#define ESRCH            3   /* No such process                     (~4) */
#define EINTR            4   /* Interrupted syscall (wait_event rc) (~6) */
#define EIO              5   /* I/O error                           (~3) */
#define E2BIG            7   /* Argument list too long (exec/spawn stack) */
#define ENOEXEC          8   /* Exec format error                   (~3) */
#define EBADF            9   /* Bad file descriptor                (~14) */
#define EAGAIN          11   /* Try again / would block             (~5) */
#define ENOMEM          12   /* Out of memory                      (~31) */
#define EACCES          13   /* Permission denied                  (~11) */
#define EFAULT          14   /* Bad address (user_ptr_valid fail) (~101) */
#define EBUSY           16   /* Device or resource busy                  */
#define EEXIST          17   /* File exists                              */
#define EXDEV           18   /* Cross-device link                   (~1) */
#define ENODEV          19   /* No such device                      (~1) */
#define ENOTDIR         20   /* Not a directory                     (~1) */
#define EISDIR          21   /* Is a directory                           */
#define EINVAL          22   /* Invalid argument                   (~54) */
#define EMFILE          24   /* Too many open files                (~10) */
#define ENOTTY          25   /* Inappropriate ioctl for device      (~8) */
#define ENOSPC          28   /* No space left on device             (~1) */
#define ESPIPE          29   /* Illegal seek                        (~1) */
#define EPIPE           32   /* Broken pipe                         (~1) */
#define ERANGE          34   /* Result too large                         */
#define ENAMETOOLONG    36   /* File name too long                  (~6) */
#define ENOSYS          38   /* Function not implemented            (~2) */
#define ENOTEMPTY       39   /* Directory not empty                      */
#define ELOOP           40   /* Too many symlinks                        */
#define ENOTSOCK        88   /* Not a socket                             */
#define EDESTADDRREQ    89   /* Destination address required        (~1) */
#define EMSGSIZE        90   /* Message too long                         */
#define ENOPROTOOPT     92   /* Protocol not available              (~2) */
#define EPROTONOSUPPORT 93   /* Protocol not supported              (~3) */
#define EOPNOTSUPP      95   /* Operation not supported on socket   (~1) */
#define EAFNOSUPPORT    97   /* Address family not supported        (~2) */
#define EADDRINUSE      98   /* Address already in use              (~4) */
#define ENETDOWN       100   /* Network is down                     (~2) */
#define EISCONN        106   /* Transport endpoint already connected(~1) */
#define ENOTCONN       107   /* Transport endpoint not connected    (~2) */
#define ETIMEDOUT      110   /* Connection timed out (wait_event rc)(~2) */
#define ECONNREFUSED   111   /* Connection refused                  (~1) */
#define EALREADY       114   /* Operation already in progress       (~1) */
#define EINPROGRESS    115   /* Operation now in progress           (~1) */

/* Aegis-internal name for "no matching capability". Returned from cap_check /
 * cap_grant as -ENOCAP internally and bubbled up to userspace via the ~27
 * `return SYS_ERR(ENOCAP)` sites. The old value (130) is not in musl's errno
 * table, so userspace saw a meaningless strerror() on every cap-gate denial.
 * Alias to EPERM (1) so a cap denial lands as the conventional POSIX
 * "operation not permitted". The kernel-internal contract is unchanged —
 * cap_check/cap_grant callers test `!= 0` / `>= 0`, never equality to a
 * specific numeric value (verified: no `== ENOCAP` checks, no Rust dependency
 * on 130). Single-sourced here for the Rust/C boundary and every syscall. */
#define ENOCAP           1   /* Missing capability (Aegis) == EPERM (~5) */

#endif /* AEGIS_ERRNO_H */
