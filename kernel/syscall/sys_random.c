/* sys_random.c — getrandom(2) syscall implementation. */
#include "sys_impl.h"
#include "sched.h"
#include "proc.h"
#include "random.h"

#define GRND_NONBLOCK 0x0001u
#define GRND_RANDOM   0x0002u

/*
 * sys_getrandom — syscall 318 (x86-64), 278 (ARM64)
 *
 * Fills a user-space buffer with cryptographically random bytes from
 * the kernel ChaCha20 CSPRNG.
 *
 * arg1 = user pointer to output buffer
 * arg2 = buffer length in bytes
 * arg3 = flags (GRND_NONBLOCK, GRND_RANDOM — both treated identically
 *         since our pool is always seeded)
 *
 * Returns number of bytes written on success, negative errno on failure.
 * Capped at 256 bytes per call (matches Linux behavior for small reads;
 * larger reads should use /dev/urandom).
 */
uint64_t
sys_getrandom(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    (void)arg3;  /* flags — pool is always seeded, GRND_NONBLOCK is a no-op */

    uint64_t len = arg2;
    if (len == 0)
        return 0;

    /* Cap per-call output to 256 bytes. Callers needing more should loop
     * or use /dev/urandom. This keeps the kernel-side bounce buffer small. */
    if (len > 256)
        len = 256;

    if (!user_ptr_valid(arg1, len))
        return SYS_ERR(EFAULT);

    /* Generate into a kernel buffer, then copy to userspace. */
    uint8_t kbuf[256];
    random_get_bytes(kbuf, (size_t)len);
    copy_to_user((void *)(uintptr_t)arg1, kbuf, (uint32_t)len);

    return len;
}
