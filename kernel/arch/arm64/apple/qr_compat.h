/* Only the pinned QR translation unit uses this freestanding libc adapter. */
#ifndef AEGIS_APPLE_QR_COMPAT_H
#define AEGIS_APPLE_QR_COMPAT_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#define LONG_MAX __LONG_MAX__
size_t strlen(const char *);
void apple_qr_assert_fail(void) __attribute__((noreturn));
#define assert(condition) do { if (!(condition)) apple_qr_assert_fail(); } while (0)
static inline int abs(int x) { return x < 0 ? -x : x; }
static inline long labs(long x) { return x < 0 ? -x : x; }
static inline const char *qr_strchr(const char *s, int c)
{
    do { if (*s == (char)c) return s; } while (*s++);
    return 0;
}
#define strchr qr_strchr
/* QR bit buffers are deliberately byte-addressed. Before MMU enable even
 * normal RAM has Device semantics, so the normal kernel's word-wide libc
 * helpers are not suitable for unaligned encoder scratch offsets. */
static inline void *qr_memset(void *out, int value, size_t n)
{
    volatile uint8_t *p = out;
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)value;
    return out;
}
static inline void *qr_memcpy(void *out, const void *in, size_t n)
{
    volatile uint8_t *d = out;
    const volatile uint8_t *s = in;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return out;
}
static inline void *qr_memmove(void *out, const void *in, size_t n)
{
    volatile uint8_t *d = out;
    const volatile uint8_t *s = in;
    if ((uintptr_t)d <= (uintptr_t)s)
        for (size_t i = 0; i < n; i++) d[i] = s[i];
    else
        for (size_t i = n; i; i--) d[i - 1] = s[i - 1];
    return out;
}
#define memset qr_memset
#define memcpy qr_memcpy
#define memmove qr_memmove
#endif
