/* kernel/lib/string.c — see string.h. Word-wide (uint64_t) bodies with byte
 * head/tail: these back ~70 call sites across net/fs/drivers, and GCC keeps
 * the named kmem* loops as byte loops even at -O2 (the memcpy-idiom rewrite
 * only fires for the standard names). Unaligned uint64_t loads/stores are
 * fine on x86-64 and on arm64 with MMU on (normal memory). */
#include "string.h"
#include <stdint.h>

void *
kmemcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n >= 8) {
        uint64_t w;
        __builtin_memcpy(&w, s, 8);
        __builtin_memcpy(d, &w, 8);
        d += 8; s += 8; n -= 8;
    }
    while (n--)
        *d++ = *s++;
    return dst;
}

void *
kmemset(void *dst, int val, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    uint64_t w = 0x0101010101010101ULL * (unsigned char)val;
    while (n >= 8) {
        __builtin_memcpy(d, &w, 8);
        d += 8; n -= 8;
    }
    while (n--)
        *d++ = (unsigned char)val;
    return dst;
}

int
kmemcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (n >= 8) {
        uint64_t wx, wy;
        __builtin_memcpy(&wx, x, 8);
        __builtin_memcpy(&wy, y, 8);
        if (wx != wy) break;   /* fall through to the byte loop for the diff */
        x += 8; y += 8; n -= 8;
    }
    while (n--) {
        if (*x != *y)
            return (int)*x - (int)*y;
        x++;
        y++;
    }
    return 0;
}

/*
 * Standard C mem* symbols. GCC emits calls to these for struct assignments,
 * array initializers, and the like even in a freestanding kernel. They used to
 * be supplied by the Rust cap crate's bundled compiler_builtins (libcap.a); now
 * that the cap core is plain C (kernel/cap/cap.c), the kernel must provide them.
 * They delegate to the kmem* bodies above, which -O2 keeps as real loops rather
 * than rewriting into a self-call. memmove carries the no-pattern attribute so
 * its own byte loops are never turned back into a memmove/memcpy call.
 */
void *memcpy(void *dst, const void *src, size_t n) { return kmemcpy(dst, src, n); }
void *memset(void *dst, int val, size_t n)         { return kmemset(dst, val, n); }
int   memcmp(const void *a, const void *b, size_t n) { return kmemcmp(a, b, n); }

__attribute__((optimize("no-tree-loop-distribute-patterns")))
void *
memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0)
        return dst;
    if (d < s)                          /* forward copy is safe when dst < src */
        for (size_t i = 0; i < n; i++) d[i] = s[i];
    else                                /* overlap with dst > src: copy backward */
        for (size_t i = n; i > 0; i--)  d[i-1] = s[i-1];
    return dst;
}
