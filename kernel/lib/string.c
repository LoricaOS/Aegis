/* kernel/lib/string.c — see string.h. Plain byte-wise implementations; no
 * word-at-a-time optimization (these are not hot enough to justify it, and the
 * private copies they replace weren't optimized either). */
#include "string.h"

void *
kmemcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

void *
kmemset(void *dst, int val, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--)
        *d++ = (unsigned char)val;
    return dst;
}

int
kmemcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (n--) {
        if (*x != *y)
            return (int)*x - (int)*y;
        x++;
        y++;
    }
    return 0;
}
