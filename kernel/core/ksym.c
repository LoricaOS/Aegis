#include "ksym.h"

/* Symbol table arrays.  Strong definitions are emitted at build time by
 * tools/gen-ksyms.sh into build/ksyms.c (sorted by address); the weak
 * fallbacks below keep the kernel linkable before that file exists, in which
 * case ksym_count==0 and ksym_lookup returns NULL (backtraces stay hex).
 *
 * ksym_names is an array of name pointers in the same order as ksym_addrs, so
 * ksym_lookup indexes it directly. (Emitting a pointer array rather than a
 * NUL-separated blob keeps the generator to plain `echo` — no printf, and no
 * literal `\0` escape, neither of which is portable across the host shell and
 * stsh in the self-hosting toolchain rootfs.) */
__attribute__((weak)) const uint32_t     ksym_count    = 0;
__attribute__((weak)) const uint64_t     ksym_addrs[1] = { 0 };
__attribute__((weak)) const char *const  ksym_names[1] = { 0 };

const char *
ksym_lookup(uint64_t addr, uint64_t *off)
{
    uint32_t n = ksym_count;
    if (n == 0)
        return (const char *)0;

    /* Binary search for the greatest table address <= addr. */
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (ksym_addrs[mid] <= addr)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0)
        return (const char *)0;   /* addr below the first symbol */

    uint32_t idx = lo - 1;
    if (off)
        *off = addr - ksym_addrs[idx];
    return ksym_names[idx];
}
