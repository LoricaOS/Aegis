#include "ksym.h"

/* Symbol table arrays.  Strong definitions are emitted at build time by
 * tools/gen-ksyms.sh into build/ksyms.c (sorted by address); the weak
 * fallbacks below keep the kernel linkable before that file exists, in which
 * case ksym_count==0 and ksym_lookup returns NULL (backtraces stay hex).
 *
 * ksym_names is a run of NUL-terminated names in the same order as ksym_addrs.
 * ksym_lookup walks to the idx-th name — no separate offset table — so the
 * generator needs no per-name length arithmetic (it can't rely on awk, which
 * isn't in the self-hosting toolchain rootfs). A backtrace does a handful of
 * lookups, so the O(idx) walk is irrelevant. */
__attribute__((weak)) const uint32_t ksym_count = 0;
__attribute__((weak)) const uint64_t ksym_addrs[1] = { 0 };
__attribute__((weak)) const char     ksym_names[1] = { 0 };

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
    /* Walk to the idx-th NUL-terminated name in ksym_names. */
    const char *p = ksym_names;
    for (uint32_t k = 0; k < idx; k++) {
        while (*p)
            p++;
        p++;   /* skip the NUL separator */
    }
    return p;
}
