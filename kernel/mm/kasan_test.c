/* kasan_test.c — KASAN self-test.  Compiled (and INSTRUMENTED) only in a
 * KASAN=1 build.  Gated behind the `kasantest` cmdline token so a normal boot
 * never runs it.  Proves the whole pipeline works: a static array gets a
 * compiler redzone, the ctor registered it, and a one-past-the-end access is
 * caught by the __asan check. */

#include "kasan.h"

#ifdef KASAN

#include "printk.h"

/* File-scope global so it is redzoned by -fsanitize=kernel-address. */
static volatile char s_probe[16];

void kasan_selftest(void)
{
    unsigned before = kasan_report_count();

    /* In-bounds: must NOT report. */
    for (int i = 0; i < 16; i++) s_probe[i] = (char)i;
    unsigned mid = kasan_report_count();

    /* One past the end: MUST report (lands in the redzone). volatile + a
     * runtime index keep the compiler from folding the access away. */
    volatile int idx = 16;
    char sink = s_probe[idx];
    (void)sink;

    unsigned after = kasan_report_count();

    if (mid == before && after == before + 1)
        printk("[KASANTEST] PASS: in-bounds clean, OOB read caught (1 report)\n");
    else
        printk("[KASANTEST] FAIL: before=%u mid=%u after=%u (want %u/%u/%u)\n",
               before, mid, after, before, before, before + 1);
}

#endif /* KASAN */
