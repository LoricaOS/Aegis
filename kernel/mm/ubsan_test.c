/* ubsan_test.c — UBSAN self-test.  Compiled (and INSTRUMENTED) only in a
 * UBSAN=1 build.  Gated behind the `ubsantest` cmdline token so a normal boot
 * never runs it.  Proves the pipeline works: an operation the compiler cannot
 * prove safe (a signed shift past the type width) trips a __ubsan_handle_*
 * call, which the runtime reports. */

#include "ubsan.h"

#ifdef UBSAN

#include "printk.h"

void ubsan_selftest(void)
{
    unsigned before = ubsan_report_count();

    /* Well-defined shift: must NOT report.  volatile inputs stop the compiler
     * from constant-folding (and thus diagnosing/eliding) the operation. */
    volatile int v = 1, ok = 4;
    volatile int r1 = v << ok;
    (void)r1;
    unsigned mid = ubsan_report_count();

    /* Shift a 32-bit int by 40 — undefined (>= width).  MUST report. */
    volatile int bad = 40;
    volatile int r2 = v << bad;
    (void)r2;
    unsigned after = ubsan_report_count();

    if (mid == before && after == before + 1)
        printk("[UBSANTEST] PASS: defined shift clean, over-wide shift caught (1 report)\n");
    else
        printk("[UBSANTEST] FAIL: before=%u mid=%u after=%u (want %u/%u/%u)\n",
               before, mid, after, before, before, before + 1);
}

#endif /* UBSAN */
