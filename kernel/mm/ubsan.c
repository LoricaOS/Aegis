/* ubsan.c — Undefined Behavior Sanitizer runtime.
 *
 * Compiled ONLY in a UBSAN=1 build (see the Makefile), which turns on
 * -fsanitize=undefined.  The compiler then emits a __ubsan_handle_* call at
 * every site where it cannot prove a signed overflow, a shift past the type
 * width, a misaligned/null pointer access, an out-of-bounds index (on anything
 * it can size), or a divide overflow is impossible.  Each handler here decodes
 * the site's source location and reports it with a backtrace.
 *
 * Report-and-continue (like kasan.c): the offending operation still proceeds
 * after we return, so one boot surfaces every UB site rather than dying on the
 * first.  ubsan_report_count() != 0 means something was caught.
 *
 * Every handler's first argument points to a struct whose first member is a
 * `struct source_location` — that is ABI-stable across all the handler-specific
 * data structs, so we decode file:line:col uniformly without modelling each one.
 *
 * A recursion guard disables reporting for the duration of a report: if the
 * reporting path (printk, backtrace) itself trips instrumentation, we must not
 * recurse.  Reporting is inert until ubsan_init() flips it on, so pre-console
 * early boot stays silent. */

#include "ubsan.h"

#ifdef UBSAN

#include "printk.h"
#include "stackshot.h"
#include <stdint.h>

struct source_location {
    const char *filename;
    uint32_t    line;
    uint32_t    column;
};

static int      s_enabled;     /* 0 until ubsan_init(); also the recursion guard */
static unsigned s_reports;

static void report(void *data, const char *kind)
{
    if (!s_enabled) return;
    s_enabled = 0;             /* guard: no recursive reports during a report    */
    s_reports++;

    const struct source_location *loc = (const struct source_location *)data;
    printk("\n==================================================================\n");
    if (loc && loc->filename)
        printk("[UBSAN] %s at %s:%u:%u\n",
               kind, loc->filename, (unsigned)loc->line, (unsigned)loc->column);
    else
        printk("[UBSAN] %s (no location)\n", kind);
    print_backtrace_from((uint64_t)__builtin_frame_address(0), 16);
    printk("==================================================================\n");

    s_enabled = 1;
}

/* ---- compiler-called handler ABI --------------------------------------- */
/* These are the handlers a -fsanitize=undefined x86-64/aarch64 kernel build
 * actually emits; the value args are unused (we report the site, not operands).
 * The _minimal-runtime variants are NOT used — we build with the full runtime
 * so `data` carries the source location. */

#define UB_H2(name, label) \
    void __ubsan_handle_##name(void *data, void *a, void *b) \
    { (void)a; (void)b; report(data, label); }

UB_H2(add_overflow,        "signed addition overflow")
UB_H2(sub_overflow,        "signed subtraction overflow")
UB_H2(mul_overflow,        "signed multiplication overflow")
UB_H2(divrem_overflow,     "division overflow")
UB_H2(shift_out_of_bounds, "shift out of bounds")
UB_H2(pointer_overflow,    "pointer overflow")

void __ubsan_handle_negate_overflow(void *data, void *v)
{ (void)v; report(data, "negation overflow"); }

void __ubsan_handle_out_of_bounds(void *data, void *index)
{ (void)index; report(data, "array index out of bounds"); }

void __ubsan_handle_type_mismatch_v1(void *data, void *ptr)
{
    /* data->loc is preceded by nothing; the struct is
     * { source_location loc; type_descriptor *type; u8 log_align; u8 kind; }.
     * A null ptr is the most common trip (null deref); report either way. */
    (void)ptr;
    report(data, "type mismatch (misaligned/null/unsized access)");
}

void __ubsan_handle_load_invalid_value(void *data, void *v)
{ (void)v; report(data, "load of invalid value (bad bool/enum)"); }

void __ubsan_handle_vla_bound_not_positive(void *data, void *bound)
{
    if ((uintptr_t)bound == 0) return;   /* zero-length VLA is not itself UB      */
    report(data, "VLA bound not positive");
}

void __ubsan_handle_builtin_unreachable(void *data)
{ report(data, "reached __builtin_unreachable()"); }

void __ubsan_handle_invalid_builtin(void *data)
{ report(data, "invalid builtin (e.g. ctz/clz of 0)"); }

void __ubsan_handle_nonnull_arg(void *data)
{ report(data, "null passed to nonnull argument"); }

void __ubsan_handle_nonnull_return_v1(void *data, void *loc)
{
    /* data->loc is the attribute site; `loc` is the return site. Prefer the
     * return site when the attribute site has no filename. */
    const struct source_location *d = (const struct source_location *)data;
    report((d && d->filename) ? data : loc, "null returned from nonnull function");
}

void __ubsan_handle_alignment_assumption(void *data, void *ptr, void *align, void *off)
{ (void)ptr; (void)align; (void)off; report(data, "alignment assumption violated"); }

/* ---- init -------------------------------------------------------------- */

void ubsan_init(void)
{
    s_enabled = 1;
    printk("[UBSAN] OK: reporting enabled (report-and-continue)\n");
}

unsigned ubsan_report_count(void) { return s_reports; }

#endif /* UBSAN */
