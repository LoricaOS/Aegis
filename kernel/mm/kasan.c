/* kasan.c — Kernel Address Sanitizer runtime (globals/BSS coverage).
 *
 * Compiled ONLY in a KASAN=1 build.  This file itself is built WITHOUT the
 * sanitizer (see the Makefile's kasan.o rule) — it must never instrument its
 * own shadow accesses.
 *
 * The compiler emits an __asan_load or __asan_store call before every access.
 *
 * Model (standard KASAN): 1 shadow byte per 8 bytes of covered memory.
 *   shadow == 0        → all 8 bytes addressable
 *   shadow == 1..7 (k) → first k bytes addressable, rest poisoned
 *   shadow  < 0  (0x80..0xff, e.g. the 0xf9 global-redzone magic) → all poisoned
 *
 * Coverage is the kernel image window [KASAN_LO, KASAN_HI) only — that is where
 * every static/global object (.data/.bss) lives, so a redzone overrun on a
 * static array is caught here.  The compiler forces every check to a call
 * (asan-instrumentation-with-call-threshold=0), so the range guard below lets
 * us leave the rest of the 64-bit address space (the direct map, MMIO, user VA,
 * stacks) uncovered without needing shadow for it.
 *
 * Reports are report-and-CONTINUE (like Linux's default): the access still
 * proceeds after the check, so one boot surfaces every corruption rather than
 * dying on the first.  kasan_report_count() != 0 means something was caught. */

#include "kasan.h"

#ifdef KASAN

#include "kva.h"
#include "printk.h"
#include "stackshot.h"
#include "arch.h"          /* ARCH_KERNEL_VIRT_BASE */
#include <stdint.h>
#include <stddef.h>

/* Covered window: the kernel image + BSS.  The linker ASSERTs image+BSS <= 8MB
 * (KERN_VMA+0x800000, the VMM window base), so this window covers all of it. */
#define KASAN_LO           ARCH_KERNEL_VIRT_BASE
#define KASAN_SPAN         0x800000UL          /* 8 MB image window            */
#define KASAN_HI           (KASAN_LO + KASAN_SPAN)
#define KASAN_SHADOW_BYTES (KASAN_SPAN / 8)    /* 1 MB shadow                  */
#define KASAN_GRAN         8

#define KASAN_GLOBAL_REDZONE 0xf9              /* libsanitizer magic           */

static uint8_t *s_shadow;      /* shadow[(a - KASAN_LO) >> 3]                   */
static int      s_ready;
static unsigned s_reports;

/* GCC's __asan_global descriptor (ABI-fixed layout). */
struct kasan_global {
    const void   *beg;
    uint64_t      size;
    uint64_t      size_with_redzone;
    const char   *name;
    const char   *module_name;
    uint64_t      has_dynamic_init;
    const void   *location;
    uint64_t      odr_indicator;
};

/* Global constructors GCC emits (asan.module_ctor lands in .init_array). */
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

static inline uint8_t *shadow_for(uint64_t addr)
{
    return s_shadow + ((addr - KASAN_LO) >> 3);
}

static inline int in_window(uint64_t addr, uint64_t size)
{
    return addr >= KASAN_LO && (addr + size) <= KASAN_HI;
}

/* Write `value` to the shadow bytes covering [addr, addr+size).  addr and size
 * must be 8-aligned (redzone regions always are). */
static void poison_shadow(uint64_t addr, uint64_t size, uint8_t value)
{
    if (!in_window(addr, size)) return;
    uint8_t *s = shadow_for(addr);
    for (uint64_t i = 0; i < size / KASAN_GRAN; i++)
        s[i] = value;
}

/* Is any byte in [addr, addr+size) poisoned?  Per-byte; size is <= 16. */
static int is_poisoned(uint64_t addr, uint64_t size)
{
    for (uint64_t i = 0; i < size; i++) {
        uint64_t a = addr + i;
        int8_t  sv = (int8_t)*shadow_for(a);
        if (sv == 0) continue;                 /* granule fully addressable    */
        int last = (int)(a & (KASAN_GRAN - 1));
        if (sv < 0 || last >= sv) return 1;    /* poisoned / past partial edge */
    }
    return 0;
}

static const char *shadow_class(uint8_t sv)
{
    switch (sv) {
    case KASAN_GLOBAL_REDZONE: return "global-redzone (out-of-bounds)";
    default:                   return (sv & 0x80) ? "poisoned" : "partial-granule";
    }
}

static void kasan_report(uint64_t addr, uint64_t size, int write, void *pc)
{
    s_reports++;
    uint8_t sv = *shadow_for(addr);
    printk("\n==================================================================\n");
    printk("[KASAN] %s of size %u at 0x%lx\n",
           write ? "WRITE" : "READ", (unsigned)size, (unsigned long)addr);
    printk("[KASAN] pc=0x%lx  shadow=0x%x (%s)\n",
           (unsigned long)pc, (unsigned)sv, shadow_class(sv));
    print_backtrace_from((uint64_t)__builtin_frame_address(0), 16);
    printk("==================================================================\n");
    /* report-and-continue: the actual access proceeds after we return */
}

static inline void check(uint64_t addr, uint64_t size, int write, void *pc)
{
    if (!s_ready) return;
    if (!in_window(addr, size)) return;        /* outside covered image window */
    if (is_poisoned(addr, size))
        kasan_report(addr, size, write, pc);
}

/* ---- compiler-called instrumentation ABI (outline) --------------------- */

/* Kernel KASAN is always recover-mode: the compiler emits the _noabort forms. */
#define ASAN_ACCESS(sz)                                                    \
    void __asan_load##sz##_noabort(uint64_t a)  { check(a, sz, 0, __builtin_return_address(0)); } \
    void __asan_store##sz##_noabort(uint64_t a) { check(a, sz, 1, __builtin_return_address(0)); }
ASAN_ACCESS(1)
ASAN_ACCESS(2)
ASAN_ACCESS(4)
ASAN_ACCESS(8)
ASAN_ACCESS(16)
#undef ASAN_ACCESS

void __asan_loadN_noabort(uint64_t a, uint64_t sz)  { check(a, sz, 0, __builtin_return_address(0)); }
void __asan_storeN_noabort(uint64_t a, uint64_t sz) { check(a, sz, 1, __builtin_return_address(0)); }

void __asan_handle_no_return(void) {}

/* GCC 14 emits a version handshake call from each module ctor. */
void __asan_version_mismatch_check_v8(void) {}

void __asan_register_globals(struct kasan_global *g, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++) {
        uint64_t beg     = (uint64_t)g[i].beg;
        uint64_t size    = g[i].size;
        uint64_t aligned = (size + KASAN_GRAN - 1) & ~(uint64_t)(KASAN_GRAN - 1);
        /* Poison the trailing redzone [beg+aligned, beg+size_with_redzone). */
        poison_shadow(beg + aligned, g[i].size_with_redzone - aligned,
                      KASAN_GLOBAL_REDZONE);
        /* Partial last granule: first (size%8) bytes stay addressable. */
        if (size != aligned && in_window(beg + size, 1))
            *shadow_for(beg + aligned - KASAN_GRAN) = (uint8_t)(size & (KASAN_GRAN - 1));
    }
}

void __asan_unregister_globals(struct kasan_global *g, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++)
        poison_shadow((uint64_t)g[i].beg, g[i].size_with_redzone, 0);
}

/* ---- init ------------------------------------------------------------- */

void kasan_init(void)
{
    /* Shadow is allocated in the kva heap, which sits ABOVE KASAN_HI — so it is
     * outside the covered window and shadow-of-shadow never arises. */
    s_shadow = (uint8_t *)kva_alloc_pages(KASAN_SHADOW_BYTES / 4096);
    for (uint64_t i = 0; i < KASAN_SHADOW_BYTES; i++)
        s_shadow[i] = 0;                       /* default: all addressable     */
    s_ready = 1;

    /* Run the compiler's global-registration constructors now that shadow is
     * live; each poisons its module's redzones. */
    unsigned nctor = (unsigned)(__init_array_end - __init_array_start);
    for (unsigned i = 0; i < nctor; i++)
        __init_array_start[i]();

    printk("[KASAN] OK: shadow 0x%lx, %u ctors, window 0x%lx..0x%lx\n",
           (unsigned long)s_shadow, nctor,
           (unsigned long)KASAN_LO, (unsigned long)KASAN_HI);
}

unsigned kasan_report_count(void) { return s_reports; }

#endif /* KASAN */
