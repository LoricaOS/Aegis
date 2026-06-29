#include "arch.h"
#include "printk.h"
#include <stdint.h>

int arch_smap_enabled = 0;

/* g_use_xsave — 1 once AVX has been enabled (CR4.OSXSAVE + XCR0 bits 0-2) on
 * this boot's CPUs.  ctx_switch.asm and the fpu_state_* helpers branch on this:
 * XSAVE/XRSTOR (covers YMM) when set, FXSAVE/FXRSTOR (SSE only) when clear.
 * Clear on CPUs without XSAVE+AVX (e.g. QEMU's default `qemu64` used by the
 * boot oracle) so those still work with the legacy SSE-only context switch —
 * AVX user code simply can't run there, which is fine (qemu64 never runs it).
 * Set identically by every CPU's arch_sse_init(); read after that point. */
uint8_t g_use_xsave = 0;

/*
 * arch_sse_init — enable SSE/SSE2 for user-mode code.
 *
 * musl's TLS initialisation uses SSE instructions (movq xmm0, punpcklqdq,
 * movaps) even on a simple binary.  Without this sequence the CPU raises #UD
 * (exception 6) on the first SSE instruction in user space.
 *
 * Required bits:
 *   CR0.EM (bit 2) — must be 0 ("no emulation"; set by BIOS/UEFI, clear it to be safe)
 *   CR0.MP (bit 1) — must be 1 (monitor co-processor, lets WAIT fault on TS)
 *   CR4.OSFXSR     (bit 9)  — OS declares it supports FXSAVE/FXRSTOR
 *   CR4.OSXMMEXCPT (bit 10) — OS handles SSE numeric exceptions (#XF)
 *
 * This must be called before sched_start() hands control to user space.
 * The kernel itself is compiled -mno-sse so the kernel never touches XMM
 * registers; these bits only affect user-mode execution.
 */
void
arch_sse_init(void)
{
    /* Clear CR0.EM (bit 2 = 0x4), set CR0.MP (bit 1 = 0x2) */
    __asm__ volatile (
        "mov %%cr0, %%rax\n"
        "and $0xFFFFFFFFFFFFFFFB, %%rax\n"  /* clear bit 2 (EM) */
        "or  $0x2, %%rax\n"                 /* set   bit 1 (MP) */
        "mov %%rax, %%cr0\n"
        : : : "rax"
    );
    /* Set CR4.OSFXSR (bit 9 = 0x200) and CR4.OSXMMEXCPT (bit 10 = 0x400) */
    __asm__ volatile (
        "mov %%cr4, %%rax\n"
        "or  $0x600, %%rax\n"               /* set bits 9 and 10 */
        "mov %%rax, %%cr4\n"
        : : : "rax"
    );

    /* Enable AVX (YMM) for user-mode code.  Modern toolchains emit AVX
     * unconditionally (e.g. Ladybird's libs), so without this the first VEX
     * instruction in user space raises #UD.  Requires:
     *   CPUID.1:ECX.XSAVE (bit 26) and CPUID.1:ECX.AVX (bit 28),
     *   CR4.OSXSAVE (bit 18) set, then XCR0 bits 0-2 (x87|SSE|AVX) via XSETBV.
     * Guarded on CPUID: a CPU without XSAVE+AVX (QEMU qemu64) keeps FXSAVE-only
     * state and g_use_xsave stays 0.  XSAVE/XRSTOR (which save YMM) then become
     * the context-switch primitive — see ctx_switch.asm / fpu_state_* . */
    {
        uint32_t eax, ebx, ecx, edx;
        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "0"(1), "2"(0));
        if ((ecx & (1u << 26)) && (ecx & (1u << 28))) {  /* XSAVE && AVX */
            __asm__ volatile (
                "mov %%cr4, %%rax\n"
                "or  $0x40000, %%rax\n"     /* CR4.OSXSAVE (bit 18) */
                "mov %%rax, %%cr4\n"
                : : : "rax"
            );
            /* XSETBV: XCR0 = 0x7 (x87 | SSE | AVX).  ECX=0 selects XCR0. */
            __asm__ volatile (
                "xor %%ecx, %%ecx\n"
                "mov $0x7, %%eax\n"
                "xor %%edx, %%edx\n"
                "xsetbv\n"
                : : : "rax", "rcx", "rdx"
            );
            g_use_xsave = 1;
        }
    }
}

static int
cpuid_smap_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    /* CPUID leaf 7, subleaf 0, EBX bit 20 = SMAP.
     * cpuid overwrites all four registers; declare them all as outputs so
     * the compiler does not assume EAX/ECX retain their input values.
     * "0"(7) places leaf 7 in EAX (same register as output operand 0);
     * "2"(0) places subleaf 0 in ECX (same register as output operand 2). */
    __asm__ volatile (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "0"(7), "2"(0)
    );
    (void)eax; (void)ecx; (void)edx;
    return (ebx >> 20) & 1;
}

void
arch_smap_init(void)
{
    if (!cpuid_smap_supported()) {
        printk("[SMAP] WARN: not supported by CPU\n");
        return;
    }
    /* Set CR4.SMAP (bit 21 = 0x200000) */
    __asm__ volatile (
        "mov %%cr4, %%rax\n"
        "or $0x200000, %%rax\n"
        "mov %%rax, %%cr4\n"
        : : : "rax"
    );
    arch_smap_enabled = 1;
    printk("[SMAP] OK: supervisor access prevention active\n");
}

static int
cpuid_smep_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    /* CPUID leaf 7, subleaf 0, EBX bit 7 = SMEP.
     * cpuid overwrites all four registers; declare them all as outputs so
     * the compiler does not assume EAX/ECX retain their input values.
     * "0"(7) places leaf 7 in EAX (same register as output operand 0);
     * "2"(0) places subleaf 0 in ECX (same register as output operand 2). */
    __asm__ volatile (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "0"(7), "2"(0)
    );
    (void)eax; (void)ecx; (void)edx;
    return (ebx >> 7) & 1;   /* bit 7 = SMEP */
}

void
arch_smep_init(void)
{
    if (!cpuid_smep_supported()) {
        printk("[SMEP] WARN: not supported by CPU\n");
        return;
    }
    /* Set CR4.SMEP (bit 20 = 0x100000) */
    __asm__ volatile (
        "mov %%cr4, %%rax\n"
        "or $0x100000, %%rax\n"
        "mov %%rax, %%cr4\n"
        : : : "rax"
    );
    printk("[SMEP] OK: supervisor mode execution prevention active\n");
}

/* ── Fault-tolerant user copy (exception table) ─────────────────────────────
 *
 * __uaccess_copy is the single primitive behind copy_from_user / copy_to_user.
 * The rep-movsb that touches the user buffer is registered in the __ex_table
 * (a {fault_pc, fixup_pc} pair emitted into .rodata by linker.ld). If that
 * access faults — e.g. a sibling thread munmap'd the buffer during a blocking
 * syscall, the validate-then-block-then-copy TOCTOU class — the #PF handler
 * (isr_dispatch) looks the faulting RIP up via ex_table_lookup and redirects
 * execution to the fixup instead of panic_halt()ing the kernel. This makes
 * EVERY copy_*_user fault-safe (graceful, no ring-0 panic) without each caller
 * having to re-validate. stac/clac live inside the asm block (not around a
 * function call) to honor the arch.h "no call between stac/clac" rule.
 *
 * Returns the number of bytes NOT copied (0 = full success, Linux convention).
 * On a fault, rcx holds the remaining count at the faulting iteration, so the
 * "+c" output captures bytes-not-copied automatically. */
uint64_t
__uaccess_copy(void *dst, const void *src, uint64_t len)
{
    uint64_t remaining = len;
    if (arch_smap_enabled) {
        __asm__ volatile (
            "   stac\n"
            "1: rep movsb\n"
            "2: clac\n"
            ".pushsection __ex_table,\"a\"\n"
            "   .align 8\n"
            "   .quad 1b\n"   /* fault_pc: the user-touching rep movsb        */
            "   .quad 2b\n"   /* fixup_pc: clac + fall through (rcx=remaining) */
            ".popsection\n"
            : "+c"(remaining), "+D"(dst), "+S"(src)
            :
            : "memory");
    } else {
        __asm__ volatile (
            "1: rep movsb\n"
            "2:\n"
            ".pushsection __ex_table,\"a\"\n"
            "   .align 8\n"
            "   .quad 1b\n"
            "   .quad 2b\n"
            ".popsection\n"
            : "+c"(remaining), "+D"(dst), "+S"(src)
            :
            : "memory");
    }
    return remaining;
}

/* ex_table entry layout must match the .quad pairs emitted above. */
typedef struct { uint64_t fault_pc; uint64_t fixup_pc; } ex_entry_t;
extern const ex_entry_t __start_ex_table[];
extern const ex_entry_t __stop_ex_table[];

/* ex_table_lookup — if `rip` is a registered faulting instruction, return its
 * fixup address; else 0. Called from the #PF/#GP path in isr_dispatch for
 * kernel-mode faults only. Linear scan: the table has one entry (the single
 * non-inline __uaccess_copy), so this is O(1) in practice. */
uint64_t
ex_table_lookup(uint64_t rip)
{
    const ex_entry_t *e;
    for (e = __start_ex_table; e < __stop_ex_table; e++) {
        if (e->fault_pc == rip)
            return e->fixup_pc;
    }
    return 0;
}
