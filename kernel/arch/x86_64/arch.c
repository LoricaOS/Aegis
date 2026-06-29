#include "arch.h"
#include "serial.h"
#include "vga.h"

/*
 * arch_init — initialize all x86_64 early subsystems.
 *
 * Called once from kernel_main before any other subsystem.
 * Order matters: serial must be up before vga_init (vga_init calls serial).
 * Clobbers: nothing directly (subsystems manage their own state).
 */
void arch_init(void)
{
    serial_init();
    vga_init();
}

/* arch_pat_init — enable Write-Combining in PAT entry 1.
 *
 * Default IA32_PAT layout (Intel/AMD):
 *   PA0=WB(06), PA1=WT(04), PA2=UC-(07), PA3=UC(00), PA4-PA7 mirror PA0-PA3.
 *
 * After this call:
 *   PA0=WB(06), PA1=WC(01), PA2=UC-(07), PA3=UC(00) — PA4-PA7 mirror PA0-PA3.
 *   (PA5 also changes from WT to WC; bits [39:32] of the MSR. The PAT bit in
 *   4KB PTEs is never set by this kernel, so PA4-PA7 are unused in practice.)
 *
 * This allows VMM_FLAG_WC (PWT=1, PCD=0) to select WC for framebuffer pages.
 */
void arch_pat_init(void)
{
    uint32_t cpuid_edx;

    /* Check CPUID.1:EDX[16] — PAT support bit. */
    __asm__ volatile (
        "cpuid"
        : "=d"(cpuid_edx)
        : "a"(1u)
        : "ebx", "ecx"
    );
    if (!(cpuid_edx & (1u << 16)))
        return;   /* CPU lacks PAT — VMM_FLAG_WC falls back to WT; acceptable */

    /* New PAT value:
     *   PA0=WB(06), PA1=WC(01), PA2=UC-(07), PA3=UC(00),
     *   PA4=WB(06), PA5=WC(01), PA6=UC-(07), PA7=UC(00) */
    const uint64_t pat_val = 0x0007010600070106ULL;

    /* wrmsr IA32_PAT (0x277) */
    __asm__ volatile (
        "wrmsr"
        :
        : "c"(0x277u),
          "a"((uint32_t)(pat_val & 0xFFFFFFFFU)),
          "d"((uint32_t)(pat_val >> 32))
    );
}
