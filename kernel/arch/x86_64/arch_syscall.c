#include "arch.h"
#include "printk.h"
#include <stdint.h>

#define IA32_EFER   0xC0000080UL
#define IA32_STAR   0xC0000081UL
#define IA32_LSTAR  0xC0000082UL
#define IA32_SFMASK 0xC0000084UL

static inline void
wrmsr(uint32_t msr, uint64_t val)
{
    __asm__ volatile ("wrmsr"
        : : "c"(msr),
            "a"((uint32_t)(val & 0xFFFFFFFFUL)),
            "d"((uint32_t)(val >> 32))
        : "memory");
}

static inline uint64_t
rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

/* Defined in syscall_entry.asm */
extern void syscall_entry(void);

void
arch_syscall_init(void)
{
    /* Enable SYSCALL/SYSRET: set SCE bit (bit 0) in IA32_EFER */
    wrmsr(IA32_EFER, rdmsr(IA32_EFER) | 1UL);

    /*
     * STAR selector layout:
     *   bits [47:32] = ARCH_KERNEL_CS  → SYSCALL: CS=0x08, SS=0x10
     *   bits [63:48] = ARCH_KERNEL_DS  → SYSRET:  SS=(0x10+8)|3=0x1B, CS=(0x10+16)|3=0x23
     *
     * The user data descriptor (0x18) must be at GDT index 3 and user code (0x20)
     * at GDT index 4 for these selector values to land on the correct descriptors.
     */
    wrmsr(IA32_STAR, ((uint64_t)ARCH_KERNEL_DS << 48) | ((uint64_t)ARCH_KERNEL_CS << 32));

    /* LSTAR: syscall entry point */
    wrmsr(IA32_LSTAR, (uint64_t)(uintptr_t)syscall_entry);

    /*
     * SFMASK: bits cleared in RFLAGS on SYSCALL entry.
     *   bit 9 (IF)  — disable interrupts; syscall dispatch is non-preemptible
     *   bit 8 (TF)  — disable single-step traps
     *   bit 10 (DF) — clear direction flag; required for kernel C string ops
     *   0x700 = bits 10:8
     */
    wrmsr(IA32_SFMASK, 0x700UL);

    printk("[SYSCALL] OK: SYSCALL/SYSRET enabled\n");
}
