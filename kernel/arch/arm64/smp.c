/*
 * smp.c — ARM64 SMP: per-CPU data + secondary-core bring-up via PSCI CPU_ON.
 *
 * QEMU virt / cortex-a72, PSCI conduit = HVC (same as arch_debug_exit). APs
 * are discovered by probing PSCI CPU_ON for target MPIDRs 1..N-1 (QEMU virt
 * uses Aff0 = CPU index for a flat topology); a PSCI error means "no such
 * core" and stops the probe. Each AP boots through ap_boot.S (physical
 * trampoline) into ap_c_entry, brings up its own GIC CPU interface + timer,
 * and joins the shared scheduler exactly like the x86 ap_entry path.
 */
#include "smp.h"
#include "arch.h"
#include "sched.h"
#include "printk.h"
#include "kva.h"
#include "vmm.h"
#include "arch_vmm.h"
#include "lockrank.h"
#include "fdt.h"
#include <stdint.h>

percpu_t          g_percpu[MAX_CPUS];
uint32_t          g_cpu_count = 1;
volatile uint8_t  g_ap_online[MAX_CPUS];
int               g_ap_sched_enabled = 1;   /* APs run the scheduler */
int               g_hwwatch = 0;            /* no arm64 DR watchpoints */
void hwwatch_arm_local(void) {}

void gic_cpu_init(uint32_t cpu);
void timer_ap_init(void);

extern char ap_trampoline[];   /* ap_boot.S */

/* Kept in sync with the offsets ap_boot.S reads. */
struct ap_params {
    uint64_t ttbr0, ttbr1, tcr, mair, sctlr, vbar, sp_top, c_entry, cpu_index;
};
static struct ap_params s_ap_params[MAX_CPUS];

/* Identity map of the kernel image's 1GB region for the MMU-enable window. */
static uint64_t s_idmap_l0[512] __attribute__((aligned(4096)));
static uint64_t s_idmap_l1[512] __attribute__((aligned(4096)));

/* Kernel-image VA → PA (image is contiguous with a single slide). */
static inline uint64_t img_phys(const void *va)
{
    return (uint64_t)(uintptr_t)va - ARCH_KERNEL_VIRT_BASE + arch_kern_phys_slide();
}

/* Clean a data range to the point of coherency so an AP reading it with the
 * MMU (and caches) off sees the BSP's writes. */
static void
clean_dcache(const void *addr, uint64_t len)
{
    uint64_t p = (uint64_t)(uintptr_t)addr & ~63UL;
    uint64_t end = (uint64_t)(uintptr_t)addr + len;
    for (; p < end; p += 64)
        __asm__ volatile("dc cvac, %0" : : "r"(p) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}

/* PSCI conduit: 1 = SMC, 0 = HVC. Chosen once in smp_start_aps from the DTB
 * /psci "method" (QEMU virt = hvc, Pi 5 / TF-A = smc); defaults to HVC when
 * there is no DTB, which is the working QEMU behaviour. */
static int s_psci_use_smc;

/* One PSCI SMCCC call over the selected conduit. HVC and SMC are distinct
 * instructions (not a runtime-conduit register), so the branch is here. */
static long
psci_call(uint64_t func, uint64_t a1, uint64_t a2, uint64_t a3)
{
    register uint64_t x0 __asm__("x0") = func;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;
    register uint64_t x3 __asm__("x3") = a3;
    if (s_psci_use_smc)
        __asm__ volatile("smc #0" : "+r"(x0)
                         : "r"(x1), "r"(x2), "r"(x3) : "memory");
    else
        __asm__ volatile("hvc #0" : "+r"(x0)
                         : "r"(x1), "r"(x2), "r"(x3) : "memory");
    return (long)x0;
}

/* PSCI CPU_ON (64-bit). Returns 0 (SUCCESS) or a negative error. */
static long
psci_cpu_on(uint64_t target_mpidr, uint64_t entry_phys, uint64_t ctx)
{
    return psci_call(0xC4000003UL /* PSCI_CPU_ON_AARCH64 */,
                     target_mpidr, entry_phys, ctx);
}

void
smp_percpu_init_bsp(void)
{
    g_percpu[0].self         = &g_percpu[0];
    g_percpu[0].cpu_id       = 0;
    g_percpu[0].current_task = 0;
    __asm__ volatile("msr tpidr_el1, %0" : : "r"(&g_percpu[0]));
    printk("[SMP] OK: per-CPU data initialized\n");
}

/* ap_c_entry — higher-half C entry for a secondary core (from ap_boot.S).
 * Mirrors the x86 ap_entry scheduler handoff. */
void
ap_c_entry(uint64_t cpu)
{
    /* FP/SIMD (ctx_switch uses V registers). */
    __asm__ volatile("msr cpacr_el1, %0\n\tisb" : : "r"(3UL << 20));

    g_percpu[cpu].self   = &g_percpu[cpu];
    g_percpu[cpu].cpu_id = (uint8_t)cpu;
    __asm__ volatile("msr tpidr_el1, %0" : : "r"(&g_percpu[cpu]));

    /* Drop the identity map: run on the empty master user table in TTBR0. */
    arch_vmm_load_pml4(vmm_get_master_pml4());

    gic_cpu_init((uint32_t)cpu);   /* this core's redistributor + CPU iface */
    timer_ap_init();               /* arm this core's virtual timer         */

    g_ap_online[cpu] = 1;

    /* Wait for the BSP to spawn every idle task and start the scheduler. */
    while (!sched_is_ready())
        arch_pause();

    aegis_task_t *idle = (aegis_task_t *)g_percpu[cpu].idle_task;
    if (!idle)
        for (;;) arch_wait_for_irq();

    idle->on_cpu = (int)cpu;
    percpu_set_current(idle);
    arch_set_kernel_stack(idle->kernel_stack_top);

    /* Outgoing-only throwaway TCB (like sched_start / x86 ap_entry): written by
     * ctx_switch, never read (the __builtin_unreachable below — we never switch
     * back to it).  A single SHARED static suffices, not one slot per CPU:
     * concurrent APs saving discarded state into it during this one-shot entry
     * is benign (garbage no one consumes).  Was aegis_task_t[MAX_CPUS] = ~1.25 MB
     * of BSS for write-only scratch. */
    static aegis_task_t s_ap_dummy;
    ctx_switch(&s_ap_dummy, idle);
    __builtin_unreachable();
}

void
smp_start_aps(void)
{
    g_ap_online[0] = 1;

    /* Build the kernel-image identity map (one 1GB block, executable). */
    uint64_t img = ARCH_KERNEL_PHYS_BASE + arch_kern_phys_slide();
    uint64_t base1g = img & ~0x3FFFFFFFUL;
    uint64_t l0i = (base1g >> 39) & 0x1FF;
    uint64_t l1i = (base1g >> 30) & 0x1FF;
    /* valid block | AF | inner-shareable | AttrIdx0 (Normal WB); PXN/UXN
     * clear so the trampoline is executable at EL1. */
    s_idmap_l1[l1i] = base1g | (1UL << 0) | (1UL << 10) | (3UL << 8);
    s_idmap_l0[l0i] = img_phys(s_idmap_l1) | 3UL;   /* table descriptor */
    uint64_t idmap_phys = img_phys(s_idmap_l0);

    /* Capture the BSP's live translation config so APs match exactly. */
    uint64_t tcr, mair, sctlr, ttbr1;
    __asm__ volatile("mrs %0, tcr_el1"   : "=r"(tcr));
    __asm__ volatile("mrs %0, mair_el1"  : "=r"(mair));
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    extern char exception_vectors[];

    clean_dcache(s_idmap_l0, sizeof(s_idmap_l0));
    clean_dcache(s_idmap_l1, sizeof(s_idmap_l1));

    /* Pick the PSCI conduit from the DTB (QEMU virt = HVC, Pi 5 = SMC).
     * Default HVC when the DTB has no /psci node — the working QEMU path. */
    s_psci_use_smc = (fdt_psci_conduit() == 1);
    printk("[SMP] PSCI conduit: %s\n", s_psci_use_smc ? "SMC" : "HVC");

    uint32_t online = 1;
    for (uint32_t cpu = 1; cpu < MAX_CPUS; cpu++) {
        /* Target MPIDR for CPU_ON. The DTB's /cpus/cpu@N reg is the real
         * affinity — flat 0..3 on QEMU, core-index-in-Aff1 (0x100,0x200,…)
         * on the Pi 5 — so read it rather than assume a topology. No such
         * node means we have enumerated every core; stop. Falls back to a
         * flat index when there is no DTB at all. */
        uint64_t target = cpu;
        if (fdt_available() && !fdt_cpu_mpidr((int)cpu, &target))
            break;

        /* Per-CPU kernel boot stack (higher-half). */
        void *stk = kva_alloc_pages(4);
        if (!stk)
            break;

        g_percpu[cpu].self   = &g_percpu[cpu];
        g_percpu[cpu].cpu_id = (uint8_t)cpu;

        s_ap_params[cpu].ttbr0     = idmap_phys;
        s_ap_params[cpu].ttbr1     = ttbr1;
        s_ap_params[cpu].tcr       = tcr;
        s_ap_params[cpu].mair      = mair;
        s_ap_params[cpu].sctlr     = sctlr;
        s_ap_params[cpu].vbar      = (uint64_t)(uintptr_t)exception_vectors;
        s_ap_params[cpu].sp_top    = (uint64_t)(uintptr_t)stk + 4 * 4096;
        s_ap_params[cpu].c_entry   = (uint64_t)(uintptr_t)ap_c_entry;
        s_ap_params[cpu].cpu_index = cpu;
        clean_dcache(&s_ap_params[cpu], sizeof(s_ap_params[cpu]));

        long r = psci_cpu_on(target,
                             img_phys(ap_trampoline),
                             img_phys(&s_ap_params[cpu]));
        if (r != 0) {
            /* Any failure ends the probe. On a flat MPIDR topology (QEMU
             * virt and Pi 5, cpu index == Aff0) the first failure means no
             * higher core exists. PSCI_INVALID_PARAMETERS (-2) is the clean
             * "no such core". On the native Pi 5 path PSCI lives at EL3 and
             * needs the SMC conduit, but this driver issues HVC (correct for
             * QEMU); since we dropped past EL2, HVC is unhandled and returns
             * the CPU_ON function id unchanged (0xc4000003) rather than a
             * PSCI error. Without breaking here that "failure" repeats for
             * ~1024 candidate cores, flooding the log and blowing the boot's
             * time budget (the watchdog fired before init). Break on the
             * first failure either way; real multi-core Pi 5 SMP is a
             * follow-up (switch the conduit to SMC on this path). */
            if (r != -2)
                printk("[SMP] WARN: CPU_ON cpu%u failed (%ld) — stopping probe "
                       "(1 core; SMC conduit needed for native Pi5 SMP)\n", cpu, r);
            break;
        }

        /* Wait for the AP to signal online (~200ms budget). */
        volatile uint32_t spin = 0;
        while (!g_ap_online[cpu] && spin < 20000000u) {
            arch_pause();
            spin++;
        }
        if (g_ap_online[cpu]) {
            online++;
        } else {
            /* Also stop here (not just on a CPU_ON error): if the first AP
             * never signals online, none will on this conduit, and the
             * ~200ms-per-core wait × ~1024 candidates otherwise blows the
             * boot time budget (watchdog before init). */
            printk("[SMP] WARN: cpu%u did not come online — stopping probe\n", cpu);
            break;
        }
    }

    g_cpu_count = online;
    printk("[SMP] OK: %u CPU%s online\n", online, online == 1 ? "" : "s");
}
