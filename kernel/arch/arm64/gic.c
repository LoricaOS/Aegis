/*
 * gic.c — GIC dispatcher + GICv3 backend.
 *
 * GICv3 (QEMU virt default, and `-machine virt,gic-version=3`): distributor
 * @ 0x08000000, redistributor frames @ 0x080A0000, system-register CPU
 * interface. BSP-bring-up path only; APs call gic_cpu_init() themselves.
 *
 * GICv2 (GIC-400: Raspberry Pi 5/BCM2712, and
 * `-machine virt,gic-version=2`) lives in gic_v2.c — genuinely different
 * hardware (memory-mapped CPU interface, no redistributors, 10-bit INTID in
 * IAR/EOIR vs. v3's 24-bit field), not a register-offset variant of this
 * file. gic_init() reads the DTB's interrupt-controller "compatible" string
 * once and every public entry point below dispatches on that.
 */

#include "arch.h"
#include "printk.h"
#include "fdt.h"
#include "gic_v2.h"
#include <stdint.h>

static int s_is_v2;

/* QEMU-virt defaults; overridden from the DTB's arm,gic-v3 node at init
 * (Apple Virtualization.framework puts these at 0x1000_0000/0x1001_0000). */
#define GICD_PHYS   0x08000000UL
#define GICR_PHYS   0x080A0000UL

static uint64_t s_gicd_phys = GICD_PHYS;
static uint64_t s_gicr_phys = GICR_PHYS;

#define GICD_CTLR        0x0000
#define GICD_IGROUPR     0x0080
#define GICD_ISENABLER   0x0100
#define GICD_IPRIORITYR  0x0400
#define GICD_IROUTER     0x6000

#define GICR_CTLR        0x0000
#define GICR_WAKER       0x0014
/* SGI/PPI frame = redistributor base + 64K */
#define GICR_SGI_OFF     0x10000
#define GICR_IGROUPR0    0x0080
#define GICR_ISENABLER0  0x0100
#define GICR_IPRIORITYR  0x0400

static volatile uint8_t *s_gicd;
static volatile uint8_t *s_gicr;

static inline uint32_t d32(uint32_t off)             { return *(volatile uint32_t *)(s_gicd + off); }
static inline void     dw32(uint32_t off, uint32_t v){ *(volatile uint32_t *)(s_gicd + off) = v; }
static inline void     dw64(uint32_t off, uint64_t v){ *(volatile uint64_t *)(s_gicd + off) = v; }

/* Redistributor frame for a given CPU. QEMU virt lays the GICv3
 * redistributors out as consecutive 128 KiB (0x20000) frames in CPU-index
 * order starting at GICR_PHYS, so core N's frame is GICR_PHYS + N*0x20000. */
#define GICR_STRIDE 0x20000UL
static volatile uint8_t *
gicr_for(uint32_t cpu)
{
    return (volatile uint8_t *)arch_dmap(s_gicr_phys + (uint64_t)cpu * GICR_STRIDE);
}

/* gic_cpu_init — per-CPU bring-up: dispatches to gicv2_cpu_init() on GIC-400,
 * else the GICv3 path below (wake THIS core's redistributor, make its
 * SGIs/PPIs group-1 at a permissive priority, enable the virtual timer PPI
 * (27), and enable the system-register CPU interface). Called on the BSP by
 * gic_init and on each AP by its ap_c_entry (with its own index). */
void
gic_cpu_init(uint32_t cpu)
{
    if (s_is_v2) {
        gicv2_cpu_init(cpu);
        return;
    }

    volatile uint8_t *rd = gicr_for(cpu);

    *(volatile uint32_t *)(rd + GICR_WAKER) &= ~(1u << 1);   /* ProcessorSleep=0 */
    while (*(volatile uint32_t *)(rd + GICR_WAKER) & (1u << 2))
        ;                                                    /* ChildrenAsleep=0 */

    *(volatile uint32_t *)(rd + GICR_SGI_OFF + GICR_IGROUPR0) = 0xFFFFFFFFu;
    for (int i = 0; i < 8; i++)
        *(volatile uint32_t *)(rd + GICR_SGI_OFF + GICR_IPRIORITYR + 4 * i) = 0xA0A0A0A0u;
    /* Enable the generic virtual-timer PPI (INTID 27) on this core. */
    *(volatile uint32_t *)(rd + GICR_SGI_OFF + GICR_ISENABLER0) = 1u << 27;

    uint64_t sre;
    __asm__ volatile("mrs %0, S3_0_C12_C12_5" : "=r"(sre));       /* ICC_SRE_EL1 */
    __asm__ volatile("msr S3_0_C12_C12_5, %0" : : "r"(sre | 1));
    __asm__ volatile("isb");
    __asm__ volatile("msr S3_0_C4_C6_0, %0" : : "r"(0xF8UL));     /* ICC_PMR_EL1 */
    __asm__ volatile("msr S3_0_C12_C12_7, %0" : : "r"(1UL));      /* ICC_IGRPEN1_EL1 */
    __asm__ volatile("isb");
}

void
gic_init(void)
{
    /* Real GIC-400 silicon (Raspberry Pi 5/BCM2712) reports itself as
     * "arm,gic-400" in its DTB (confirmed via a live dump off real Pi 5
     * hardware). QEMU's `virt,gic-version=2` machine is a DIFFERENT GICv2
     * implementation string, "arm,cortex-a15-gic" (confirmed via
     * `-machine dumpdtb` + dtc) — same v2 register model this driver
     * already implements (memory-mapped CPU interface, no redistributors),
     * just a different compatible string. Checking only "arm,gic-400"
     * meant QEMU's v2 machine fell through to the GICv3 branch below and
     * tried to bring up a redistributor that doesn't exist on this
     * hardware — an external abort at the very first GICR_WAKER access,
     * discovered testing this driver against QEMU before ever touching
     * real Pi 5 silicon. */
    const char *v2_compat = 0;
    if (fdt_compat_exists("arm,gic-400"))
        v2_compat = "arm,gic-400";
    else if (fdt_compat_exists("arm,cortex-a15-gic"))
        v2_compat = "arm,cortex-a15-gic";

    if (v2_compat) {
        s_is_v2 = 1;
        uint64_t gicd, gicc, sz;
        int from_dtb = fdt_reg_by_compat(v2_compat, 0, &gicd, &sz) &&
                       fdt_reg_by_compat(v2_compat, 1, &gicc, &sz);
        if (!from_dtb) {
            /* QEMU virt,gic-version=2 fallback (matches the GICv3 pattern
             * below: builtin constants if a DTB somehow lacks reg data). */
            gicd = 0x08000000UL;
            gicc = 0x08010000UL;
        }
        gicv2_init(gicd, gicc);
        return;
    }

    /* Prefer the DTB's arm,gic-v3 node (reg[0]=distributor, reg[1]=first
     * redistributor frame); fall back to the QEMU-virt constants. */
    uint64_t d, r, sz;
    int from_dtb = fdt_reg_by_compat("arm,gic-v3", 0, &d, &sz) &&
                   fdt_reg_by_compat("arm,gic-v3", 1, &r, &sz);
    if (from_dtb) {
        s_gicd_phys = d;
        s_gicr_phys = r;
    }

    s_gicd = (volatile uint8_t *)arch_dmap(s_gicd_phys);
    s_gicr = (volatile uint8_t *)arch_dmap(s_gicr_phys);

    /* Distributor: affinity routing + group-1 forwarding (once, BSP). */
    dw32(GICD_CTLR, (1u << 4) | (1u << 1) | (1u << 0));

    gic_cpu_init(0);   /* BSP's own redistributor + CPU interface */

    printk("[GIC] OK: GICv3 dist@%lx redist@%lx (%s)\n",
           s_gicd_phys, s_gicr_phys, from_dtb ? "DTB" : "builtin");
}

/* gic_enable_ppi — enable a private interrupt (INTID < 32) on this CPU. */
void
gic_enable_ppi(uint32_t intid)
{
    if (s_is_v2) {
        gicv2_enable_ppi(intid);
        return;
    }
    *(volatile uint32_t *)(s_gicr + GICR_SGI_OFF + GICR_ISENABLER0) = 1u << intid;
}

/* gic_enable_spi — enable a shared interrupt, routed to CPU 0. */
void
gic_enable_spi(uint32_t intid)
{
    if (s_is_v2) {
        gicv2_enable_spi(intid);
        return;
    }
    dw32(GICD_IGROUPR + 4 * (intid / 32),
         d32(GICD_IGROUPR + 4 * (intid / 32)) | (1u << (intid % 32)));
    *(volatile uint8_t *)(s_gicd + GICD_IPRIORITYR + intid) = 0xA0;
    dw64(GICD_IROUTER + 8 * intid, 0);            /* affinity 0.0.0.0 */
    dw32(GICD_ISENABLER + 4 * (intid / 32), 1u << (intid % 32));
}

uint32_t
gic_ack(void)
{
    if (s_is_v2)
        return gicv2_ack();

    uint64_t iar;
    __asm__ volatile("mrs %0, S3_0_C12_C12_0" : "=r"(iar));       /* ICC_IAR1_EL1 */
    return (uint32_t)iar & 0xFFFFFFu;
}

void
gic_eoi(uint32_t intid)
{
    if (s_is_v2) {
        gicv2_eoi(intid);
        return;
    }
    __asm__ volatile("msr S3_0_C12_C12_1, %0" : : "r"((uint64_t)intid)); /* ICC_EOIR1_EL1 */
    __asm__ volatile("isb");
}
