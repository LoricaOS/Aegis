/*
 * gic_v2.c — GICv2 backend (GIC-400: Raspberry Pi 5/BCM2712, and QEMU
 * virt with `-machine virt,gic-version=2`).
 *
 * Unlike GICv3 (gic.c), there is no per-CPU redistributor frame: the SGI/PPI
 * range of the distributor (INTID 0-31) is banked by hardware per requesting
 * core at the SAME physical address, and there is one memory-mapped CPU
 * interface (GICC) instead of system-register access — also banked per-core
 * at one shared address. So every core's gicv2_cpu_init() touches the exact
 * same s_gicd/s_gicc pointers; the hardware sorts out which core's banked
 * copy it's operating on.
 */

#include "gic_v2.h"
#include "arch.h"
#include "printk.h"
#include <stdint.h>

/* Distributor: registers below 0x800 are laid out identically to GICv3. */
#define GICD_CTLR        0x0000
#define GICD_IGROUPR     0x0080
#define GICD_ISENABLER   0x0100
#define GICD_IPRIORITYR  0x0400
#define GICD_ITARGETSR   0x0800   /* v2-only: byte-per-interrupt CPU mask */

/* CPU interface (memory-mapped, v2-only). */
#define GICC_CTLR   0x0000
#define GICC_PMR    0x0004
#define GICC_IAR    0x000C
#define GICC_EOIR   0x0010

static volatile uint8_t *s_gicd;
static volatile uint8_t *s_gicc;

static inline uint32_t d32(uint32_t off)              { return *(volatile uint32_t *)(s_gicd + off); }
static inline void     dw32(uint32_t off, uint32_t v) { *(volatile uint32_t *)(s_gicd + off) = v; }
static inline void     cw32(uint32_t off, uint32_t v) { *(volatile uint32_t *)(s_gicc + off) = v; }
static inline uint32_t c32(uint32_t off)              { return *(volatile uint32_t *)(s_gicc + off); }

/* gicv2_cpu_init — per-CPU bring-up. Every core writes the SAME addresses;
 * the SGI/PPI distributor range and the CPU interface are hardware-banked
 * per requesting core, so this needs no per-core frame lookup (unlike v3's
 * gicr_for()). */
void
gicv2_cpu_init(uint32_t cpu)
{
    (void)cpu;

    dw32(GICD_IGROUPR, 0xFFFFFFFFu);         /* SGI/PPI (banked) -> group 1 */
    for (int i = 0; i < 8; i++)
        dw32(GICD_IPRIORITYR + 4 * i, 0xA0A0A0A0u);
    dw32(GICD_ISENABLER, 1u << 27);          /* generic virtual-timer PPI */

    cw32(GICC_PMR, 0xFFu);                   /* accept every priority */
    cw32(GICC_CTLR, (1u << 1) | (1u << 0));  /* EnableGrp1 | EnableGrp0 */
}

void
gicv2_init(uint64_t gicd_phys, uint64_t gicc_phys)
{
    s_gicd = (volatile uint8_t *)arch_dmap(gicd_phys);
    s_gicc = (volatile uint8_t *)arch_dmap(gicc_phys);

    dw32(GICD_CTLR, (1u << 1) | (1u << 0));  /* EnableGrp1 | EnableGrp0 */

    gicv2_cpu_init(0);

    printk("[GIC] OK: GICv2 dist@%lx cpuiface@%lx\n", gicd_phys, gicc_phys);
}

void
gicv2_enable_ppi(uint32_t intid)
{
    dw32(GICD_ISENABLER, 1u << intid);
}

/* gicv2_enable_spi — enable a shared interrupt, targeted at CPU 0 (bit 0 of
 * the byte-per-interrupt ITARGETSR mask — no affinity routing in v2). */
void
gicv2_enable_spi(uint32_t intid)
{
    dw32(GICD_IGROUPR + 4 * (intid / 32),
         d32(GICD_IGROUPR + 4 * (intid / 32)) | (1u << (intid % 32)));
    *(volatile uint8_t *)(s_gicd + GICD_IPRIORITYR + intid) = 0xA0;
    *(volatile uint8_t *)(s_gicd + GICD_ITARGETSR + intid) = 0x01;   /* CPU 0 */
    dw32(GICD_ISENABLER + 4 * (intid / 32), 1u << (intid % 32));
}

/* IAR/EOIR carry a 10-bit INTID in v2 (bits 9:0), vs. v3's 24-bit ICC_IAR1_EL1
 * field — mask accordingly so a spurious-interrupt sentinel (1023) round-trips
 * the same way callers already expect from the v3 path. */
uint32_t
gicv2_ack(void)
{
    return c32(GICC_IAR) & 0x3FFu;
}

void
gicv2_eoi(uint32_t intid)
{
    cw32(GICC_EOIR, intid);
}
