/* gic_v2.h — GICv2 backend, dispatched to from gic.c when the DTB reports
 * "arm,gic-400" instead of "arm,gic-v3". See gic_v2.c for the why. */
#ifndef AEGIS_ARM64_GIC_V2_H
#define AEGIS_ARM64_GIC_V2_H

#include <stdint.h>

void     gicv2_init(uint64_t gicd_phys, uint64_t gicc_phys);
void     gicv2_cpu_init(uint32_t cpu);
void     gicv2_enable_ppi(uint32_t intid);
void     gicv2_enable_spi(uint32_t intid);
uint32_t gicv2_ack(void);
void     gicv2_eoi(uint32_t intid);

#endif /* AEGIS_ARM64_GIC_V2_H */
