/*
 * pi5_thermal.c — BCM2712 SoC temperature via the AVS monitor.
 *
 * DTB: avs-monitor@7d542000 (compatible "brcm,bcm2711-avs-monitor"), child
 * 0x7d542000 under soc@107c000000 → CPU-phys 0x10_7d542000, inside the step-2b
 * device block (reachable via arch_dmap, no extra mapping). The bcm2711-thermal
 * block reads AVS_RO_TEMP_STATUS at offset 0x200; millicelsius is a linear
 * transform of the 10-bit reading using the DTB thermal-zone coefficients
 * (slope -550, offset 450000): milliC = 450000 - 550*raw. A read-only MMIO
 * load, safe to call any time after vmm_init.
 */

#include "arch.h"
#include "printk.h"
#include <stdint.h>

#define AVS_MON_PHYS       0x107d542000UL
#define AVS_RO_TEMP_STATUS 0x200
#define AVS_TEMP_VALID     (1u << 10)
#define AVS_TEMP_DATA_MSK  0x3ffu
#define AVS_SLOPE          (-550)     /* DTB coefficients[0] = 0xfffffdda */
#define AVS_OFFSET         450000     /* DTB coefficients[1] = 0x6ddd0    */

/* pi5_temp_millicelsius — SoC temperature in milli-°C, or INT32_MIN if the
 * sensor reading is not valid yet. */
int32_t
pi5_temp_millicelsius(void)
{
    volatile uint32_t *avs = (volatile uint32_t *)arch_dmap(AVS_MON_PHYS);
    uint32_t v = avs[AVS_RO_TEMP_STATUS / 4];
    if (!(v & AVS_TEMP_VALID))
        return INT32_MIN;
    int32_t raw = (int32_t)(v & AVS_TEMP_DATA_MSK);
    return AVS_OFFSET + AVS_SLOPE * raw;
}

/* pi5_thermal_report — log the current SoC temperature (whole + tenths °C). */
void
pi5_thermal_report(void)
{
    int32_t m = pi5_temp_millicelsius();
    if (m == INT32_MIN) {
        printk("[TEMP] SoC sensor not ready\n");
        return;
    }
    printk("[TEMP] SoC %d.%d C\n", m / 1000, (m % 1000) / 100);
}
