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

/* rp1_fan_set — native/rp1.c: fan speed, per-mille (0 = off .. 1000 = full). */
void rp1_fan_set(uint32_t permille);

/* pi5_fan_governor — temperature→fan-speed curve, run ~once/second from the
 * arm64 timer tick. Curve (SoC temp):
 *   < 45 C   fan off
 *   45–70 C  linear 35% → 100%
 *   >= 70 C  100% (maxed out here, well below the ~80 C soft-throttle so the
 *            fan is already flat-out before the SoC would start slowing down)
 * The 35% floor when running is enough to spin the fan up reliably (lower duty
 * can stall it). Hysteresis: once running, keep going until below 40 C so it
 * doesn't chatter on/off around the 45 C turn-on threshold. */
static int s_fan_running = 0;

void
pi5_fan_governor(void)
{
    int32_t t = pi5_temp_millicelsius();
    if (t == INT32_MIN)
        return;                     /* sensor not ready — leave fan as boot set it */

    const int32_t  ON_MC = 45000, OFF_MC = 40000, FULL_MC = 70000;
    const uint32_t FLOOR_PM = 350;

    if (s_fan_running) {
        if (t < OFF_MC) s_fan_running = 0;
    } else if (t >= ON_MC) {
        s_fan_running = 1;
    }

    uint32_t pm;
    if (!s_fan_running)
        pm = 0;
    else if (t >= FULL_MC)
        pm = 1000;
    else {
        int32_t d = t - ON_MC;      /* 0 .. (FULL_MC-ON_MC) */
        if (d < 0) d = 0;
        pm = FLOOR_PM + (uint32_t)(((uint64_t)(1000u - FLOOR_PM) * (uint32_t)d)
                                   / (uint32_t)(FULL_MC - ON_MC));
    }
    rp1_fan_set(pm);

    /* Log only when the duty crosses a 10% bucket, so steady state is quiet but
     * transitions (and the off/full endpoints) still show on the console. */
    static uint32_t s_last_bucket = 0xffffffff;
    uint32_t bucket = pm / 100;
    if (bucket != s_last_bucket) {
        s_last_bucket = bucket;
        printk("[FAN] SoC %d.%d C -> duty %u%%\n", t / 1000, (t % 1000) / 100, pm / 10);
    }
}
