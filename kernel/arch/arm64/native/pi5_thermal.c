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

/* pi5_fan_governor — temperature→fan-speed governor, run ~once/second from the
 * arm64 timer tick. DISCRETE STEPS (not a continuous ramp): the fan holds a
 * speed and only changes at real thresholds. A continuous duty made the fan
 * "hunt" — audibly waver — as the temperature micro-oscillated; stepping mirrors
 * how the Pi firmware's cooling states work. Each step has FAN_HYST_MC
 * hysteresis: rise to a step at its threshold, fall out of it only once the temp
 * has dropped a full FAN_HYST_MC below. Maxes at 70 C — well below the ~80 C
 * soft-throttle, so the fan is already flat-out before the SoC would slow. */
static const struct { int32_t up_mC; uint16_t duty_pm; } s_fan_steps[] = {
    {     0,    0 },   /* off              */
    { 45000,  400 },   /* 40%              */
    { 52000,  550 },   /* 55%              */
    { 58000,  700 },   /* 70%              */
    { 64000,  850 },   /* 85%              */
    { 70000, 1000 },   /* 100% (curve max) */
};
#define FAN_NSTEPS  ((int)(sizeof s_fan_steps / sizeof s_fan_steps[0]))
#define FAN_HYST_MC 3000            /* 3 C hysteresis on step-down */

static int s_fan_step = 0;

void
pi5_fan_governor(void)
{
    int32_t t = pi5_temp_millicelsius();
    if (t == INT32_MIN)
        return;                     /* sensor not ready — leave fan as boot set it */

    /* Rise while the next step's threshold is reached; fall while we're a full
     * FAN_HYST_MC below the current step's threshold. */
    while (s_fan_step < FAN_NSTEPS - 1 && t >= s_fan_steps[s_fan_step + 1].up_mC)
        s_fan_step++;
    while (s_fan_step > 0 && t < s_fan_steps[s_fan_step].up_mC - FAN_HYST_MC)
        s_fan_step--;

    uint32_t pm = s_fan_steps[s_fan_step].duty_pm;
    rp1_fan_set(pm);

    /* Log only when the step changes, so steady state stays silent. */
    static int s_last_step = -1;
    if (s_fan_step != s_last_step) {
        s_last_step = s_fan_step;
        printk("[FAN] SoC %d.%d C -> step %d duty %u%%\n",
               t / 1000, (t % 1000) / 100, s_fan_step, pm / 10);
    }
}
