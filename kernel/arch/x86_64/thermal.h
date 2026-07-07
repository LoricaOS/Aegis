#ifndef AEGIS_THERMAL_H
#define AEGIS_THERMAL_H

/* Current CPU die temperature in °C, or -1 if unavailable (non-AMD CPU, or no
 * Data Fabric present — e.g. under a VM). When non-NULL, *tjmax_out receives
 * the nominal throttle ceiling in °C. AMD Zen/Zen2/Zen3 via a k10temp-style
 * SMN read; Intel DTS is a separate TODO. */
int cpu_temp_read(int *tjmax_out);

#endif /* AEGIS_THERMAL_H */
