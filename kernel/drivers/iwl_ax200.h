#ifndef IWL_AX200_H
#define IWL_AX200_H

/* iwl_ax200 — Intel Wi-Fi 6 AX200 (8086:2723) driver.
 * Phase 1: PCI bring-up + first register read. Called from kernel_main's
 * device-probe sequence; silent no-op when no AX200 is present. */
void iwl_ax200_init(void);

#endif /* IWL_AX200_H */
