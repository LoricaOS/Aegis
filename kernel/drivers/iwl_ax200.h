#ifndef IWL_AX200_H
#define IWL_AX200_H

/* iwl_ax200 — Intel Wi-Fi 6 AX200 (8086:2723) driver.
 * Phase 1: PCI bring-up + first register read. Called from kernel_main's
 * device-probe sequence; silent no-op when no AX200 is present. */
void iwl_ax200_init(void);

/* ── WiFi control surface (used by sys_netcfg, driven by the network manager) ── */
#include <stdint.h>

/* ABI struct copied out to userspace by sys_netcfg WiFi ops. Keep in sync with
 * the mirror in lumen-netman. */
typedef struct {
    char    ssid[33];
    uint8_t channel;
    uint8_t sec;         /* 0 = open, 1 = secured (Privacy/RSN) */
    uint8_t connected;   /* 1 = this is the currently-associated network */
    uint8_t pad;
} wifi_net_pub_t;

int iwl_wifi_present(void);                            /* 1 if an AX200 was found */
int iwl_wifi_list(wifi_net_pub_t *out, int max);      /* returns #networks copied */
int iwl_wifi_connect(const char *ssid);               /* 0 = associated, <0 = error */
int iwl_wifi_rescan(void);                             /* re-run the scan (blocking) */

#endif /* IWL_AX200_H */
