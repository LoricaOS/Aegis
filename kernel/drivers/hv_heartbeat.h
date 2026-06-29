/* hv_heartbeat.h — Hyper-V Heartbeat IC: makes the guest report "healthy" to
 * the host (Get-VMIntegrationService / Hyper-V Manager). No-op off Hyper-V. */
#ifndef HV_HEARTBEAT_H
#define HV_HEARTBEAT_H

void hv_heartbeat_init(void);
void hv_heartbeat_poll(void);

#endif /* HV_HEARTBEAT_H */
