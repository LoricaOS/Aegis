/* hv_shutdown.h — Hyper-V Shutdown IC: host-initiated graceful shutdown/restart
 * (Stop-VM / Restart-VM) → signal vigil for a clean teardown. No-op off Hyper-V. */
#ifndef HV_SHUTDOWN_H
#define HV_SHUTDOWN_H

void hv_shutdown_init(void);
void hv_shutdown_poll(void);

#endif /* HV_SHUTDOWN_H */
