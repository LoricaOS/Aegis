/* hv_kvp.h — Hyper-V KVP / Data Exchange IC: serves guest OS info to the host
 * (shown in Hyper-V Manager / Get-VMIntegrationService). No-op off Hyper-V. */
#ifndef HV_KVP_H
#define HV_KVP_H

void hv_kvp_init(void);
void hv_kvp_poll(void);

#endif /* HV_KVP_H */
