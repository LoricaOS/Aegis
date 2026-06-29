/* pvpanic.h — QEMU pvpanic guest→host panic notification */
#ifndef PVPANIC_H
#define PVPANIC_H

/* Probe for a pvpanic-pci device (1b36:0011) and map it. Silent if absent. */
void pvpanic_init(void);

/* Tell the host the guest panicked. Safe from the panic path; no-op if absent. */
void pvpanic_signal_panic(void);

#endif /* PVPANIC_H */
