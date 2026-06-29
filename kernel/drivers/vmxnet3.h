/* vmxnet3.h — VMware vmxnet3 paravirtual NIC */
#ifndef VMXNET3_H
#define VMXNET3_H

/* Scan PCI for a vmxnet3 (15AD:07B0), activate it, register as "eth0".
 * Silent if none found. Called from kernel_main after the other NIC probes. */
void vmxnet3_init(void);

#endif /* VMXNET3_H */
