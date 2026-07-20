/*
 * fdt.h — minimal read-only flattened-device-tree reader (arm64).
 *
 * The Limine (QEMU virt) and Apple Virtualization.framework platforms put
 * their GIC / PCIe-ECAM / UART at DIFFERENT physical bases. Both hand the
 * guest a DTB; this reader resolves those bases at runtime so the drivers
 * stop hardcoding QEMU-virt constants. Call fdt_init() once, early, while
 * the bootloader HHDM is still live (before vmm_init).
 */
#ifndef AEGIS_ARM64_FDT_H
#define AEGIS_ARM64_FDT_H

#include <stdint.h>

/* Copy the DTB (bootinfo dtb_phys, via the still-live HHDM) into a static
 * buffer and validate its header. Safe to call with no DTB — then every
 * query below returns 0 and callers fall back to their builtin defaults. */
void fdt_init(void);

/* 1 if a valid DTB was captured. */
int fdt_available(void);

/* Find the first node whose "compatible" list contains `compat` and read
 * the `index`-th <address,size> pair of its "reg" property (decoded with
 * the parent's #address-cells/#size-cells). Returns 1 on success. */
int fdt_reg_by_compat(const char *compat, int index,
                      uint64_t *addr_out, uint64_t *size_out);

/* 1 if any node advertises `compat` in its "compatible" list. */
int fdt_compat_exists(const char *compat);

/* Like fdt_reg_by_compat, but for compat strings shared by more than one
 * node (e.g. BCM2712's three "brcm,bcm2712-pcie" root complexes at
 * different reg bases) -- node_index selects which MATCHING NODE (0 = the
 * first node in the tree with this compatible string, 1 = the second,
 * ...), and reads that node's reg[0]. Ignores "status" -- callers that
 * care which node is enabled must already know which node_index they
 * want (this session's rpi5-pcie-driver-research memory: pcie1 is
 * node_index 1, the board's NVMe M.2 slot). */
int fdt_reg_by_compat_nth(const char *compat, int node_index,
                          uint64_t *addr_out, uint64_t *size_out);

/* Collect every <addr,size> reg pair from every node whose "device_type"
 * is "memory" (the standard Devicetree convention for RAM -- these nodes
 * normally have no "compatible" property at all, so fdt_reg_by_compat
 * can't see them). A single node's "reg" property may itself carry
 * multiple pairs (real hardware can be a small handful of nodes each with
 * several ranges, or one node with many -- both are handled). Writes up
 * to `max` pairs into addr_out/size_out; returns the number written. */
int fdt_memory_regions(uint64_t *addr_out, uint64_t *size_out, int max);

/* Read the firmware-provided initramfs range from /chosen
 * (linux,initrd-start/end). Returns 1 with [*start,*end) on success. */
int fdt_initrd(uint64_t *start_out, uint64_t *end_out);

/* PSCI conduit from /psci "method": 1 = SMC (Pi 5 / TF-A), 0 = HVC (QEMU
 * virt), -1 = no /psci node. Lets the SMP bring-up pick the right one at
 * runtime instead of hardcoding per platform. */
int fdt_psci_conduit(void);

/* MPIDR affinity of the index-th /cpus/cpu@* node, for the PSCI CPU_ON
 * target. Returns 1 + *mpidr_out, or 0 when index >= core count. Handles
 * both QEMU virt (flat 0..3) and the Pi 5 (core index in Affinity 1). */
int fdt_cpu_mpidr(int index, uint64_t *mpidr_out);

#endif /* AEGIS_ARM64_FDT_H */
