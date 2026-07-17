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

/* Collect every <addr,size> reg pair from every node whose "device_type"
 * is "memory" (the standard Devicetree convention for RAM -- these nodes
 * normally have no "compatible" property at all, so fdt_reg_by_compat
 * can't see them). A single node's "reg" property may itself carry
 * multiple pairs (real hardware can be a small handful of nodes each with
 * several ranges, or one node with many -- both are handled). Writes up
 * to `max` pairs into addr_out/size_out; returns the number written. */
int fdt_memory_regions(uint64_t *addr_out, uint64_t *size_out, int max);

#endif /* AEGIS_ARM64_FDT_H */
