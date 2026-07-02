#ifndef ARM64_ACPI_H
#define ARM64_ACPI_H
/* No ACPI subsystem on arm64 (QEMU virt uses DTB/PSCI); this header only
 * satisfies shared includes whose ACPI calls are all __x86_64__-guarded. */
#endif
