/*
 * fdt_test.c — host unit check for the arm64 FDT reader.
 *
 * The Limine+edk2 boot path presents ACPI, not a device tree, so the
 * parser can't be exercised through a QEMU boot (it falls back to builtin
 * constants). This feeds it a REAL device tree — QEMU's own `virt` DTB —
 * and asserts it extracts the GIC / ECAM bases the drivers rely on.
 *
 * Build + run: tools/test-fdt.sh  (dumps the DTB, compiles, runs).
 */
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

extern uint32_t fdt_ingest(const uint8_t *src, uint32_t avail);
extern int fdt_reg_by_compat(const char *compat, int index,
                             uint64_t *addr, uint64_t *size);
extern int fdt_compat_exists(const char *compat);
extern int fdt_available(void);

int
main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <virt.dtb>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    static uint8_t buf[256 * 1024];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);

    uint32_t cap = fdt_ingest(buf, (uint32_t)n);
    assert(cap > 0 && fdt_available());
    printf("captured %u bytes\n", cap);

    uint64_t a, s;

    /* GICv3: reg[0] = distributor, reg[1] = redistributor. QEMU virt puts
     * them at the constants gic.c falls back to. */
    assert(fdt_reg_by_compat("arm,gic-v3", 0, &a, &s));
    printf("gic dist   = 0x%llx (size 0x%llx)\n",
           (unsigned long long)a, (unsigned long long)s);
    assert(a == 0x8000000ULL);
    assert(fdt_reg_by_compat("arm,gic-v3", 1, &a, &s));
    printf("gic redist = 0x%llx\n", (unsigned long long)a);
    assert(a == 0x80a0000ULL);

    /* PCIe ECAM base — 64-bit address (2 address-cells), exercises the
     * multi-cell combine that the single-cell case wouldn't. */
    assert(fdt_reg_by_compat("pci-host-ecam-generic", 0, &a, &s));
    printf("ecam       = 0x%llx\n", (unsigned long long)a);
    assert(a == 0x4010000000ULL);

    /* Existence queries + PL011 presence (absent under Apple VZ). */
    assert(fdt_compat_exists("arm,pl011"));
    assert(!fdt_compat_exists("acme,does-not-exist"));

    /* Out-of-range reg index must fail cleanly, not read past the prop. */
    assert(!fdt_reg_by_compat("pci-host-ecam-generic", 99, &a, &s));

    printf("FDT-TEST PASS\n");
    return 0;
}
