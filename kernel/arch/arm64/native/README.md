# Native (non-Limine, non-UEFI) RPi5 boot

This directory holds Aegis's from-scratch boot path for stock, unmodified
Raspberry Pi 5 firmware — no Limine, no UEFI, no U-Boot. Entry is
`boot_probe.S` (image-header parsing → EL2→EL1 drop → page tables/MMU →
jump into C), landing in `native_entry.c`'s `kernel_main_native()`.

**Status: working through PCIe/NVMe enumeration.** Phase A (native boot to a
clean "no init found" panic on stock Pi 5 EEPROM firmware) works. Phase B
(real NVMe storage via a from-scratch Broadcom PCIe root-complex driver,
`pcie_brcmstb.c`) reached a milestone on 2026-07-17: the PCIe link trains and
the NVMe SSD enumerates on real hardware:

```
[PCIE-BRCM] OK: link up @ phys 0x1000110000
[PCIE-BRCM] found 14e4:2712 class=6 at bus 0 dev 0    (the root complex)
[PCIE-BRCM] found 15b7:5041 class=1 at bus 1 dev 0    (the NVMe SSD)
```

## The multi-session "PCIe wall" was never a PCIe bug

For a long stretch this looked like a Broadcom PCIe bring-up problem: every
MMIO register read (rescal STATUS, RC vendor/device ID, MISC_CTRL, …) came
back as a fixed garbage value, and the link never trained. Six
register-sequencing hypotheses and a U-Boot-chainload research detour all
came up empty.

The actual root cause was in `../vmm.c`'s `map_page_in()`: it installed a
fresh leaf PTE with only `dsb ishst` and **no `TLBI` + `ISB`**. That's fine
for a genuine first-ever mapping, but not when a VA previously held a live
translation torn down without its own TLBI (early-boot idmaps, VA reuse via
the kva freelist), and it never synchronized the walker for the caller's
next load. So every `kva_map_mmio()`'d MMIO page was read through a stale
cached translation — a bit-perfect-correct PTE still returned garbage. The
native RPi5 path was simply the first code in the tree to heavily use
`kva_map_mmio()`, so the latent bug surfaced here first. Fixed in commit
`d88ba23` with the full `STR → DSB ISHST → TLBI VAAE1IS → DSB ISH → ISB`
sequence. See [[rpi5-pcie-driver-research]] for the full story.

## Known-open secondary issue (not blocking)

`GICD_IIDR` at phys `0x7fff9008` reads `0xffffffff` (real-Linux devmem:
`0xEB010042`), through both `arch_dmap` and `kva_map_mmio`, even though the
GIC works for interrupts. Leading theory: `vmm_init()`'s "map all reported
RAM as Normal-cacheable" pass sweeps the GIC's device page into a cacheable
alias because the DTB `memory` node doesn't strictly exclude MMIO holes.
Fix would be to build the cacheable-RAM map from DRAM banks only and treat
all `0x10_xxxx_xxxx` SoC/AXI ranges as Device. Does not currently block
anything.

## Next feature step

Wire up the existing NVMe block driver (from the x86 port) on top of the
now-working PCIe RC to actually read/write the disk.

## Files

- `Makefile.pi5native` (repo root) — `make -f Makefile.pi5native kernel`
  builds `build/pi5native/pi5-kernel.img`; `NATIVE_TEST_STOP=N` gates
  bring-up at stage N for one-subsystem-per-flash bisection (see the
  Makefile's own header comment for what each stage means).
- `boot_probe.S` / `linker-pi5-native.ld` — the entry stub + linker script.
- `native_entry.c` — `kernel_main_native()`, this path's thin wrapper
  around the shared `kernel_main_arm64()` in `../main.c`.
- `pcie_brcmstb.c` — the Broadcom PCIe root-complex driver. Still carries
  temporary `[PCIE-BRCM]` diagnostics + a `vmm_debug_raw_kernel_pte()`
  helper (in `../vmm.c`) from the bring-up investigation, pending a cleanup
  pass.

None of this is referenced by the default `make`/`make iso`/`make dist`
targets, so it cannot regress the shipped x86-64/Limine-arm64 build.

To rebuild and test on real hardware exactly as this session did:
`make -f Makefile.pi5native kernel NATIVE_TEST_STOP=6`, flash
`build/pi5native/pi5-kernel.img` as `kernel_2712.img` on the boot partition
alongside `config.txt` (`dtparam=pciex1` is required for pcie1 to be
enabled), boot, and read the `[PCIE-BRCM]` diagnostic lines over serial
(115200 8N1, `/dev/ttyACM0` via the Pi 5's USB-C debug port).
