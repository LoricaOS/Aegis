# Native (non-Limine, non-UEFI) RPi5 boot — PARKED 2026-07-17

This directory holds Aegis's from-scratch boot path for stock, unmodified
Raspberry Pi 5 firmware — no Limine, no UEFI, no U-Boot. Entry is
`boot_probe.S` (image-header parsing → EL2→EL1 drop → page tables/MMU →
jump into C), landing in `native_entry.c`'s `kernel_main_native()`.

**Status: parked, not deleted.** Phase A (a real native boot reaching a
clean "no init found" panic on stock Pi 5 EEPROM firmware) is done and
works — see [[rpi5-port-research]]. Phase B (real NVMe storage via a
from-scratch Broadcom PCIe root-complex driver, `pcie_brcmstb.c`) hit a
hardware wall that isn't fixable from software alone; see
[[rpi5-pcie-driver-research]] for the full investigation.

## Why this is parked, in one paragraph

`pcie_brcmstb.c` implements pcie1 (the NVMe M.2 slot) bring-up ported from
Linux/U-Boot/Zephyr reference drivers. On real hardware, with a genuine
NVMe module installed, the PCIe root complex's own register block (vendor/
device ID, MISC_CTRL, HARD_DEBUG, PCIE_CTRL, PCIE_STATUS, and the shared
`rescal` calibration block) reads a **fixed, non-real pattern that never
changes** — not across six independently-tested hypotheses (KVA→phys
translation, three different reset/bridge orderings including the
verified real U-Boot sequence, sibling-controller `rescal`-sharing bridge
gating, and a 2-second settling wait with zero writes). The translation
was independently proven correct via `kva_page_phys()`. A vendor/device ID
is a fixed silicon constant with zero dependence on reset state, so no
amount of driver-side reordering could ever fix a bad read there. The
conclusion: some firmware/EEPROM-level init step this driver has no way to
discover or replicate from a from-scratch boot is missing — likely
something the stock EEPROM/bootloader only performs when handing off to a
recognized boot chain. This is out of scope for a single-session driver
fix; see [[rpi5-pcie-driver-research]]'s dated entries for the full
register-by-register evidence trail.

## Decision (2026-07-17): pivot to an existing bootloader

Rather than keep guessing at undocumented Broadcom firmware behavior, the
plan is to put this native path on the backburner and boot via an existing,
proven bootloader (U-Boot is the leading candidate — it already has a
**working** `pcie_brcmstb` driver for this exact SoC, see
`~/Developer/rpi5-pcie-ref/uboot-pcie-brcmstb.c`) instead of stock EEPROM
directly loading `kernel_2712.img`. See [[rpi5-uboot-research]] for
whatever comes out of that research.

## How to resume this path later

Everything native-boot-specific lives in this one directory plus one
top-level file, and is **not** referenced by the default `make`/`make
iso`/`make dist` targets — it cannot regress the shipped x86-64/Limine-
arm64 build by existing:

- `Makefile.pi5native` (repo root) — `make -f Makefile.pi5native kernel`
  builds `build/pi5native/pi5-kernel.img`; `NATIVE_TEST_STOP=N` gates
  bring-up at stage N for one-subsystem-per-flash bisection (see the
  Makefile's own header comment for what each stage means).
- `boot_probe.S` / `linker-pi5-native.ld` — the entry stub + linker script.
- `native_entry.c` — `kernel_main_native()`, this path's thin wrapper
  around the shared `kernel_main_arm64()` in `../main.c`.
- `pcie_brcmstb.c` — the parked PCIe driver. Its diagnostics (register
  dumps, `kva_page_phys` self-check) are left in place deliberately, not
  stripped — they're exactly what the next attempt needs to pick up from,
  whether that's a fresh from-scratch attempt or comparing against
  whatever U-Boot leaves initialized when Aegis boots after it.

To rebuild and smoke-test on real hardware exactly as this session did:
`make -f Makefile.pi5native kernel NATIVE_TEST_STOP=6`, flash
`build/pi5native/pi5-kernel.img` as `kernel_2712.img` on the boot
partition alongside the existing `config.txt`
(`dtparam=pciex1` is required for pcie1 to even be enabled), boot, and
read the `[PCIE-BRCM]` diagnostic lines over serial (115200 8N1,
`/dev/ttyACM0` via the Pi 5's USB-C debug port).
