# Resident m1n1: debug transport experiment

Status: **offline qualified; native transport test passed on J514s/T6030**.
This is not an Aegis kernel boot, a V4 memory-intake rerun, or a production
dependency. Native V2/V3/V4 remain one-way handoffs: m1n1 shuts down USB before
entering those diagnostics. A USB disconnect there is not a result.

## Separate paths

- Production/native: standalone image, no resident m1n1 requirement.
- Debug-only: existing m1n1 remains at EL2 and owns USB; a tiny EL1 guest
  sends two fixed BRK messages. No change to installed boot entries, firmware,
  ESP, Linux, or production kernel build.

The first test deliberately has no framebuffer, guest allocator, device
access, firmware calls, or Aegis memory-intake code. The **monitor** still
initializes its hypervisor: the pinned implementation shuts down PCIe,
brings up secondary CPUs, configures watchdog/timer state and stage-2
translation. This is a hardware experiment, not just a serial echo.

The host proxyclient is pinned to
`ba130ffbeeadaa35215ed88b07ebcee3199d0be7`. The existing first-stage debug
firmware reported m1n1 v1.6.1; its exact build is not identified by that version
string. Its minimal M3 hypervisor/USB path passed the native test below;
broader hypervisor support is **not established**. This experiment neither
replaces it nor assumes it matches the host source. An unsupported operation,
timeout, exception or hang is a failed experiment: stop, retain evidence and
coordinate a power-off. Do not automatically retry or reboot.

## Guest and protocol

`Makefile.appledebug` builds only `build/appledebug/guest.{elf,bin}`.
Qualified raw-image SHA256:
`c8f35b7dd54e6662196b8a791b2a7ab56ed9c3893771799527437f4ebb13a20d`.

The monitor allocates 48 KiB and maps exactly three 16 KiB stage-2 pages
starting at guest IPA `0x80000000`:

1. Code, read-only/executable.
2. Fixed 32-byte report, read/write and execute-never.
3. Stack, read/write and execute-never.

Stage 1 and caches stay off; DAIF stays masked. No guest MMIO is mapped.
The host checks the uploaded bytes and stage-2 walker results. The pinned
walker strips lower attributes, so readback verifies physical addresses,
hardware-page type and upper attributes/XN, **not** the lower permission bits.
`hv_translate` is not suitable here: it returns the input address with guest
stage 1 disabled.

Both calls use `brk #0x4242`:

- Call 1: exact trap PC, `x0=1`, fixed message address and length.
  Host validates and saves `AEGIS DEBUG: resident m1n1 USB transport\n`,
  advances the saved PC by four and resumes.
- Call 2: exact trap PC, `x0=2`, fixed report address and length 32.
  Host validates four little-endian u64 fields: completion stage 2,
  `CurrentEL=4` (EL1), `ID_AA64MMFR0_EL1`, and `SCTLR_EL1` with M/C/I off.
  It exits the guest, checks the report again and requests a proxy nop.

The host never follows guest-selected report/log pointers. An unexpected
registered event requests guest exit, not a shell or an unhandled return
which could cause m1n1 to reboot. Transport loss can prevent orderly exit.
The allocation is retained until power-off, including on failure.

## Validation and use

```sh
export PATH="$PWD/build/host-tools/root/usr/bin:$PATH"
make -f Makefile.appledebug test
/home/derek/asahi/m1n1-venv/bin/python -B tools/apple-debug-usb.py --check /path/to/attached/linux
```

Six host test methods cover layout/no relocations, ordered completion,
rejected PCs/pointers/lengths/call IDs/exception classes, wrong messages,
wrong report state, and extra events. A real QEMU EL2 test stub executes
the unchanged guest at EL1, captures both BRKs and feeds their actual
registers and report through the same host protocol validator.

QEMU uses identity RAM without stage 2. It does **not** validate the Apple
monitor's stage-2 implementation, M3 register support, or USB connection.
`--check` verifies the image hash, client revision, imports and host assembler
without opening a target device or sending requests.

Only explicit root `--arm` may acquire the shared native/debug boot lock,
wait up to 600 seconds for `/dev/m1n1`, check J514s/T6030, initialize HV and
run the guest once. Capture its complete stdout/stderr. Per-run evidence under
`build/appledebug/usb-*` includes a manifest, fixed guest log, binary report
and final JSON on success (or available failure details). A pass requires
both guest messages **and return to a responsive resident proxy**.

Arm first and confirm the listener is waiting before asking the owner to
boot the existing Fedora debug entry using the left USB-C port nearest
MagSafe. Do not confuse this path with DH. No automatic fallback or native
chainload follows this experiment.

## Native evidence

Run `build/appledebug/usb-20261113T032854Z-85566` passed on the owner's
J514s/T6030 using the existing Fedora USB-debug entry and m1n1 v1.6.1.
The listener captured the exact fixed message, both ordered BRK events and
the 32-byte report. It then observed `HV: All CPUs exited`, reread the same
report and completed the final proxy nop over USB.

The saved report contains:

| Field | Value |
| --- | --- |
| Completion stage | 2 |
| CurrentEL | 4 (EL1) |
| ID_AA64MMFR0_EL1 | `0x110012120f100003` |
| SCTLR_EL1 | `0x30d00980` (M/C/I off) |

This qualifies the tiny cache-off EL1 guest's resident-monitor logging and
return path on this machine. It does not qualify a full Aegis boot, guest
stage-1 translation, interrupts, cache-on execution, or V4 memory intake.
No subsequent guest or boot is automatically started. Bounded failed-range
reporting for native V4 is now prepared and offline tested, without relaxing
its checks; see `apple-silicon-memory.md`. Running V4 under the resident
monitor is a separate integration step, not something this tiny guest proves.
