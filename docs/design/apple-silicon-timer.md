# Apple one-shot physical-timer FIQ checkpoint

## Scope and status

Profile 7 (`Makefile.appletimer`) builds on the native-passed shared-init and
8 MiB owned-memory checkpoints. It is **native passed on J514s/T6030**,
as well as emulator/host tested. The native-passed Image SHA256 is:

`69f81db8e7841d45ed0c8b018dcbaee19c85245235e62827ae983a854ebc30a7`

The goal is one physical-timer FIQ through the real kernel vectors and an
actual ERET back to a bounded foreground wait. This is not periodic
timekeeping, scheduler initialization, device enumeration or userspace.
The existing capability model is unchanged.

## Routing and return contract

Apple timers arrive as FIQ, not through the QEMU GIC backend. Reference
sources in the attached Linux tree are `drivers/irqchip/irq-apple-aic.c`
(`aic_handle_fiq`) and `arch/arm64/include/asm/el2_setup.h`. Pinned m1n1
revision `ba130ffbeeadaa35215ed88b07ebcee3199d0be7` defines the guest timer
gate in `src/cpu_regs.h`.

Before dropping from EL2, the timer-only profile reads the effective HCR.
It enables physical counter/timer access using the actual E2H layout:
CNTHCTL bits 10/11 for E2H=1, bits 0/1 otherwise. On Apple implementer
0x61 only, it preserves the guest timer gate `s3_5_c15_c1_3` and sets its
physical-timer bit 1. HCR.FMO must remain clear. The captured HCR,
CNTHCTL and gate before/after values appear in the QR report.

After the memory checkpoint succeeds, the diagnostic disables/masks the
physical and virtual timers, programs a physical deadline about 10 ms ahead,
and unmasks FIQ only. IRQ stays masked. A counter deadline (two seconds)
and an independent iteration cap bound the foreground polling loop.

The FIQ path uses the kernel's full integer exception frame. It requires:

- a frame within the boot kernel stack;
- an active, first physical-timer event with CNTP_CTL low bits equal to 5;
- saved EL1h state with IRQ masked and FIQ unmasked;
- a return PC inside the bounded wait routine.

The handler disables/masks its timer and masks IRQ/FIQ in the saved return
state. It takes no locks, allocates nothing and touches no GIC/AIC registers.
Unknown sources fail the checkpoint; an invalid stack frame never reaches
ERET. Foreground verifies preserved x19–x28 sentinels, delivery exactly once,
masked/disabled timer state and execution after ERET, then reports
`build=timer-qr1`, `phase=timer-complete`, `fiq=1`, `returned=1`, `reason=0`.
It deliberately halts. A missing source reports `timer-timeout`, reason 9.

## Evidence and native procedure

`make -f Makefile.appletimer check` passes host models of setup/refusal and
handler state, inherited memory checks, and five QEMU executions:
EL2 entry, direct EL1 entry, high physical placement/native-size framebuffer,
PAN-capable CPU, and deliberately absent interrupt routing. Positive cases
deliver a real FIQ and return; the absent route produces the expected timeout.
Tests independently decode both the QR matrix and rendered framebuffer pixels.

A **test-only entry fixture** configures QEMU GICv2 Group 0 PPI 30 as FIQ.
That fixture is not linked into the native Image. QEMU does not emulate the
Apple gate or forced E2H behavior; host state tests cover the validation
rules, but only a native run can qualify the Apple-specific setup.

`tools/apple-probe-usb.sh --check-timer LINUX PYTHON` packages the pinned
candidate without contacting the target. `--arm-timer` is reserved for
explicit owner authorization after a fresh power-off, using the existing
Fedora USB-debug entry. It sends exactly one RAM chainload, never a next-stage
proxy request. USB shutdown/SerialException is not a checkpoint result:
scan the QR. Profiles 5, 6 and 7 select their frozen, native-passed Images.

## Native result

The owner's scanned report from
`build/appletimer/loader/usb-20261113T071357Z-104878` confirmed:

| Field | Value |
| --- | --- |
| Build / phase | `timer-qr1` / `timer-complete` |
| EL / SCTLR | `1` / `0x0000100030550985` |
| Frequency | `0x3b9aca00` (1,000,000,000 Hz) |
| FIQ / returned / reason | `1` / `1` / `0` |
| HCR | `0x0000000480000000` (RW and E2H set, FMO clear) |
| Guest gate before / after | `0xf` / `0xf` (physical bit already enabled) |
| CNTHCTL | `0xc00` (E2H timer-access layout) |
| Arena / root | `0x0000010007a9c000` / same |
| Arena bytes / free pages | `0x800000` / `0x7e4` |
| PC / SP | `0xffffffff802080b4` / `0xffffffff80284ea0` |
| ESR / FAR / ELR | `0x96000004` / `0x50000000` / `0xffffffff8020189c` |

ESR/FAR retain the earlier deliberate uaccess test fault. ELR now resolves
to the bounded physical-counter wait (`timer_wait.S`), consistent with the
FIQ return. They are not evidence of a new unhandled synchronous exception.
The report's atomic fields were attempts=1, status=0, value=1, lock=0.

The exact Image and corresponding loader/kernel ELFs are preserved under
ignored `build/appletimer/timer-passed/`; the USB helper now selects that
snapshot. This qualifies one timer FIQ/return on the tested boot CPU only:
not periodic interrupts, other CPUs, AIC devices or scheduling.

## Before scheduler or userspace

This one-shot path intentionally does not call the shared periodic timer
handler: that handler also drives scheduler/poll/wait-queue work. Before
enabling periodic preemption, adapt interrupt masking so FIQ cannot enter
shared critical sections that currently mask only IRQ, initialize required
shared subsystems without probing absent QEMU devices, and establish FP/SIMD
access before the existing context-switch assembly uses FP registers.
Keep Apple routing separate from GIC routing and test actual context switches
before attempting the first EL0 process.
