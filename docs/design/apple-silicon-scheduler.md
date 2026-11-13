# Apple cooperative scheduler checkpoint

## Scope

Profile 8 (`Makefile.applesched`) repeats the owned-memory and one-shot FIQ
checkpoints, disables the timers, then runs two kernel threads through the
**existing** `sched_spawn`, `sched_start`, `sched_yield_to_next` and
`ctx_switch.S`. It is **native passed on J514s/T6030**, as well as
host/QEMU tested. The native-passed Image SHA256 is:

`ef68539239d7d5be261471b81974e5c80719a99eb916ee719ff41a2b7d5f1edd`

This isolates task creation and context-state preservation from periodic
preemption. No AIC/device probing, interrupt-driven scheduling, task teardown,
EL0 entry, rootfs or console input is enabled. Only the existing 8 MiB
image-owned arena is admitted to the allocator. Capabilities are unchanged.

## Entry prerequisites

The loader configures CPTR_EL2 for FP/SIMD using the **effective** HCR.E2H:
the non-VHE layout uses the existing `0x33ff`; VHE uses CPACR-style FPEN=3
at bits 20/21. The kernel then enables CPACR_EL1.FPEN and reads it back.
This is needed because the shared context switch saves/restores all V
registers even for kernel tasks.

The scheduler profile selects FIQ-aware interrupt helpers: enable unmasks
FIQ while keeping unqualified IRQ sources masked; disable/save masks both.
Restore reinstates the exact saved DAIF. A source-disabled enable/save/
nested-save/restore/disable test checks these semantics before threads start.
Normal GIC builds retain their existing IRQ-only semantics.

Kernel task creation now clears the TCB before assigning fields. Recycled
KVA pages previously left TLS, sleep deadlines, clear-child-TID and other
fields carrying stale bytes. This general initialization fix applies to
all architectures, not just the Apple caller.

## Thread proof

Each worker checks its own current-task identity, CPU ownership, live SP
inside its allocated stack, unmapped bottom guard, and stack frames within
the admitted arena. It installs distinct patterns in all 32 V registers,
FPSR/FPCR and TPIDR_EL0. For 32 rounds it yields through the real scheduler,
then compares the restored FP/TLS state and verifies masked DAIF and current
task ownership. An assembly wrapper checks distinct x19–x28 sentinels across
each yield.

The final worker requires both workers to finish, with distinct task/stack
addresses, then publishes `build=sched-qr1`, `phase=sched-complete`,
`a=0x20`, `b=0x20`, `rounds=0x20`, `tasks=2`, `reason=0`. It halts without
reaping either live stack. A finite rendezvous budget detects failure of
the peer to complete; it is not an independent watchdog for wedged assembly,
locks or a fault that prevents the reporter from running.

The default fair scheduler's queue selection is exercised. The normal
periodic timekeeping initializer is deliberately not called, so its runtime
clock remains at the pre-timer fallback; this is **not** a fairness-accounting
or periodic-preemption qualification.

## Checks

`make -f Makefile.applesched check` runs:

- inherited PMM and memory-handoff host checks;
- actual task creation on deliberately dirty pages, for both ARM64 and x86
  frame layouts, including first/second allocation failures and guard setup;
- four real QEMU executions: EL2, direct EL1, high physical placement with
  native-size framebuffer, and a PAN-capable CPU;
- two temporary-Image mutation tests: omit the V30/V31 restore (reason 11)
  or TLS restore (reason 10), requiring a failure rather than success.

The positive tests inspect both TCBs' saved TLS and on-CPU ownership,
prerequisite memory/timer reports, and independently decode the QR matrix
and native-size rendered pixels. Mutated Images exist only in temporary
test directories and are never packaged for the Mac.

`make -f Makefile.arm64 test` and
`make CC=gcc LD=ld NM=nm OBJCOPY=objcopy test` also pass after the shared
task-initialization change. Evidence is in
`build/evidence/apple-sched-{check-final,arm64-regression,x86-regression}.log`.
QEMU alone does not qualify Apple's forced-E2H CPTR behavior; the native
result below supplies that evidence for this tested boot CPU.

## Native result

The owner's scanned QR from
`build/applesched/loader/usb-20261113T072637Z-109202` confirmed:

| Field | Value |
| --- | --- |
| Build / phase | `sched-qr1` / `sched-complete` |
| A / B / required rounds | `0x20` / `0x20` / `0x20` |
| Tasks / reason | `2` / `0` |
| EL / SCTLR | `1` / `0x0000100030550985` |
| CPACR / DAIF | `0x300000` / `0x3c0` |
| PC / SP | `0xffffffff802081b4` / `0xffffffff8400eb30` |
| Arena / root | `0x0000010007c9c000` / same |
| Arena bytes | `0x800000` |
| Free before / now | `0x7e4` / `0x7da` |
| ESR / FAR / ELR | `0x96000004` / `0x50000000` / `0xffffffff8020189c` |
| Atomic attempts / status / value / lock | `1` / `0` / `1` / `0` |

The free-page delta is ten retained pages: two TCBs and two four-page usable
stacks, with their guard frames returned. The final SP is on a KVA thread
stack rather than the original boot stack. ESR/FAR retain the deliberate
earlier uaccess fault; ELR retains the prior timer wait. These are not new
unhandled synchronous faults.

The tested Image and matching loader/kernel ELFs are frozen under ignored
`build/applesched/scheduler-passed/`. Profile 8 now selects that snapshot.
This qualifies the bounded cooperative proof on the tested boot CPU, not
periodic preemption, SMP, task exit/reaping or EL0.

## Native procedure and next boundary

`tools/apple-probe-usb.sh --check-sched LINUX PYTHON` prepares the frozen
native-passed image offline. Only explicit owner authorization permits `--arm-sched`
after a fresh power-off. Use the existing Fedora USB-debug entry and the
one-shot RAM chainload. No disk/ESP/boot-policy changes, retries or reboot
automation are introduced. Profiles 5–8 keep their frozen native-passed Images.

After native context-switch proof, periodic preemption still requires a
proper Apple timer/timekeeping backend and a critical-section audit. In
particular, cooperative scheduler switch paths must not reopen FIQ between
publishing the incoming current-task pointer and actually swapping stacks.
This checkpoint keeps both interrupt classes masked during every yield;
it does not claim that enabling periodic FIQ against those paths is safe.
First EL0 execution and RAM-rootfs integration remain separate milestones.
