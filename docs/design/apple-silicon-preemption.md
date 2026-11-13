# Apple bounded timer-driven preemption checkpoint

## Scope and status

Profile 9 (`Makefile.applepreempt`) is **native passed on J514s/T6030**,
as well as host/QEMU tested. The native-passed Image SHA256 is:

`9c8f1fffaf2967a8ce6bca5ee5ab80e91274396e3b026c1fae6e9e2a6aa8c0e9`

It repeats the memory and one-shot FIQ prerequisites, then runs two kernel
threads that **never voluntarily yield**. Only a physical-timer FIQ can
switch the first thread to the second through the shared `sched_tick` and
`ctx_switch.S`. This is a bounded proof on the boot CPU, not unrestricted
preemptible kernel execution or a userspace/rootfs boot.

Only the existing 8 MiB image-owned arena is admitted. No AIC, disk, USB,
network or other device driver is initialized. No capabilities are granted
or relaxed. The native handler contains no GIC acknowledgement.

## Timer and state contract

The existing timer's clock initialization and BSP tick accounting are
separated from timer arming/polling, with two callers each: the normal timer
path and this checkpoint. The Apple checkpoint uses the physical counter;
QEMU/Limine's normal build retains its virtual timer. Existing random/poll/
wait-queue work is deliberately not invoked from this diagnostic FIQ.

Each timer FIQ must come from the enabled, unmasked, pending physical timer
(CNTP_CTL low bits 5), on one of the two known kernel tasks. Its saved frame
must lie inside that task's stack, with EL1h mode, IRQ masked/FIQ unmasked,
and ELR in the assembly-only foreground window. Unknown source, frame,
mode, PC, task or CPU ownership fails closed.

The handler rearms about 10 ms ahead, advances shared BSP tick accounting,
and calls the existing scheduler while hardware exception-entry masks remain
in force. The outgoing handler frame remains parked on its task's stack.
When that task resumes, the handler verifies current-task/CPU identity,
increments its resume counter, then returns through the real vectors/ERET.

Workers keep distinct patterns in V0–V31, FPSR, FPCR, TPIDR_EL0 and integer
sentinels. Both must resume through at least eight FIQ handlers and execute
foreground state checks afterward. A second assembly-only rendezvous lets
the peer finish without a yield. The final worker disables/masks the timer
and publishes:

- `build=preempt-qr1`, `phase=preempt-complete`, `reason=0`;
- `a=1`, `b=1`: both foreground state checks passed;
- `rounds=8`: required handler resumes per task;
- `ret_a >= 8`, `ret_b >= 8`, `tasks=2`;
- `ticks = fiq_a + fiq_b`, at most 128, with IRQ/FIQ masked at halt.

One peer's FIQ frame may remain suspended at halt, so total delivered ticks
may exceed total resumes by one. The resume counters are not a claim that
every outstanding frame has unwound. Both foreground loops have two-second
counter deadlines plus independent iteration caps. Timer events have a hard
128-event cap. These do not recover from arbitrary lock/assembly/reporting
failure and do not reboot the Mac.

## Why this does not enable arbitrary kernel preemption

Only the call-free assembly wait windows unmask FIQ. Setup, FP/TLS checks,
reporting and task creation keep IRQ/FIQ masked. `sched_tick` itself always
runs masked on exception entry. Thus this test never exercises the unsafe
cooperative-switch window between publishing the new current-task pointer
and actually swapping stacks.

Before general kernel preemption, audit/fix those cooperative switch paths,
per-task interrupt-mask restoration, all FIQ-visible critical sections,
poller/wait-queue initialization and unexpected-source dispatch. EL0 frames,
user address-space switching, SMP, task teardown and input remain separate
qualification gates.

## Host and QEMU evidence

`make -f Makefile.applepreempt check` passes:

- inherited PMM/handoff checks and dirty-page kernel-task creation checks;
- 15 host executions of the actual frame/source/resume validator, including
  wrong task/frame/mode/source/PC/CPU, event cap and lost resume identity;
- four QEMU executions: EL2, direct EL1, high physical placement/native-size
  framebuffer, and PAN-capable CPU;
- a missing-EOI fixture: exactly one periodic FIQ, then a bounded timeout
  with reason 8 instead of a false success or unbounded foreground wait.

Positive executions observed 19 ticks, 10/8 handler resumes, both state checks
passed, and shared clock/tick advancement. Exact counts are scheduling/timing
dependent; the contract is the bounds above. Tests inspect the real reports,
saved frame modes/PCs, timer-disabled final state, and independently decode
the QR matrix and actual native-size framebuffer pixels.

QEMU routes its timer through GICv2, unlike Apple's direct timer FIQ.
`test/apple_preempt_fixture.py` installs adapters **only into temporary test
Images**, in unsupported AArch32 vector slots. One acknowledges the GIC before
the timer is rearmed; another EOIs after rearm but before scheduling can park
the handler. They briefly install test-only device tables in TTBR0 and restore
the original table before entering kernel C. These adapters and tables are
absent from the native Image and its pinned payload. The fixture uses explicit
branch encodings: this host linker relaxed an absolute-symbol JUMP26 into a
NOP, which the initial test correctly caught as a kernel fault.

Normal ARM64 capability/no-init smoke tests and the cooperative scheduler
checkpoint regressions also pass after the clock refactoring. Evidence:
`build/evidence/apple-preempt-{check-final,arm64-regression,sched-regression}.log`.
No new x86 implementation change is made in this checkpoint; x86 boot tests
were last run and passed with the preceding task-initialization fix.

## Native result

The owner's scanned QR from
`build/applepreempt/loader/usb-20261113T074102Z-112105` confirmed:

| Field | Value |
| --- | --- |
| Build / phase | `preempt-qr1` / `preempt-complete` |
| State checks A / B / reason | `1` / `1` / `0` |
| Required resumes / tasks | `8` / `2` |
| Total timer FIQs | `0x13` (19) |
| FIQs A / B | `0xa` (10) / `9` |
| Resumes A / B | `0xa` (10) / `8` |
| Frequency | `0x3b9aca00` (1,000,000,000 Hz) |
| EL / SCTLR | `1` / `0x0000100030550985` |
| CPACR / DAIF | `0x300000` / `0x3c0` |
| PC / SP | `0xffffffff80208394` / `0xffffffff84009b40` |
| Arena / root | `0x000001000829e000` / same |
| Arena bytes | `0x800000` |
| Free before / now | `0x7e4` / `0x7da` |
| ESR / FAR / ELR | `0x96000004` / `0x50000000` / `0xffffffff80201aac` |
| Atomic attempts / status / value / lock | `1` / `0` / `1` / `0` |

Both non-yielding threads passed their foreground integer/FP/TLS checks after
at least eight handler resumes. The single outstanding B handler at halt is
expected, as described above. Ten retained pages account for the two TCBs
and two four-page stacks; guard frames were returned. ESR/FAR retain the
earlier deliberate uaccess fault, while ELR resolves to `apple_preempt_wait`
line 44, in the permitted foreground window.

The exact Image and matching loader/kernel ELFs are frozen under ignored
`build/applepreempt/preemption-passed/`; profile 9 now selects that snapshot.
This qualifies the bounded boot-CPU proof, not arbitrary kernel preemption,
SMP or EL0 execution.

## Native procedure

`tools/apple-probe-usb.sh --check-preempt LINUX PYTHON` packages the pinned
native-passed image offline. Only explicit owner authorization permits `--arm-preempt`
after a fresh power-off. Use the existing Fedora USB-debug entry. Exactly
one RAM chainload is sent, with no next-stage proxy request, disk/ESP edits,
boot-policy changes, retries or automatic reboot. Profiles 5–9 retain their
frozen native-passed Images.

USB shutdown/SerialException after vectoring is not a pass/fail result.
Scan the final QR. Only the native report can qualify repeated Apple timer
delivery and preempted context returns on this hardware.
