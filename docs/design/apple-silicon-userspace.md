# Apple first EL0 isolation checkpoint

## Scope and status

Profile 10 (`Makefile.appleuser`) is **native passed on J514s/T6030**,
as well as host/QEMU tested. Native-passed Image SHA256:

`e357a443634b672ef0cfed1f4ac38e21dbcc893ec6f8518b2b8fceb222a19a18`

This is a bounded, static diagnostic ELF—not `/bin/vigil`, a RAM rootfs,
interactive shell or a production boot. The ELF is linked into **this explicit
diagnostic profile only**; the normal kernel artifact still embeds no userland.
It repeats the memory and one-shot FIQ prerequisites, leaves both timers
disabled, and enters one EL0 process with all interrupt classes masked.
User timer preemption and asynchronous signal delivery are not tested.

## Existing machinery, minimal diagnostic process

The checkpoint uses the real `elf_load`, VMA tracking, private user page
tables, guarded KVA kernel stack, fd-table allocator, `sched_add`,
`sched_start`, `ctx_switch.S`, `proc_enter_user`, vectors, syscall dispatcher,
uaccess helpers and capability gate.

A private diagnostic constructor fills the PCB and the existing first-entry
stack-frame protocol. It deliberately does **not** call `proc_spawn`'s init
bootstrap: that path grants init seven capabilities, opens console/keyboard
handles, and requires a seeded random pool for AT_RANDOM. None is needed or
appropriate for this test. No deterministic seed or fake entropy is introduced.

The PCB has cosmetic uid/gid 0, unbound authentication identity, **zero
capabilities**, an empty fd table and one mapped user stack page. The fixture
does not consume argc/argv/auxv or libc, so the complete init ABI and init
policy remain future work. Only the existing 8 MiB image-owned arena is
admitted. No additional DRAM is assumed free.

The shared ELF loader installs one RX user page and drops its temporary
kernel mapping. The stack is RW/NX. The normal first-entry trampoline clears
all GPRs and loads the user TTBR0/SP/SPSR before ERET. The payload checks
cleared registers and 16-byte SP alignment.

## Syscalls and hardware denials

The payload makes five **normal aarch64 SVCs**, each observed but never
replaced by diagnostic code:

1. `getpid` (172) returns 1.
2. `getuid` (174) returns 0.
3. `uname` (160) copies a real result into the writable user stack, returns
   0, and the payload reads identity bytes back.
4. `uname` with a kernel pointer returns `-EFAULT`.
5. `socket(AF_INET, SOCK_STREAM, 0)` (198) returns `-EPERM`/`-ENOCAP`
   through the existing NET_SOCKET capability gate, despite uid 0.

The process then attempts three forbidden accesses:

- read the mapped privileged kernel text at `0xffffffff80200000`;
- write its own RX entry instruction;
- execute a RET instruction written onto its NX stack.

All must produce real lower-EL permission aborts. The fixture has
**diagnostic-only fault recovery**, compiled out of normal kernels. It
accepts only the exact expected sequence, process, private root, stack frame,
EL0 mode/masks, fault PC, FAR and read/write direction. It advances the known
read/write instructions by four bytes or restores the known NX-test return
PC. Unexpected faults fail and halt; no permissions change, generic fault
skipping, signal-policy relaxation or recovery API is added.

The final fixed BRK is the terminal diagnostic event, not a new syscall.
Success requires all five independently checked syscall results, all three
permission denials, the cap denial and the invalid-pointer denial. The process
is left halted; it is not exited or reaped through production teardown.

## QR contract and evidence

Expected native success:

- `build=user-qr1`, `phase=user-complete`, `reason=0`;
- `entered=1`, `pid=1`, `uid=0`, `svcs=5`;
- `kernel_deny=1`, `text_deny=1`, `nx_deny=1`, `capdeny=1`, `badptr=1`;
- private `ttbr0` distinct from the kernel memory checkpoint's `root`.

The QR encoder runs in the kernel, so its ordinary `el` field remains 1.
That does not mean the test stayed in EL1: `entered` is set only after
validating the exception frame from EL0, and the results require actual
SVC returns and lower-EL permission aborts. ESR/FAR/ELR at success describe
the final BRK/last fault, not an unhandled kernel exception.

`make -f Makefile.appleuser check` passes:

- inherited PMM/handoff host tests;
- 13 host executions of the actual context/SVC/result/fault validators;
- four QEMU executions: EL2, direct EL1, high physical placement/native-size
  framebuffer, PAN-capable CPU;
- a missing-kernel-read-fault mutation, rejected with reason 7;
- a W+X ELF mutation, rejected by the shared ELF loader with reason 10.

Tests inspect the actual RX/NX/AP/WB leaf PTEs, unchanged loaded ELF bytes,
uname output in user memory, final process frame, prerequisite reports,
and independently decoded QR matrix and native framebuffer pixels.
Mutations exist only in temporary Images, never the native payload.

Normal ARM64 capability/no-init smoke tests and the preemption checkpoint
regressions also pass. Evidence:
`build/evidence/apple-user-{check-final,arm64-regression,preempt-regression}.log`.
No x86 implementation change is made here; the preceding x86 boot/capability
checks remain the last x86 evidence, not a new run for this checkpoint.

## Native result and session handoff

The owner's scanned QR from
`build/appleuser/loader/usb-20261113T080421Z-114584` confirmed:

| Field | Value |
| --- | --- |
| Build / phase / reason | `user-qr1` / `user-complete` / `0` |
| Entered / PID / UID | `1` / `1` / `0` |
| Normal SVCs | `5` |
| Kernel read / RX write / NX execute denials | `1` / `1` / `1` |
| Capability / bad-pointer denials | `1` / `1` |
| Kernel reporter EL / SCTLR | `1` / `0x0000100030550985` |
| Reporter PC / SP | `0xffffffff80208294` / `0xffffffff84029e40` |
| ESR / FAR / ELR | `0xf200005a` / `0x000007ffffffeff0` / `0x4001b0` |
| Owned arena / kernel root | `0x0000010007a9e000` / same |
| Arena bytes / pre-test free pages | `0x800000` / `0x7e4` |
| Private user TTBR0 | `0x0000010007abc000` |
| User SP | `0x000007ffffffee00` |
| Atomic attempts / status / value / lock | `1` / `0` / `1` / `0` |

ESR is the expected final lower-EL BRK `#0x5a`; ELR resolves to `user_done`
in the fixture ELF. FAR retains the prior NX stack target. The distinct user
root, validated EL0 frames, successful SVC returns and hardware permission
denials qualify actual EL0 execution, not merely construction of page tables.
This remains one fixed capless process, not libc/init/rootfs integration.

The exact Image, matching loader/kernel ELFs and the user ELF are frozen under
ignored `build/appleuser/userspace-passed/`. Profile 10 selects that snapshot.
The native timer, cooperative scheduler and preemption snapshots remain under
their respective `*-passed` directories. No commits, merges, publication,
installed boot changes or target-disk writes were performed for these milestones.

This is the agreed end-of-night stopping point. The Mac is deliberately
halted with timers disabled; the listener has exited and no retry is armed.
Next session should begin with the full init ABI and legitimate entropy/rootfs
ownership requirements below, rather than extending the diagnostic fault
fixups into a general userspace policy.

## Native procedure and stopping point

`tools/apple-probe-usb.sh --check-user LINUX PYTHON` prepares the pinned
native-passed image offline. Explicit owner authorization is required for `--arm-user`
after a fresh power-off. Use the existing Fedora USB-debug entry and exactly
one RAM chainload; no disk/ESP/boot-policy changes or reboot/retry automation.
Profiles 5–10 retain their frozen native-passed Images.

USB disconnect/SerialException after vectoring is expected and proves no
kernel result. Scan the full final QR JSON. A native pass is the agreed
end-of-session milestone. Next time: complete process/init ABI, a trustworthy
entropy source, explicit rootfs memory ownership/budget, RAM-rootfs assembly
and init execution—not an assumed full boot from this fixture.
