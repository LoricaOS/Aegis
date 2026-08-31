# Brief for the next Aegis security audit

Written by the agent that **fixed** the 2026-07-30 audit (all 41 findings), for
whoever runs the next one. It is deliberately opinionated: it says what to do
differently, not just what to look at.

Read `docs/audits/2026-07-30-kernel-security-audit.md` first — but read it as
*calibration*, not as a template to copy. Its blind spots are listed below and
they are the most valuable part of this document.

---

## 0. The one-paragraph version

The last audit was a pure source-reading exercise. It was good — 41 real
findings, no false positives that survived verification — but it left the two
sanitizers already wired into this build unused, never compiled anything but the
default config, never built the other architecture (which was in fact broken),
and never touched the 3371-line USB stack or the capability *policy parser*. Run
the tools first, then read code in the places the tools can't reach.

---

## 1. What the last audit got wrong

Calibrate on these. Each is a real error made by a competent audit.

**It proposed two fixes that were wrong.**
- H9's suggested fix (`if (row < 0) row = 0;`) leaves the signed-overflow UB in
  place. At `-O2` the compiler is entitled to delete a `< 0` test on a value it
  has already assumed cannot go negative. The correct fix was to accumulate
  unsigned. *Lesson: a fix that papers over UB is not a fix. If the bug is UB,
  the fix must remove the UB, not its symptom.*
- H8's suggested fix (reject spans wider than one native sector) would have
  broken legitimate multi-sector I/O on 4K-native drives. *Lesson: state what
  your fix breaks. An auditor who has not asked "what legitimate caller does this
  now reject?" has not finished the finding.*

**It missed a second trigger for its own headline bug.** C1 was `readlink(p, buf, 0)`.
The audit did not notice that `bufsiz` is narrowed from `uint64` to `uint32`
*before* being clamped, so `readlink(p, buf, 2^32)` reaches the same underflow.
*Lesson: when you find an integer bug, enumerate every input that reaches the
same arithmetic, including via narrowing conversions.*

**It mis-rated severity in both directions.** L12 (`vfork_freeze` silently skips
past 16 concurrent vforks) is described as "never-hit" and filed LOW — but ~17
thread groups vforking at once is trivially reachable from hostile userspace, and
the consequence is the exact address-space corruption the freeze exists to
prevent. Meanwhile H4 was "initially mis-rated as bounded/terminating" by two
independent sub-audits before someone spotted the uint32 wrap. *Lesson: "reachable
from unprivileged userspace" outranks "seems unlikely". If you cannot write the
trigger, say so explicitly rather than assuming it is hard.*

**Its "Audited and found GUARDED" section is where the risk now lives.** That
section is load-bearing — future readers will trust it — and it was written from
the same reading that produced the findings. It contains at least one claim that
was too strong: exception-table coverage was called "complete", with the TCP
`read()` path noted separately as an exception (L11). One documented exception to
a completeness claim means the claim is not a completeness claim. **Re-derive that
section from scratch. Do not inherit it.**

**It never looked at the build.** The aarch64 build did not link at all — three
whole translation units missing from `Makefile.arm64`, and the file never
consumed the kconfig header, so `virtio_core.c`'s device discovery compiled to an
empty shell that could never find a device. An audit that only ever builds one
config on one arch is auditing one of many kernels this tree can produce.

---

## 2. Ground rules

1. **Verify before reporting.** Every finding must be confirmed by reading the
   current source, not by pattern-matching. The previous audit's file:line refs
   are now stale — 41 fixes moved things.
2. **Give a trigger, not a theory.** Each finding states the concrete input,
   syscall sequence, or device behaviour that reaches it. If you cannot construct
   one, label the finding `UNTRIGGERED` and say what would be needed. Do not
   quietly upgrade a theory into a scenario.
3. **Propose a fix, then attack your own fix.** What does it break? Does it leave
   UB? Does it change an ABI or reject a legitimate caller? Two of the last
   audit's proposed fixes failed this test.
4. **Severity is reachability × impact, and reachability is a claim you must
   defend.** Use: `[stock]` unprivileged with baseline caps, `[priv]` needs a
   non-trivial capability, `[media]` needs crafted mounted media, `[device]`
   needs a malicious device/host/firmware, `[boot]` needs control of
   bootloader-supplied data.
5. **Say what you did not check.** The most dangerous output is a confident,
   silent gap. The previous audit's caveats were its best feature; keep that.
6. **Do not fix anything.** Findings only. A separate session does the fixing and
   needs your reasoning intact, including the parts you were unsure about.

---

## 3. Do this before reading any code

The last audit skipped all of this. Expect it to produce findings on its own, and
to tell you where to point the humans.

**Run the sanitizers. Both are already wired up and neither has been used.**
```
make KASAN=1  && make test          # -fsanitize=kernel-address, globals/BSS
make UBSAN=1  && make test          # shift, signed-overflow, bounds, ptr-overflow, ...
make -f Makefile.arm64 UBSAN=1 test
```
`UBSAN_CHECKS` is a curated high-signal set (see the Makefile comment for why not
full `-fsanitize=undefined`). There is a `ubsantest` cmdline and
`kernel/mm/ubsan_test.c` to confirm the runtime actually reports. Note KASAN and
UBSAN do not co-fit — the Makefile says their instrumentation together overruns
something; run them separately and report if that comment is now wrong.

**Build the whole config matrix.** There are six tiers and 38 Kconfig symbols;
only `full` is routinely built.
```
for c in full microvm nano pico2 tiny workstation; do
    make ${c}_defconfig && make -j$(nproc) || echo "BROKEN: $c"
done
```
A tier that does not compile is a finding. A tier that compiles but silently
drops a security check because the code was `#ifdef`'d out is a *much* better
finding — `virtio_core.c` was exactly that shape on arm64. Specifically hunt for
`#ifdef CONFIG_*` wrapping anything that validates, bounds-checks, or
`cap_check`s.

**Build and test both architectures.** x86_64 and aarch64 diverge in the fault
path, uaccess, and entry/exit. `arch/arm64/traps.c` and `arch/x86_64/idt.c` are
twins that have drifted before.

**Run the existing harnesses and read what they do NOT cover.**
`tools/{captest,ktest,captest-arm64,ktest-arm64,captest-microvm,test-fdt,vblktest-arm64}.sh`.
The boot tests exercise a freestanding init — so no dynamic linking, no musl, no
threads beyond the explicit clone cases, and no filesystem other than the ext2
test image. Everything outside that envelope is untested at runtime.

**Reproduce arithmetic findings as host PoCs.** `test/audit-poc/` has the pattern:
lift the arithmetic verbatim, run pre-fix and post-fix logic side by side, and
include a companion assertion that normal behaviour is unchanged (so a "fix" that
rejects everything fails too). Plain `cc`, no cross toolchain. This turns
"I believe this overflows" into "here is it overflowing".

---

## 4. Coverage map

**Well covered last time — go in only with a specific hypothesis.** syscall/uaccess
boundary, MM/VMA, ELF/exec, ext2, FAT, GPT, the block layer, virtio-blk/NVMe/AHCI,
scheduler/SMP/PCB lifetime, signal delivery/sigreturn, procfs. These got real
scrutiny and 41 fixes. Re-reading them from scratch is the lowest-yield thing you
can do.

**Barely or never covered — start here.**

| Area | LOC | Why it matters |
|---|---:|---|
| `drivers/xhci.c` | 3371 | Largest single file in the tree. Touched by the last audit only through a procfs generator (H7). Parses descriptors from attacker-controlled USB devices. |
| `fs/initrd.c` | 879 | Parses bootloader-supplied data before any capability exists. |
| `cap/cap_policy.c` | 689 | **Parses `/etc/aegis/caps.d/*` — the files that decide what authority a binary gets.** A parser bug here is a capability grant bug. The last audit checked the *model*, not the *parser*. |
| `tty/pty.c` | 710 | Called "guarded" on refcounting alone. The line-discipline and ioctl surface was not examined. |
| `arch/arm64/fdt.c` | 631 | Device-tree parsing; firmware/bootloader-controlled input. |
| `arch/x86_64/acpi.c` | 596 | Firmware tables. Same threat model as FDT. |
| `net/epoll.c` | 471 | Declared guarded in one paragraph. |
| `drivers/hda.c`, `virtio_gpu.c`, `virtio_input.c`, `virtio_9p.c`, `virtio_vsock.c`, `virtio_console.c`, `virtio_balloon.c`, `virtio_pmem.c` | ~1500 | Every one consumes device-controlled data. Only virtio-blk and the shared `virtqueue.c` were audited. |
| `core/limine.c`, boot path | 146 | Bootloader handoff. |
| `net/tcp.c` state machine | — | Header *parsing* was audited; the state machine, retransmit and window handling were not. |
| DHCP/ARP clients | — | Parse network-controlled input. |
| **The LoricaOS userland** | — | `vigil` (init), the installers, coreutils, `herald`. **Entirely unaudited, in a different repo.** `vigil` is PID 1 and holds the widest capability set on the system. |

---

## 5. Subagent roster

Spawn these as separate agents with genuinely different mandates. The point of
distinct attitudes is that each one's blind spot is another's obsession — do not
homogenise them into "look for bugs in area X". Each gets: this brief, its own
mandate, and instructions to report in the format in §6.

Run them in two waves. **Wave 1** (1–2) produces artifacts the others depend on.

---

### Wave 1

**A1 — The Toolsmith.** *Attitude: nothing is true until a machine agrees.*
Runs §3 in full before anyone else starts: both sanitizers on both arches, the
whole config matrix, all harnesses. Deliverable is a report of every crash,
sanitizer splat, build failure and silently-disabled-check found, plus a written
statement of what the harnesses do **not** cover, which A5–A9 will rely on. Files
no source-reading findings. If a sanitizer run is clean, that is itself a
reportable result — say so plainly rather than padding.

**A2 — The Skeptic.** *Attitude: the previous audit is a suspect, not a source.*
Sole job is to re-derive the previous audit's "Audited and found GUARDED"
section from current source. Every claim in it is a hypothesis to be disproved.
Pay particular attention to any claim containing "complete", "every", "all", or
"no". The exception-table completeness claim already has one known exception —
find the others. **Do not read the findings sections first**; you are checking
the parts nobody re-checks, and knowing what was found will bias you toward
believing the rest.

---

### Wave 2

**A3 — The Integer Pedant.** *Attitude: every arithmetic operation is guilty.*
Every cast, narrowing conversion, shift, subtraction that could underflow, and
multiplication that could overflow. This mandate produced both CRITs last time.
Two specific patterns that already bit this codebase: (a) a 64-bit user value
narrowed to 32 bits *before* being range-checked; (b) a signed accumulator fed
from attacker-controlled digits. Cross-reference A1's UBSAN output — but do not
stop where UBSAN stops, since it only reports paths actually executed.

**A4 — The Concurrency Adversary.** *Attitude: two CPUs, worst possible interleaving.*
Lock ordering, what is held across what, and specifically: anything that calls a
function pointer, allocates, frees, or does a TLB shootdown while holding a lock.
`IF=0` masks interrupts on *one* CPU and is not mutual exclusion — the last audit
found three bugs whose root cause was treating it as such. Also: every place a
pointer into a shared table outlives the lock that protected it.

**A5 — The Capability Lawyer.** *Attitude: the model is the product; everything else is plumbing.*
Per `SECURITY.md`, a capability bypass is the highest-severity class of bug here.
Hunt confused deputies, authority laundering across `exec`/fd-passing/inheritance,
and TOCTOU between a policy decision and its use. **Start with `cap_policy.c`'s
parser**, which decides grants from on-disk files and was never examined. The
known-and-accepted TOCTOU between `cap_path_is_protected` and `O_CREAT` is
documented in that file — determine whether it is still merely theoretical.

**A6 — The Hostile Device.** *Attitude: the hypervisor, firmware and every peripheral are the enemy.*
Everything read from MMIO, DMA'd memory, a descriptor ring, a device register, an
ACPI table or a device tree is attacker-controlled. Aegis is a microVM kernel, so
a malicious host is squarely in scope. Priority: `xhci.c` (3371 lines, essentially
unaudited), the seven un-audited virtio drivers, `acpi.c`, `fdt.c`. Note that
device-supplied indices reaching an array were already a real bug here (H11).

**A7 — The Lifetime Tracker.** *Attitude: everything is freed twice and used after.*
Refcounts, teardown ordering, fd/socket/pty/memfd slot reuse, and the exit/reap
path. Ask of every object: who frees it, what else can hold a pointer at that
moment, and can its slot be reallocated to a different object while a stale
reference survives. The `unix_socket.c` linger comment is a good example of this
class being hit for real.

**A8 — The Exhauster.** *Attitude: I do not need to corrupt memory to end you.*
Unbounded loops, allocation without a ceiling, and any per-page or per-entry walk
driven by a user-supplied length running with interrupts disabled. Also fixed-size
tables: what happens at the limit, and is exceeding it *silently* degrading rather
than failing? That exact shape was `vfork_freeze`'s bug and it was filed LOW.
Include exhaustion of pids, fds, VMA slots, ext2 fd pool slots, and virtio
descriptors.

**A9 — The Userland Auditor.** *Attitude: the kernel is not the attack surface, the system is.*
Scope is the **LoricaOS repo**, not this one. `vigil` is PID 1 with the broadest
capability set on the box; the installers run with `DISK_ADMIN` and `INSTALL`;
`herald` unpacks downloaded packages. None of it has ever been audited. Start with
what parses untrusted input and what holds capabilities it does not need for the
whole of its lifetime.

---

## 6. Deliverable format

Match the 2026-07-30 document — it was genuinely good — with these changes:

- **Every finding gets a `Trigger:` line** with a concrete input or sequence, or
  the explicit label `UNTRIGGERED — would require <X>`.
- **Every proposed fix gets a `Breaks:` line** naming what legitimate behaviour it
  would reject, or `Breaks: nothing (argued: <why>)`.
- **Every finding gets `Testable: yes/no`** — whether it can be caught by the boot
  suite, a host PoC, or a sanitizer. This directly drives whether the fixing
  session can prove the fix.
- **Add a `Tooling results` section** up front: what A1 ran, what it found, what
  was clean. A clean sanitizer run on a subsystem is real evidence and belongs in
  the record.
- **The "found guarded" section must state who verified it and against what
  commit**, so the next audit knows whether to re-derive it.
- **Add an explicit `Not examined` section.** List it. The gap you name is
  cheaper than the gap someone finds later.

Do not include a fix-order hit list ranked by severity alone. Rank by
`reachability × impact × confidence-in-the-fix`, because a CRIT whose fix is
uncertain is worse to start with than a HIGH whose fix is a one-line bound.

---

## 7. Anti-goals

- **Do not re-audit ext2/FAT/GPT/mm/exec line by line.** Forty-one fixes just
  landed there. Go in with a hypothesis or stay out.
- **Do not report style, naming, or missing `const`.** This is a security audit.
- **Do not trust a comment.** `uaccess_user.h` confidently documented the exact
  opposite of the truth for however long, and that comment is *why* the
  ignored-`copy_from_user` bug looked safe to everyone who read it. Comments are
  claims to verify, and a wrong one is itself a finding.
- **Do not pad severity to look productive.** The previous audit's credibility
  comes from its LOW section being genuinely low. One inflated CRIT costs more
  trust than ten honest LOWs.
