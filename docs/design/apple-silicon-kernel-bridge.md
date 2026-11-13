# Apple native bridge to existing ARM64 initialization

Status: **native real-kernel shared-init checkpoint passed on J514s/T6030**.
Build `wb-qr2` completed native shared initialization; the earlier cache-off
and cache-transition stops are retained below as historical evidence.
This is a real-kernel checkpoint build, not another reimplementation of its
shared initialization and not a usable OS boot.

## Why stop before the allocator?

The normal ARM64 kernel expects its higher-half linked VA and Limine-style
memory setup. The native Pi path also assumes Pi hardware and uses the legacy
RAM-node parser; neither is an Apple entry path.

The shared PMM bootstrap bitmap covers physical addresses below 4 GiB.
J514s/T6030 RAM begins near 1 TiB. V4's candidate list cannot simply be
passed to that allocator: ownership remains unqualified and none of those
pages fit the bootstrap window. Increasing a bitmap to cover the address
hole is not a sound long-term fix. PMM/VMM high-base support and explicit
firmware/loader ownership review remain follow-up work.

The first bridge therefore conveys **no usable-memory authority** and
cannot fall through into PMM, VMM replacement, interrupts, timers, SMP AP
startup, device discovery, filesystem mounts, or process creation.

## Build and flow

```
make -f Makefile.applekernel check
```

1. Build the real ARM64 kernel source/object set with
   `APPLE_CHECKPOINT=1` into `build/applekernel/kernel/`. Default builds
   remain under `build/arm64/`; Pi, x86 and Lorica images are not replaced.
2. Link at the existing kernel VA `0xffffffff80200000`, with page-aligned
   RX text, RO/XN constants, and RW/XN data/BSS. Include the normal exception
   table, symbol table and an image-owned 32 KiB kernel stack.
3. Pad the flat kernel through its full BSS footprint and embed it in a
   RAM-only bridge Image under `build/applekernel/loader/`. This is all
   part of the loaded, owned image; no free RAM is selected or probed.
   For USB transport only, gzip that complete bridge Image using the pinned
   stage 2's existing compressed-Image support. Stage 2 reserves a fresh
   aligned destination for the decompressed footprint. The kernel and
   bridge bytes are unchanged by this packaging.
4. Reuse the native-tested entry/simplefb and V3 EL1/4 KiB identity-map
   code. Add a bounded TTBR1 table pool mapping only the embedded kernel.
   Text is RO/executable; constants RO/XN; data RW/XN. Kernel high mappings
   are Normal WB (MAIR Attr2); their entire low NC blob alias is removed
   before activating them. Loader code/data, stack and tables remain NC;
   framebuffer stays Device. DAIF stays masked and zero VA stays unmapped.
   After bounded cache maintenance on the owned kernel span, D-cache is
   enabled; I-cache remains off. No WB/NC aliases are retained.
5. Enter `apple_kernel_start` at its linked VA and switch onto the kernel's
   own higher-half stack. Initialize the same validated boot framebuffer
   renderer as the existing kernel's output sink (no PL011 MMIO).
6. First run a bounded halfword exclusive-operation/initial-lock check through
   lock-free framebuffer output. Failure halts without calling a shared lock.
   Then call the existing `kernel_main_arm64`. Its existing per-CPU setup,
   PAN initialization, exception vectors and uaccess self-test run. The
   shared capability-core initialization announcement also runs, without
   granting any process capabilities or creating a process.
7. Require the uaccess check to succeed, save a fixed register-state report,
   print `[APPLE] SHARED INIT CHECKPOINT`, then halt before any allocator or
   platform device initialization.

The explicit checkpoint changes output routing only in that build.
The regular ARM64 `uaccess_selftest` now returns success/failure; existing
normal callers still retain their previous logging behavior.
No capability checks, ambient-authority rules or firmware reservations change.

This is a **one-way native handoff**, not the resident-m1n1 debug guest.
USB disconnect after vectoring remains expected. Installed boot entries,
ESP, disks and firmware are not changed.

## Evidence and qualification limits

`test/apple_kernel_test.py` executes the unchanged bridge and real kernel:

- Incoming EL1 and EL2, each with low and >1 TiB load addresses.
- An additional Cortex-A76 run exercises PAN (its 40-bit PA limit prevents
  using it for the >1 TiB case; high cases use Cortex-A72).
- An ephemeral test-only image with a nonzero initial atomic-probe value
  refuses before per-CPU initialization or any shared logging. All five
  positive cases also verify the atomic-preflight report.
- Verifies the kernel checkpoint PC/SP are higher-half, EL1/MMU/cache/DAIF
  state, real vector-table address, TPIDR/per-CPU initialization, and the
  existing uaccess fault-fixup result.
- Reads the real kernel printk ring and framebuffer transcript, and checks
  framebuffer guards.
- Independently walks every actual TTBR1 leaf, verifying exact physical
  placement, complete image coverage, no extra high mappings, no EL0
  access, Normal WB attributes, and W^X/RO/XN permissions. Walks TTBR0 to
  verify the low alias is absent for every kernel page.

Evidence: `build/evidence/apple-kernel-check.log`.
The normal `make -f Makefile.arm64 test` also passes its capability/syscall
and no-userland smoke boots with the locally extracted edk2 firmware and
`QEMU_TIMEOUT=45`; evidence:
`build/evidence/apple-kernel-arm64-regression.log`.

The first compressed Mac run reached higher-half C entry but stopped before
shared-init output (details below). QEMU is evidence for the shared code,
not M3 qualification. Native PAN and the shared fault-return path must
still be observed. This checkpoint deliberately
does not establish that the allocator, scheduler or any device works on Apple.

## Physical test

Use `tools/apple-probe-usb.sh --check-kernel <linux> <python>` to prepare
the payload without target requests. Only explicit root `--arm-kernel`
waits for the existing Fedora USB-debug entry and sends one payload under
the shared boot lock. Helper profile 5 means the real-kernel checkpoint;
default modes and V2/V3/V4 remain separate.

Qualified Image SHA256:
`03f5b60d1fcc3e6926253aafc6b23ea2b1c73b10236de17e871aaebc7ee38a2e`.

After a fresh power-off, arm and confirm the listener before asking the owner
to boot Fedora (not DH). Success requires the final real-kernel checkpoint
screen, including the uaccess OK line; a USB disconnect is not success.
No retry, firmware call, automatic reboot or fallback follows a failed run.

### First native attempt: refused before upload

Run `build/applekernel/loader/usb-20261113T043409Z-89989` passed the target
identity and payload checks, but `chainload.py` refused the uncompressed
packed image with `Image overlaps live Stage 1 heap`. This happened before
image staging/upload, firmware-block copies, vectoring or kernel execution.
It is a loader preflight refusal, not the expected post-vector USB loss
and not evidence about the kernel entry.

Do not weaken the overlap guard or relocate into guessed free memory.
Only profile 5 packaging now uses a gzip-compressed, fully padded Image.
V2/V3/V4 packaging remains raw and their Image hashes remain unchanged.

Offline prepared run `build/applekernel/loader/usb-20261113T043618Z-90505`
has a `0x46f34c`-byte packed transfer, including a `0x38d85`-byte gzip
stream that expands to the exact `0x4a9000`-byte padded bridge Image.
This is smaller than the raw image-only copy span rejected above.
The original Stage 1 placement guards remain authoritative for each boot.

`test/apple_kernel_payload_test.py <linux> <prepared-run>` compiles the
pinned upstream `tinfgzip.c`, `tinflate.c` and `crc32.c` as a host library
without modifying them. It checks the actual packaged stream against all
uncompressed bytes, both known-length and inline/zero-length decoder modes,
exact consumed length and destination guard bytes. Both modes passed.
The manifest records encoding, compressed size and padded Image SHA256.
No target requests or native retry were made for this packaging validation.

### Compressed native attempt: higher-half entry, not shared-init success

Run `build/applekernel/loader/usb-20261113T043844Z-90616` used the previous
Image SHA256
`c345d79d84b62da5a12a5d11ecaa8e3421261146dd25d3ed808de489b318fe30`.
It passed the placement guards, copied/uploaded once and vectored. The
owner confirmed the final visible line was
`APPLE CHECKPOINT - NO ALLOCATOR OR DEVICES`, with no subsequent SMP line.

This establishes higher-half kernel entry/stack/C/framebuffer execution,
not successful shared initialization. Do not record the five QEMU shared-init
passes as native success. No native allocator or device initialization ran.

Disassembly puts the first shared log after per-CPU stores and TPIDR setup.
That log's ticket lock uses an unbounded halfword `ldxrh`/`stxrh` retry loop.
Exclusive operations on the current NC mappings/cache-off state are a
hypothesis, not a confirmed cause; incorrect initial lock state is another.

The next revision adds a read-only snapshot of the initial printk lock,
then at most 128 attempts of the same relaxed halfword exclusive fetch-add
on an image-owned test word. It prints initial/final values, attempts and
store status with the existing lock-free framebuffer renderer. Unexpected
state or unsuccessful stores halt at report stage 3 before shared init;
passing preflight continues through the unchanged shared locks.
It does not bypass a lock, enable caches, change mappings or grant authority.

### Cache-off exclusive-operation stop and cache-on revision

Run `build/applekernel/loader/usb-20261113T044443Z-91425` used Image SHA256
`ce67054bee62f9e5aa650dc7a3e7d30684a54568708f1c555b7f8817a901c6d1`.
The owner observed `BEFORE SHARED INIT - BOUNDED ATOMIC CHECK`, initial
printk lock owner/next zero, and exclusive probe initial value zero, then
no attempt/status/final-value lines. This is not evidence for 128 returned
store failures: it stops inside the exclusive sequence or its exception path.
The precise instruction/exception state was not captured.

The next revision supplies normal cacheable kernel mappings rather than
bypassing shared locks:

- Keep native-tested V3 low setup unchanged, then require M=1/C=0/I=0
  and MAIR=`0x44` before the bridge transition.
- Map the owned kernel at its high VA with Normal WB attributes and the
  same strict permissions. Remove every kernel-blob identity PTE after
  checking it against the expected owned RO/XN mapping. No WB/NC alias
  survives, and no guessed RAM or MMIO is mapped.
- The pinned m1n1 `memory.c:mmu_shutdown` disables MMU/caches and performs
  all-cache clean/invalidate. Aegis subsequently wrote with caches off.
  Derive the cache-line step from CTR_EL0, bound it, invalidate only the
  owned kernel span by its new high VA, and complete maintenance/stores
  with DSB before setting SCTLR.C. No set/way operation or maintenance
  on live firmware/device memory is introduced.
- Keep I-cache off, DAIF masked, loader/table accesses NC, table walks
  noncacheable and framebuffer accesses Device. Execute the same bounded
  atomic preflight before any shared initialization; print SCTLR as well.

Six updated QEMU cases pass, including PAN, >1 TiB placement, exact WB
permissions, absent low aliases and the refusal case. QEMU does not model
the M3 cache/exclusive behavior; a native result is still required. This
revision does not establish allocator ownership or interrupt/device support.

### Latest cache-on attempt: stopping point not yet captured

Run `build/applekernel/loader/usb-20261113T045509Z-92373` used Image SHA256
`faefef0f06be59953f43dc625b6dfef5fd6bf8b99cb314bf895eceb758b8b729`.
It passed placement/upload and vectored once. The owner reported seeing the
old V3 EL1/bounded-map heading and confirmed that the final shared-init
checkpoint was absent. The exact final line/register state was not captured.
Do not infer that D-cache-on exclusives failed from the older cache-off run,
or record this run as native shared-init success.

## Local QR reports

The next payload replaces the ambiguous V3 headings with
`AEGIS APPLE KERNEL BRIDGE - PREPARING EL1` and
`APPLE BRIDGE - EL1 / BOUNDED 4K MAPPING`. Standalone V3 remains unchanged.
The bridge no longer announces a deliberate halt before continuing into
the real kernel.

A separate right-hand QR box displays plain UTF-8 JSON, not a URL. Scanning
needs no network or upload; copy the decoded text into the thread. Text
output remains available. Small displays with no safe space for the QR
retain text only.

The JSON schema is `aegis.apple.qr1`, current build label `wb-qr2`
(the first QR payload was `wb-qr1`). Fields:

- `phase`: last report point reached; emitted synchronously before each
  risky operation so a hang can leave the preceding report visible.
- `el`, `sctlr`, `pc`, `sp`: current EL, control state, **reporter** PC and SP.
- `esr`, `far`, `elr`: current exception-register snapshots. These can be
  stale, including the expected uaccess-fixup fault on a successful boot.
  Interpret them as fault context only with `bridge-fault`/`kernel-fault`.
- `attempts`, `status`, `value`, `lock`: included once atomic preflight
  begins. At `atomic-before`, attempts is zero and status all-ones means
  **not attempted**, not failure.

Important phases are `bridge-entry`, `bridge-el1`, `bridge-map-ready`,
`bridge-before-cache`, `bridge-alias-cleared`, `bridge-high-map-ready`,
`bridge-lines-invalidated`, `bridge-before-kernel`, `kernel-entry`, `atomic-before`,
`atomic-passed`, `atomic-failed`, `shared-before-percpu`, `shared-before-pan`,
`shared-before-vectors`, `shared-before-uaccess`, and `shared-complete`.
Only `shared-complete` establishes the intended checkpoint.

Implementation uses Project Nayuki's MIT-licensed C QR generator at revision
`bcfe1b018cec5f1f91b5705eca5bb4cdd34e9f8d`, fetched into ignored build output
by `tools/fetch-apple-qr.py` with exact SHA256 checks on both upstream files.
The upstream algorithms and copyright notice are retained. A clearly marked
freestanding include adapter provides existing-memory operations and
lock-free assertion failure; its byte-wise helpers also work before the
MMU is enabled. License: `docs/licenses/qrcodegen.txt`, copied into each
prepared profile-5 run as `LICENSE.qrcodegen`.

Encoding uses fixed BSS buffers, a 512-byte bounded report, fixed QR version
20, medium error correction and mask 0. No allocator, shared lock, interrupt,
device discovery, filesystem or firmware protocol is used. The renderer
clips to the validated framebuffer and includes a four-module white quiet
zone. On the Mac's 3024×1964 geometry the box is 840×840 pixels to the right
of the text panel. Normal memory permissions and boot/cache policy are
unchanged from the preceding cache-on candidate.

`make -f Makefile.applekernel check` passes all six execution cases. An
independent `zbarimg` decoder reads every final success/refusal matrix; the
native-geometry case also decodes the **actual framebuffer pixels**, checks
all modules/quiet-zone pixels against the encoded matrix, and compares the
decoded JSON byte-for-byte with the report. Framebuffer guards and all
pixels outside the text/QR boxes remain checked.

Evidence: `build/evidence/apple-kernel-check.log`,
`build/applekernel/loader/checkpoint-qr.{pgm,json}`.
The normal ARM64 capability/syscall and smoke boots pass again in
`build/evidence/apple-qr-arm64-regression.log`. V2/V3/V4's 47 execution cases,
five mapper host methods and 22 intake host methods also pass again in
`build/evidence/apple-qr-probe-regression.log`; their Image hashes are unchanged.
The native scan below establishes readability for `wb-qr1`; the current
`wb-qr2` cache-transition reports still require a native run.

### First native QR report and cache-maintenance correction

Run `build/applekernel/loader/usb-20261113T051813Z-94835`, Image SHA256
`dac3bbbeade4eb3db6df4cb35cad38ce0354dae206103f48812031b2609da99f`,
produced a QR report which the owner successfully scanned:

```
build: wb-qr1
phase: bridge-before-cache
EL: 1
SCTLR: 0x0000100030d50981
reporter PC: 0x0000010007c04244
reporter SP: 0x00000100080b1ea0
ESR / FAR / ELR: 0
```

This confirms native QR rendering/scanning and localizes that run to the
loader's cache-transition section, before real-kernel entry or shared locks.
SCTLR has M=1/C=0/I=0 at the report point. Zero exception snapshots here do
not establish what happened afterward. The precise stalled operation was
not captured, and native shared-init success remains unproven.

The audit identified an architectural bug in that interval: `DC IVAC`
requires write access but was applied to high kernel code/constant mappings
which are deliberately read-only. QEMU/TCG passing those operations is not
permission-checking evidence. Arm's instruction reference:
https://developer.arm.com/documentation/ddi0601/2025-12/AArch64-Instructions/DC-IVAC--Data-or-unified-Cache-line-Invalidate-by-VA-to-PoC

Build `wb-qr2` uses `DC CIVAC` instead, without weakening RO/W^X permissions
or introducing writable code aliases. It still operates only on the owned
kernel span, with m1n1's clean/invalidate handoff and uncached loader stores
as the prerequisites. The test also checks emitted bridge instructions for
CIVAC and absence of IVAC, because TCG does not establish this native behavior.

The added QR markers separate:

- `bridge-alias-cleared`: low blob PTEs cleared; register/TLB switch next.
- `bridge-high-map-ready`: register/TLB group returned; line maintenance next.
- `bridge-lines-invalidated`: line-maintenance loop returned; completion
  barrier/cache enable next.
- `bridge-before-kernel`: cache-enable sequence returned; kernel jump next.

QR drawing itself finishes with a barrier, so these reports identify the
last point reached, not a guarantee that every following barrier returned.
Six execution cases and independent framebuffer decoding pass again.
This corrects the maintenance instruction but does not prove it caused the
observed Mac stop; a new native run is required.

## Native shared-init success

Run `build/applekernel/loader/usb-20261113T052610Z-96163` used Image SHA256
`03f5b60d1fcc3e6926253aafc6b23ea2b1c73b10236de17e871aaebc7ee38a2e`.
The owner scanned the following completed native report:

```json
{"schema":"aegis.apple.qr1","build":"wb-qr2","phase":"shared-complete","el":"0x0000000000000001","sctlr":"0x0000100030550985","pc":"0xffffffff802081b4","sp":"0xffffffff80282f50","esr":"0x0000000096000004","far":"0x0000000050000000","elr":"0xffffffff802015a8","attempts":"0x0000000000000001","status":"0x0000000000000000","value":"0x0000000000000001","lock":"0x0000000000000000"}
```

This confirms higher-half real-kernel execution/stack, EL1, MMU and D-cache
on with I-cache off, successful exclusive update on the first attempt,
and completion of the existing per-CPU/PAN/vector/uaccess initialization
path. No shared lock was bypassed. The checkpoint requires the existing
uaccess self-test to return success before completion.

ESR/FAR reflect the deliberately faulting read at `0x50000000`, not a new
panic. Disassembly confirms ELR `0xffffffff802015a8` is the registered
`arm64_copy_from_user` fixup which returns the uncopied length and restores
PAN. The code reached the final checkpoint after that handler returned.
The QR reporter PC is not the fault PC.

The run still deliberately halted before PMM, VMM replacement, KVA,
interrupt controller/timer, AP startup, device discovery, filesystems or
processes. It is a successful real-kernel initialization milestone, not a
usable LoricaOS boot or permission to allocate V4 candidate memory.

The next goal is existing PMM/VMM/KVA integration with bounded allocation,
mapping, write/readback and release tests on explicitly image-owned RAM.
Keep the native-tested shared-init checkpoint available separately.

The passed Image, loader ELF and real-kernel ELF have been preserved under
`build/applekernel/shared-init-passed/`; the USB helper's profile 5 reads that
pinned Image rather than an in-progress rebuild. This keeps the known native
checkpoint available while the shared PMM and later memory profile evolve.
