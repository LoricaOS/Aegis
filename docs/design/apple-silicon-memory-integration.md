# Next native gate: existing PMM/VMM/KVA

Status: **native PMM/VMM/KVA memory checkpoint passed on J514s/T6030**.
The real-kernel `wb-qr2` shared-init checkpoint passed natively. Its Image
and ELFs are preserved in `build/applekernel/shared-init-passed/`, and USB
profile 5 remains pinned to that known-good Image.

## Target and ownership boundary

Reach a new `memory-complete` checkpoint after the existing PMM, ARM64 VMM
and KVA initialize, perform bounded allocation/map/write/readback/release
checks, then halt before interrupt controllers, timers, AP startup, devices,
filesystems or processes.

Do not admit V4's general candidate list yet. The initial pool is an
explicit 8 MiB, page-aligned arena in the **loader Image's owned BSS**,
outside the real kernel ELF footprint, loader tables/stacks and metadata.
Its full span is included in the Linux Image `image_size` supplied to
m1n1. It is a deliberate part of our loaded allocation, not guessed free RAM
or reclaimed firmware.

The normal kernel-image reservation therefore stays intact; do not teach
PMM to unreserve arbitrary parts of the kernel. Validate the handoff and
publish only the designated arena as usable RAM. Keep the tested shared-init
payload separate from the new memory profile.

## PMM foundation implemented

The shared PMM now selects a nonzero bookkeeping origin only when no whole
usable page fits its normal bootstrap window. Conventional low-RAM boots
retain origin zero. Bitmap and dense refcount indices share this origin;
all public allocation addresses and `pmm_ram_max_page()` remain absolute.

- The arena near 1 TiB does not require a bitmap/refcount array for the
  preceding physical-address hole.
- `<4 GiB` DMA allocators clip against the **physical** boundary and return
  OOM when no such RAM exists. A high origin never manufactures low pages.
- Reservations round outward; admitted pages/releases round inward.
- Addresses below the origin, holes and physical zero cannot be freed or
  refcounted as managed frames.
- Late bitmap activation reapplies the same platform/kernel reservations,
  including ones beyond the previous bootstrap window.
- Wrapping map/reservation metadata refuses rather than publishing a partial
  free pool.

`test/pmm_base_test.py` compiles the complete production allocator with host
boot-map/IRQ/KVA mocks and a substituted linker end-symbol binding. Two test
methods cover nine valid scenarios and two rejection scenarios, including
200 deterministic page-set models, high/low bases, exact DMA boundaries,
allocation exhaustion/reuse, 16-bit refcount saturation, late growth, holes,
rounding, and reservations outside the original window.
These tests never dereference physical memory. Native PMM operation is not
established by them.

ARM64 and x86 full-kernel regression boots passed after the PMM change; evidence
paths are `build/evidence/apple-pmm-arm64-regression.log` and
`build/evidence/apple-pmm-x86-regression.log`.

## Implemented integration

1. **Separate memory build and arena handoff.** `Makefile.applememory` builds
   under `build/applememory/`, without overwriting profile 5. It carries/copies the explicit arena,
   kernel physical placement and validated framebuffer description into
   image-owned kernel state before retiring loader addresses.
2. **Bootstrap access to the arena.** Establishes a WB, RW/XN mapping for the
   arena with proper break-before-make and cache maintenance. The existing
   kernel's early physical-address accessor can then reach its page-table
   allocations. No NC/WB alias may remain.
3. **Publish architecture memory state.** Sets the real physical slide and
   admits only the arena. It does not invoke the legacy DTB RAM-node fallback
   or invent a PL011 UART for Apple.
4. **Exact VMM bootstrap policy.** Reuses the existing table allocator/walker
   and runtime VMM APIs, with a separate boot mapping policy for this profile.
   Preserves RX text, RO/XN constants and RW/XN data. Direct maps only the
   admitted arena plus the validated Device framebuffer, not a min-to-max RAM
   span or broad MMIO window. No writable code alias is created. The live
   MAIR palette stays consistent through the handover.
5. **Coherent table/console handover.** New page tables are WB arena pages:
   table-walk cacheability/shareability must agree. Switch to the new TTBR1
   and empty TTBR0 without changing the executing kernel's memory type.
   Rebase the boot console to its new framebuffer mapping before the first
   post-switch printk; do not lose diagnostics in the transition.
6. **KVA and bounded real checks.** KVA's data, physical and MMIO mappings now
   explicitly request NX through the shared abstract mapping API. It warms required
   mapping metadata, then verify page ownership, mapping attributes,
   write/readback and allocation/release accounting. Test low-DMA refusal
   on the high-only pool. Emit a QR report at each boundary and a final
   `memory-complete` only after all checks pass.

This gate does not grant ownership of the rest of DRAM. Full memory intake
still needs firmware/loader lifetime review before broadening the pool.

## Checks and evidence

```
make -f Makefile.applememory check
```

This runs the PMM host model, actual handoff validator/mapping policy with
host linker/architecture mocks, and five real QEMU executions of the memory
profile: low and >1 TiB placements from incoming EL1/EL2, plus a PAN-capable
Cortex-A76 case at a supported low address.

The handoff model checks valid mapping construction and 16 invalid inputs,
including missing/bad magic, wrapping/outside ranges, arena/image overlap,
wrong size/alignment, and invalid framebuffer metadata. Invalid cases must
stop before architecture RAM admission.

Execution checks cover:

- Exactly 2,048 initially free pages in the explicit 8 MiB arena.
- PMM allocation, page write/readback, release accounting, and honest DMA
  bounds/refusal.
- Real VMM root replacement, coherent WB/shareable table walks, unchanged
  MAIR, MMU/D-cache-on/I-cache-off state, DAIF masked and empty TTBR0.
- Post-handover uaccess fault/fixup and working rebased framebuffer output.
- Existing KVA initialization, late PMM refcount storage, allocation of three
  pages, full-page patterns, release, reallocation and restored free counts.
- Independent full final-table walks: exact kernel/arena/framebuffer and
  permanent refcount-storage mappings; no blocks, holes, MMIO windows,
  writable executable pages, EL0 access, or writable code aliases.
- Every table/refcount-storage frame belongs to the pool and matches the
  production bitmap. Final free count equals initial pool minus precisely
  those retained metadata frames.
- Independent decoding of the final QR, including actual pixels at native
  display geometry, and unchanged framebuffer guard/outside pixels.
- Emitted cache-maintenance instructions use CIVAC, not write-requiring IVAC.

Evidence: `build/evidence/apple-memory-kernel-check.log` and
`build/applememory/loader/memory-{qr.json,qr.pgm,transcript.txt}`.
The existing memory mapping/COW/refcount/authority host model also passes.

Shared-code regressions passed again after the VMM/KVA work:

- `make -f Makefile.arm64 test`, local edk2 firmware, `QEMU_TIMEOUT=45`:
  capability/syscall boot and no-userland smoke boot.
- `make CC=gcc LD=ld NM=nm OBJCOPY=objcopy test`, `QEMU_TIMEOUT=45`:
  x86 capability boot and Limine/Multiboot2 smoke boots.

Logs: `build/evidence/apple-memory-{arm64,x86}-regression.log`.

## Native gate

Use explicit `--check-memory` / `--arm-memory` with
`tools/apple-probe-usb.sh`. They select the separate owned-memory profile 6;
default modes, V4 metadata intake and the passed profile-5 shared-init Image
stay separate. Gzip transport, pinned loader/DTB hashes, target identity,
global boot lock and one-shot RAM-only handoff checks remain enforced.

Qualified Image SHA256:
`8982df1254bd3f2b729eefb6c7e3a8782fa7e4a303f0f59fc3b6e5be52e9b269`.

The QR uses schema `aegis.apple.qr1`, build `mem-qr1`, with additional
`arena`, `arena_bytes`, `free`, and `root` fields. Before the VMM switch,
`root` is the prepared target; afterward it is the active root. Before PMM
initialization `free` is zero/not-yet-measured. Report storage is fixed at
640 bytes, still fitting the fixed version-20/M QR.

Only `phase: memory-complete` establishes this goal. `shared-complete` is an
intermediate milestone in this build. The phase sequence also includes
`memory-handoff`, `memory-before-pmm`, `memory-before-vmm`,
`memory-vmm-switch`, `memory-vmm-live`, and `memory-before-kva-test`.
Any explicit refusal emits `memory-refused`; fatal kernel faults retain the
existing `kernel-fault` report. No automatic retry/reboot follows.

Coordinate a fresh power-off and confirm the armed listener before booting
the existing Fedora debug entry. A USB disconnect alone never establishes
the memory result; use the final native QR report.

## Native result

Run `build/applememory/loader/usb-20261113T062858Z-101459` used the qualified
Image SHA256 above. The owner scanned:

```json
{"schema":"aegis.apple.qr1","build":"mem-qr1","phase":"memory-complete","el":"0x0000000000000001","sctlr":"0x0000100030550985","pc":"0xffffffff80207f54","sp":"0xffffffff80283f00","esr":"0x0000000096000004","far":"0x0000000050000000","elr":"0xffffffff802015a8","attempts":"0x0000000000000001","status":"0x0000000000000000","value":"0x0000000000000001","lock":"0x0000000000000000","arena":"0x0000010008c9b000","arena_bytes":"0x0000000000800000","free":"0x00000000000007e4","root":"0x0000010008c9b000"}
```

The real kernel completed all checkpoint checks on the Mac:

- EL1, MMU and D-cache on, I-cache off.
- Existing PMM allocation/write/readback/release and absolute low-DMA bounds.
- Existing VMM root handover, empty TTBR0, exact kernel/arena/framebuffer
  mappings, protected code/data and post-handover uaccess fault return.
- Existing KVA and late refcount initialization, three-page write/readback,
  release/reallocation and restored free-page accounting.
- Working framebuffer/QR output after the address-space switch.

The active root is `0x0000010008c9b000`, inside the admitted arena beginning
at the same address. The 8 MiB pool contains 2,048 pages; `0x7e4` means
2,020 pages free after tests and 28 retained pages (114,688 bytes), consistent
with the permanent page-table/refcount metadata. Native full-table/bitmap
readback was not performed; the detailed independent walks remain QEMU
evidence, while the native checkpoint performs its own ownership,
attribute, translation and accounting checks before emitting completion.

ESR/FAR/ELR match the deliberate post-handover uaccess test at `0x50000000`
and its registered fixup, not a new panic. No firmware region was reclaimed.
The rest of DRAM, interrupts/timers, AP startup, drivers, filesystems and
userland remain outside this qualification. This is a bounded native
memory-management success, not a full-memory stress test or LoricaOS boot.

The passed Image and both ELFs are preserved under
`build/applememory/memory-passed/`. USB profile 6 reads that pinned Image,
so subsequent work cannot silently replace the successful memory checkpoint.
