# Apple Silicon checkpoint — 2026-11-13

## Remote source checkpoint

Branch: `checkpoint/apple-silicon-20261113` on the configured `origin`
(`https://github.com/loricaos/aegis`), based on
`5e0d385b8b6aa6b8fdda28119e98511d1ee59037`.

This is a work-in-progress safety checkpoint, not a reviewed main-branch
landing or a release. It includes the recovered ARM64 baseline fixes,
Apple diagnostic profiles, shared memory/task initialization changes,
tests, license notice and native milestone records.

The companion LoricaOS source checkpoint uses the same branch name on
`https://github.com/loricaos/loricaos`. The Linux reference worktree is not
part of either checkpoint and must not be swept into these commits.

## Native evidence preserved

J514s/T6030 (Mac15,6, M3 Pro), boot CPU only. These are separate bounded
checkpoints; they are not one full OS boot:

| Milestone | Native-passed Image SHA256 |
| --- | --- |
| Shared init | `03f5b60d1fcc3e6926253aafc6b23ea2b1c73b10236de17e871aaebc7ee38a2e` |
| Owned memory | `8982df1254bd3f2b729eefb6c7e3a8782fa7e4a303f0f59fc3b6e5be52e9b269` |
| One timer FIQ/return | `69f81db8e7841d45ed0c8b018dcbaee19c85245235e62827ae983a854ebc30a7` |
| Cooperative scheduler | `ef68539239d7d5be261471b81974e5c80719a99eb916ee719ff41a2b7d5f1edd` |
| Timer preemption | `9c8f1fffaf2967a8ce6bca5ee5ab80e91274396e3b026c1fae6e9e2a6aa8c0e9` |
| First EL0/isolation | `e357a443634b672ef0cfed1f4ac38e21dbcc893ec6f8518b2b8fceb222a19a18` |

Full reports and qualification limits are in the corresponding
`apple-silicon-{kernel-bridge,memory-integration,timer,scheduler,preemption,userspace}.md`
documents. No target-disk, installed boot-entry or boot-policy edits were
made for these RAM-only runs. Nothing is armed by saving this checkpoint.

## Recovery and current validation

The source was recovered into the newly attached worktree from the previous
isolated checkout. All 219 archived source/evidence/checkpoint files were
hash-verified after restoration. The build configuration and generated
configuration cache were also restored from that checkout.

`make -f Makefile.appleuser check` was rerun successfully after recovery:
host PMM/handoff checks, 13 context/result/fault cases, four real QEMU
EL0/SVC/isolation runs and two intentional rejection mutations. The rebuilt
Image matches the native-passed EL0 hash above byte-for-byte.

Earlier session evidence includes normal ARM64 and x86 capability/no-init
boots, the other Apple checkpoint suites, and native QR reports. These
earlier checks were not all rerun during recovery or checkpoint publication.

## What a Git push does not save

Ignored `build/` output is deliberately excluded from the commit: frozen
Images/ELFs, machine-specific toolchains, logs, rootfs images and the recovery
archive are not uploaded by pushing this branch.

Local recovery archive, relative to the recovered worktree:

`build/recovery/aegis-20261113T164010Z/source-and-passed-artifacts.tar.gz`

Archive SHA256:

`29ba4da47c935ea987f6b38e82542ad05fe9f9c3fe12c64036c2def2ff2e5e77`

Its `manifest.json` records individual file hashes. Frozen native artifacts
remain in each profile's `*-passed/` directory. Back these up separately to
an owner-approved location; this source push is not a remote binary backup.

## Next stage and end-of-session practice

Next: validate and consume legitimate boot entropy, establish the complete
init startup ABI, then explicitly budget/admit RAM-rootfs memory and integrate
the existing init path. No fake entropy, broad DRAM reclaim, ambient authority,
or diagnostic fault-fixup expansion should substitute for those gates.
General kernel preemption, SMP and libc/init/rootfs remain unqualified.

At the end of a session:

1. Record actual tests/native results and remaining limits.
2. Commit scoped work to a named checkpoint branch.
3. Push to the owner-authorized remote and verify the remote ref equals the
   local commit; a local commit alone is not the checkpoint backup.
4. Preserve important ignored artifacts separately, with hashes.
5. Record branch/commit identifiers in the conversation handoff.

Checkpoint publication does not authorize merging or pushing to `main`.
