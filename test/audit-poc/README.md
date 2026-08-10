# Audit PoCs

Standalone reproductions for the integer-overflow / bounds findings fixed in
this branch, from the 2026-07-30 and 2026-08-01 audits. Each file lifts the arithmetic **verbatim** from the kernel source
and runs it twice — once with the pre-fix logic, once with the shipped fix — so
the bug and its fix are both demonstrable without booting anything.

```
cc -O0 -fwrapv -o poc poc-mm-arch.c   && ./poc
cc -O0 -fwrapv -o poc poc-fs-block.c  && ./poc
```

Host tools only: no cross toolchain, no QEMU. Expected output is a `BEFORE FIX`
block with failing checks and an `AFTER FIX` block with none. The trailing
"N check(s) failed" counts only the BEFORE-FIX arm — it is the *point*, not a
regression. Every case also carries a companion check asserting normal
behaviour is unchanged, so a fix that simply rejected everything would fail too.

| File | Findings |
|---|---|
| `poc-mm-arch.c`  | C1 (`readlink` bufsiz underflow, both halves), H9 (VGA CSI signed overflow), H1 (`mremap` address-space wrap), H3 (`mremap` unbounded scan) |
| `poc-fs-block.c` | C2 (FAT LFN `seq==0`), H4 (ext2 dir `i_size` infinite loop), H5b (BPB geometry underflow), H5c (`cluster_lba` overflow), H8 (GPT bounce overrun) |
| `poc-2026-08-01.c` | C-4 (virtio-GPU `GET_DISPLAY_INFO` geometry overflow defeating its own clamp), C-6 (FAT's install-protected-tree test, incl. the `/binary` vs `/bin` boundary) |

Findings not represented here are structural rather than arithmetic (lock
recursion, capability gating, SMP races, guard pages) and are covered by the
in-tree boot tests in `test/init.c` and `test/exectgt.c` instead — see
`[KTEST] readlink/mremap underflow guards`, `[KTEST] brk (grow/shrink + heap
VMA)` and the procfs cap gate in the exec target.
