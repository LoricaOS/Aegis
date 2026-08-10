# tools/fuzz — host fuzzing for the kernel's remote-facing parsers

`eth_rx()` is the only entry point in Aegis that an attacker reaches with **no
capability and no authentication**: any host on the LAN can put arbitrary bytes
into it. Everything else the audits have covered needs at least a local process.
That makes it worth continuous fuzzing rather than one-off review.

These targets build the **real kernel sources** for the host, so libFuzzer,
AddressSanitizer and UndefinedBehaviorSanitizer are all available. Only the
handful of primitives that cannot exist on a host are shimmed (`shim/`).

## Running

Needs `clang` with libFuzzer (the kernel cross toolchain is not used here).

```sh
make                      # builds fuzz_netrx and fuzz_ethrx
make seeds                # writes corpus_ethrx/ (valid ARP/ICMP/TCP/UDP frames)
./fuzz_netrx corpus_ethrx -max_len=1600
```

A crash is written to `./crash-*`; replay it with `./fuzz_netrx ./crash-<hash>`.

```sh
python3 seeds_disk.py .   # corpus_fat / corpus_ext2 / corpus_gpt
./fuzz_fat corpus_fat -max_len=1048576
```

| target | covers |
|---|---|
| `fuzz_netrx` | Ethernet → ARP / IPv4 → ICMP / **TCP** / **UDP**, with a listening TCP port (`tcp_listen(80)`), a bound UDP port, and `tcp_tick()` driven so the connection state machine and retransmit timer are live |
| `fuzz_ethrx` | Ethernet / ARP / IPv4 / ICMP only, L4 stubbed — faster, and isolates a finding to the lower layers |
| `fuzz_fat` | a hostile FAT volume: BPB, FAT chains, directory + LFN reassembly, then a full walk (readdir → open → stat → read → readlink) |
| `fuzz_ext2` | the same walk against a hostile ext2 volume |
| `fuzz_gpt` | the partition table — the first kernel code to touch an attached disk — plus an assertion that every partition it registers lies inside the medium |

The disk targets take the fuzz input **as the disk image**, exposed through a
`blkdev` whose `read` fails past the end of the medium, so a read off the end of
the "device" is an ASan report rather than adjacent heap.

`fuzz_ext2` needs a valid `%gs` base because ext2's recursive lock reads
`percpu_self()->cpu_id`. Rather than fake `smp.h`, the harness points `%gs` at a
real `percpu_t` via `arch_prctl(ARCH_SET_GS)` — Linux userspace keeps TLS in
`%fs`, so `%gs` is free and the genuine kernel header and inline asm work
unmodified.

## What these do NOT cover

Stated plainly, because a clean fuzz run is easy to over-read:

- **No concurrency.** Single-threaded. The *real* ticket spinlocks are linked
  (only `arch_irq_save`/`arch_pause` are shimmed), so the genuine locking code
  runs — but uncontended. Races are out of reach here.
- **No socket layer.** `sock_get`/`sock_wake`/`epoll_notify` are stubbed, so
  nothing drains a connection's receive ring. TCP's inbound state machine and
  ring-fill paths are covered; the drain path is not. UDP's socket-enqueue is
  reached only as far as the `sock_get_nolock` NULL return.
- **No drivers.** Frames are injected at `eth_rx`, below which nothing else
  runs; virtio/e1000/xhci RX paths are untouched.
- **Host memory model.** ASan sees the harness's `malloc`'d frame, so a read
  past the delivered frame is caught precisely — but kva/pmm allocations are
  plain `posix_memalign`, so kernel heap overflows are only caught if they
  cross a host redzone.

## Verifying a harness before trusting a clean run

A probe that never reaches the vulnerable code proves nothing — this has already
cost one false "clean" result on this repo. Both harnesses count the frames the
kernel transmits in response:

```sh
FUZZ_NETRX_STATS=1 ./fuzz_netrx corpus_ethrx/tcp_syn_ck   # expect 1 (the SYN-ACK)
FUZZ_NETRX_STATS=1 ./fuzz_netrx corpus_ethrx/icmp_echo    # expect 1 (echo reply)
FUZZ_NETRX_STATS=1 ./fuzz_netrx corpus_ethrx/icmp_bcast   # expect 0 (smurf guard)
```

The first seed pass shipped **zero L4 checksums**, which `tcp_rx` and `udp_rx`
both correctly reject — so the TCP state machine was never entered and the run
looked clean. `seeds_eth.py` now computes proper pseudo-header checksums; the
`*_ck` seeds are the ones that reach L4.

The same applies to the disk targets: `seeds_disk.py` hand-builds a FAT32 volume
small enough to stay fast (Aegis does not enforce FAT32's 65525-cluster minimum,
so ~64 KB suffices where mkfs.vfat insists on ~33 MB), and both harnesses print
`FUZZ_DISKFS_STATS=1` receipts:

```sh
FUZZ_DISKFS_STATS=1 ./fuzz_fat  corpus_fat/fat32_min   # mounts=1 entries=3
FUZZ_DISKFS_STATS=1 ./fuzz_ext2 corpus_ext2/ext2_1k    # mounts=1 entries=6
FUZZ_DISKFS_STATS=1 ./fuzz_fat  corpus_fat/gpt_disk    # mounts=0 (correctly rejected)
```

An ext2 seed larger than the harness's 4 MB cap is silently skipped — that is
exactly how the first ext2 corpus reported `mounts=0`.

## Findings

**2026-08-09, `fuzz_fat`** — out-of-bounds read in `fat_time_unix`. The DOS
month field is 4 bits (0..15) and only its LOWER bound was clamped, so a crafted
directory entry with month 13..15 indexed `cum[12..14]` on a 12-entry `.rodata`
table. The leaked word lands in `i_mtime`/`i_atime`/`i_ctime`, where whoever
supplied the image reads it straight back with `stat()` and solves for it (every
other term of `days` is theirs) — a removable-media `.rodata` infoleak, and UB
besides. Fixed by clamping the upper bound. `corpus_fat/fat32_month15` is kept
as a regression seed: it reaches the bug in a single execution.

## Status

`fuzz_ethrx` and `fuzz_netrx` have run for hundreds of millions of executions
against the post-audit tree with no finding — a statement about those layers
being well hardened by the 2026-07-30 and 2026-08-01 audits, within the coverage
limits above, not a claim that the network stack is clean. `fuzz_gpt` and
`fuzz_ext2` are clean so far.
