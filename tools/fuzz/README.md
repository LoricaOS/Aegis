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

| target | covers |
|---|---|
| `fuzz_netrx` | Ethernet → ARP / IPv4 → ICMP / **TCP** / **UDP**, with a listening TCP port (`tcp_listen(80)`), a bound UDP port, and `tcp_tick()` driven so the connection state machine and retransmit timer are live |
| `fuzz_ethrx` | Ethernet / ARP / IPv4 / ICMP only, L4 stubbed — faster, and isolates a finding to the lower layers |

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

## Status

As of 2026-08-09 no finding from these targets. `fuzz_ethrx` and `fuzz_netrx`
have been run for tens of millions of executions against the post-audit tree
without a crash — which is a statement about these layers being well-hardened by
the 2026-07-30 and 2026-08-01 audits, within the coverage limits above.
