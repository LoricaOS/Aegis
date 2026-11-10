# TCP teardown-state lifetimes

Every connection slot in `s_tcp[]` is table-resident memory holding, once
attached, a 256 KiB receive ring and a 64 KiB send ring (320 KiB). `TCP_MAX_CONNS`
is 128, so leaked slots cost both the table and up to ~40 MiB. A slot returns to
the pool only when its state becomes `TCP_CLOSED`.

Invariant: **every state that is not `CLOSED` must either be owned by a live
socket or carry a bounded deadline.** Otherwise a peer that stops participating
pins the slot for the rest of the boot. That is the CVE-2026-68379 class
(Linux: a `tcp_tw_bucket` refcount leaked on a policy-failure discard, so
TIME_WAIT buckets were never freed — remote, unauthenticated, memory exhaustion).

Aegis has no refcounted TIME_WAIT buckets, so the specific missing-put defect
cannot occur. The equivalent risk had to be checked state by state:

| State | Bound |
|---|---|
| `SYN_RCVD` | `retransmit_at`/`retransmit_count` — RST after `TCP_RETRANSMIT_MAX` |
| `SYN_SENT` | same |
| `FIN_WAIT_1`, `CLOSING`, `LAST_ACK` | same; the unacked FIN is retransmitted |
| `TIME_WAIT` | `timewait_at` (4 s) → `CLOSED` in `tcp_tick` |
| `FIN_WAIT_2` | `finwait2_at` (60 s) → `CLOSED` in `tcp_tick` |
| `ESTABLISHED`, `CLOSE_WAIT` | owned by a socket; the application decides |
| `LISTEN` | reclaimed by `tcp_unlisten` when the listening socket closes |

## The bug this found

`FIN_WAIT_2` had no deadline. Our FIN is acked there, so `retransmit_at` is
deliberately 0 (nothing to resend), and `tcp_tick` skipped any connection with
`retransmit_at == 0`. `tcp_conn_close` is also a no-op outside
`ESTABLISHED`/`CLOSE_WAIT`, so closing the socket did not help.

Sequence: connect to any service that closes first, ACK its FIN, then stay
silent. The connection sat in `FIN_WAIT_2` forever holding a slot and its ring
pair. 128 of them exhausted the connection table and the TCP buffer pool;
because `tcp_find` matches on the 4-tuple regardless of state, the same tuple
could also not be re-established. `close()` on the local side did not release it
because the transition to `FIN_WAIT_2` happens after the close.

Fixed by arming `finwait2_at` on entry to the state and reclaiming the slot in
`tcp_tick`, mirroring `TIME_WAIT`. 60 s matches Linux's `tcp_fin_timeout`
default and RFC 1122 §4.2.2.13's requirement that the state be bounded;
cooperative peers still reach `TIME_WAIT` immediately on their FIN. The deadline
is not extended by inbound traffic, so replaying a FIN cannot pin the slot.

## TIME_WAIT wire behaviour

`tcp_rx` had no `case TCP_TIME_WAIT`, so everything fell through to `default`.
RFC 793 §3.9 requires a retransmitted FIN to be acknowledged — otherwise a peer
whose FIN our ACK was lost repeats it until it gives up and reports an error.
TIME_WAIT now re-ACKs a FIN (RST and duplicate data are ignored) without
extending the 2MSL deadline.

## Tests

`test/tcp_audit_test.py` covers the FIN_WAIT_2 deadline (still open inside the
deadline, reclaimed after it, slot returned to the pool, wake delivered), a peer
FIN still reaching TIME_WAIT first, and the TIME_WAIT re-ACK not extending the
timer. Removing the FIN_WAIT_2 branch makes the suite fail, confirming the
regression actually bites.

Not addressed here: `FIN_WAIT_2` reclamation still waits for the deadline rather
than being immediate when the last socket reference closes before the peer's FIN
arrives (that would need an orphan flag set under `tcp_lock` at close, or a
`sock_lock`-safe validity check). A 60 s wait is bounded, which is what the
invariant requires.
