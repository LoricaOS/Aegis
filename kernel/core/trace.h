#ifndef AEGIS_TRACE_H
#define AEGIS_TRACE_H

#include <stdint.h>

/* Lockless flight recorder — a fixed ring of binary event records appended
 * from anywhere (ISR, syscall, any CPU) via an atomic index, dumped on demand
 * (SysRq 'r', /proc/trace, or a panic).  Built for race-hunting: it records
 * WHO (cpu) did WHAT (event) to WHICH state (args) WHEN (tsc), without a lock
 * that would serialize — and therefore mask — the very race under study.
 *
 * The kbd-ring tracepoints (inject + consume) are the motivating use: they
 * capture (byte, head, tail, cpu) at every producer and consumer touch, so an
 * intermittent input-corruption race shows up as a concrete inconsistency in
 * the dump instead of "a byte scrambled somewhere". */

enum {
    TRACE_KBD_INJECT  = 1,   /* a=byte b=head c=tail (serial/PS2/USB -> ring) */
    TRACE_KBD_CONSUME = 2,   /* a=byte b=head c=tail (ring -> reader)          */
    TRACE_UNIX_SEND   = 3,   /* a=len  b=head c=tail (AF_UNIX tx ring write)   */
    TRACE_UNIX_RECV   = 4,   /* a=len  b=head c=tail (AF_UNIX tx ring read)    */
};

/* trace_emit — append one record.  Safe from any context (lockless atomic
 * append).  Cheap: an atomic add + RDTSC + a few stores. */
void trace_emit(uint16_t event, uint64_t a, uint64_t b, uint64_t c);

/* trace_dump — print the ring (oldest -> newest) to the kernel log / serial. */
void trace_dump(const char *reason);

/* ── Process-lifecycle tracing ─────────────────────────────────────────────
 * One "[PROC] <verb> pid=N ppid=M <name>" line per fork/exec/exit, gated by
 * the `proc_trace` kernel cmdline flag (default OFF so boot output / the test
 * oracle are unchanged).  For a multi-process app (Ladybird's 5-service
 * pipeline) this makes "did the services spawn, and which one died first?"
 * visible on serial instead of guesswork. */
extern int g_proc_trace;
void proc_trace_log(const char *verb, uint32_t pid, uint32_t ppid,
                    const char *name);

#endif /* AEGIS_TRACE_H */
