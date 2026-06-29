#include "trace.h"
#include "printk.h"
#include "arch.h"
#ifdef __x86_64__
#include "lapic.h"   /* lapic_id() — originating CPU; x86-specific */
#endif

/* Ring size — power of two so the index masks.  16384 records (~512 KB BSS)
 * holds enough IPC history to catch an early event (e.g. a URL passed
 * frontend->RequestServer) before a busy render wraps it. */
#define TRACE_N 16384u

typedef struct {
    uint64_t tsc;          /* arch_get_cycles() — relative ordering across CPUs */
    uint64_t a, b, c;      /* event-specific args                               */
    uint32_t seq;          /* global sequence; written LAST (completeness flag) */
    uint16_t cpu;          /* lapic_id()                                        */
    uint16_t event;        /* TRACE_* id                                        */
} trace_rec_t;

static trace_rec_t      s_trace[TRACE_N];
static volatile uint64_t s_trace_head = 0;   /* next slot (monotonic) */

void
trace_emit(uint16_t event, uint64_t a, uint64_t b, uint64_t c)
{
    uint64_t i = __atomic_fetch_add(&s_trace_head, 1, __ATOMIC_RELAXED);
    trace_rec_t *r = &s_trace[i & (TRACE_N - 1)];
    r->tsc   = arch_get_cycles();
    r->a     = a;
    r->b     = b;
    r->c     = c;
    r->event = event;
#ifdef __x86_64__
    r->cpu   = (uint16_t)lapic_id();
#else
    r->cpu   = 0;
#endif
    /* seq written last with release ordering: the dump reads it first and
     * skips a slot whose seq has been overwritten by a wrap mid-record. */
    __atomic_store_n(&r->seq, (uint32_t)i, __ATOMIC_RELEASE);
}

static const char *
trace_evname(uint16_t e)
{
    switch (e) {
    case TRACE_KBD_INJECT:  return "KBD_INJECT";
    case TRACE_KBD_CONSUME: return "KBD_CONSUME";
    case TRACE_UNIX_SEND:   return "UNIX_SEND";
    case TRACE_UNIX_RECV:   return "UNIX_RECV";
    default:                return "?";
    }
}

void
trace_dump(const char *reason)
{
    uint64_t head  = __atomic_load_n(&s_trace_head, __ATOMIC_ACQUIRE);
    uint64_t count = head < TRACE_N ? head : TRACE_N;
    uint64_t start = head - count;
    printk("[TRACE] ==== ring dump (%s) %lu records ====\n",
           reason ? reason : "?", count);
    for (uint64_t k = 0; k < count; k++) {
        uint64_t i = start + k;
        trace_rec_t *r = &s_trace[i & (TRACE_N - 1)];
        if (__atomic_load_n(&r->seq, __ATOMIC_ACQUIRE) != (uint32_t)i)
            continue;   /* overwritten by a newer record — skip */
        if (r->event == TRACE_KBD_INJECT || r->event == TRACE_KBD_CONSUME) {
            char ch = (char)(r->a & 0xFF);
            int pr  = (ch >= 32 && ch < 127);
            printk("[TRACE] seq=%u cpu=%u %s byte=0x%lx '%c' head=%lu tail=%lu\n",
                   r->seq, (unsigned)r->cpu, trace_evname(r->event),
                   r->a, pr ? ch : '.', r->b, r->c);
        } else {
            printk("[TRACE] seq=%u cpu=%u %s a=0x%lx b=0x%lx c=0x%lx\n",
                   r->seq, (unsigned)r->cpu, trace_evname(r->event),
                   r->a, r->b, r->c);
        }
    }
    printk("[TRACE] ==== end ====\n");
}

/* ── Process-lifecycle tracing ────────────────────────────────────────────── */

int g_proc_trace = 0;   /* set from the `proc_trace` kernel cmdline flag */

void
proc_trace_log(const char *verb, uint32_t pid, uint32_t ppid, const char *name)
{
    if (!g_proc_trace)
        return;
    printk("[PROC] %s pid=%u ppid=%u %s\n", verb, pid, ppid,
           (name && name[0]) ? name : "?");
}
