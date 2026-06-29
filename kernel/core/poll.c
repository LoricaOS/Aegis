#include "poll.h"
#include "printk.h"

/* Generic per-tick poll-source registry.  See poll.h for the contract.
 * No driver dependencies live here — this is portable core logic.  The actual
 * device list is in the per-arch poll_sources.c (poll_sources_init). */

#define MAX_POLL_SOURCES 32

struct poll_source {
    poll_fn_t   fn;
    int         priority;
    const char *name;
};

static struct poll_source s_sources[MAX_POLL_SOURCES];
static int s_count = 0;

int
poll_source_register(poll_fn_t fn, int priority, const char *name)
{
    if (!fn)
        return -1;
    if (s_count >= MAX_POLL_SOURCES) {
        printk("[POLL] FAIL: too many poll sources (max %u), dropped %s\n",
               (unsigned)MAX_POLL_SOURCES, name ? name : "?");
        return -1;
    }
    /* Insertion sort by priority.  Strict '>' so equal priorities do not
     * shift — the new entry lands AFTER existing equal-priority ones, i.e. a
     * stable insert that preserves registration order within a priority.
     * The table is tiny and built once at boot, so this keeps poll_sources_run
     * a flat indirect-call walk with zero per-tick sorting. */
    int i = s_count;
    while (i > 0 && s_sources[i - 1].priority > priority) {
        s_sources[i] = s_sources[i - 1];
        i--;
    }
    s_sources[i].fn       = fn;
    s_sources[i].priority = priority;
    s_sources[i].name     = name;
    s_count++;
    return 0;
}

void
poll_sources_run(void)
{
    for (int i = 0; i < s_count; i++)
        s_sources[i].fn();
}
