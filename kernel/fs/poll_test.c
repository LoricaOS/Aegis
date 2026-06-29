/* kernel/fs/poll_test.c — boot self-test for VFS .poll callbacks */
#include "vfs.h"
#include "pipe.h"
#include "kva.h"
#include "printk.h"
#include "spinlock.h"
#include "../sched/waitq.h"
#include <stdint.h>

void
poll_test(void)
{
    /* Allocate a pipe manually (same as sys_pipe2 but kernel-internal) */
    pipe_t *p = kva_alloc_pages(1);
    if (!p) {
        printk("[POLL] FAIL: kva_alloc_pages\n");
        return;
    }
    __builtin_memset(p, 0, sizeof(*p));
    {
        spinlock_t init = SPINLOCK_INIT;
        p->lock = init;
    }
    waitq_init(&p->read_waiters);
    waitq_init(&p->write_waiters);
    refcount_init(&p->read_refs, 1);
    refcount_init(&p->write_refs, 1);

    /* Test 1: empty pipe read end — expect no POLLIN */
    uint16_t ev = g_pipe_read_ops.poll(p);
    if (ev & 0x0001) { /* POLLIN */
        printk("[POLL] FAIL: empty pipe reports POLLIN\n");
        kva_free_pages(p, 1);
        return;
    }

    /* Test 2: write data, read end should now report POLLIN */
    p->buf[0] = 'X';
    p->write_pos = 1;
    p->count = 1;
    ev = g_pipe_read_ops.poll(p);
    if (!(ev & 0x0001)) {
        printk("[POLL] FAIL: pipe with data doesn't report POLLIN\n");
        kva_free_pages(p, 1);
        return;
    }

    /* Test 3: close write end — expect POLLIN|POLLHUP */
    refcount_init(&p->write_refs, 0);
    ev = g_pipe_read_ops.poll(p);
    if (!(ev & 0x0001) || !(ev & 0x0010)) {
        printk("[POLL] FAIL: closed write end — expected POLLIN|POLLHUP, got 0x%x\n",
               (unsigned)ev);
        kva_free_pages(p, 1);
        return;
    }

    kva_free_pages(p, 1);
    printk("[POLL] OK: vfs poll pipe\n");
}
