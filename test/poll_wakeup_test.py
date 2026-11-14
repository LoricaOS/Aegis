#!/usr/bin/env python3
"""Run production epoll/eventfd/poll helpers with deterministic host scheduling.

No kernel boot is required. Locks, fd lookup, scheduler and user copies are
stubbed; syscall/helper bodies are extracted unchanged from the checkout.
"""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
def function(path, name):
    text = (ROOT / path).read_text()
    match = re.search(r'(?m)^(?:static )?[\w *]+\s*' + name + r'\([^;]*?\)\n\{', text)
    assert match, name
    return text[match.start():text.index('\n}', match.end())+2] + '\n'
def header(path):
    return re.sub(r'(?m)^#include.*\n', '', (ROOT / path).read_text())
common = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
typedef int spinlock_t;
typedef int irqflags_t;
#define SPINLOCK_INIT 0
static int held;
static irqflags_t spin_lock_irqsave(spinlock_t *l) { assert(!*l); *l=1; held++; return 0; }
static void spin_unlock_irqrestore(spinlock_t *l, irqflags_t f) { (void)f; assert(*l); *l=0; held--; }
struct task {int read_nonblock;}; static struct task task;
static struct task *sched_current(void) {return &task;}
typedef struct waitq_entry {struct task *task; struct waitq_entry *next,*prev; int on_queue;} waitq_entry_t;
typedef struct waitq {waitq_entry_t *head; int wakes;} waitq_t;
static int wake_latch, registrations;
static void waitq_init(waitq_t *q) {memset(q,0,sizeof(*q));}
static void waitq_add(waitq_t *q,waitq_entry_t *e) {assert(!e->on_queue); e->next=q->head;q->head=e;e->on_queue=1;registrations++;}
static void waitq_remove(waitq_t *q,waitq_entry_t *e) {if(!e->on_queue)return;waitq_entry_t **p=&q->head;while(*p!=e){assert(*p);p=&(*p)->next;}*p=e->next;e->on_queue=0;registrations--;}
static void waitq_wake_all(waitq_t *q) {assert(!held);q->wakes++;if(q->head)wake_latch=1;}
static waitq_t g_timer_waitq;
typedef struct {int unused;} aegis_process_t;
typedef struct {uint16_t (*poll)(void *);} vfs_ops_t;
typedef struct {const vfs_ops_t *ops;void *priv;} vfs_file_t;
'''
common += header('kernel/lib/refcount.h') + header('kernel/net/epoll.h')
common += r'''
static epoll_fd_t s_epoll[EPOLL_MAX_INSTANCES]; static spinlock_t epoll_lock;
static aegis_process_t process;
static aegis_process_t *current_proc(void) {return &process;}
static uint64_t arch_get_ticks(void) {return 10;}
static int user_ptr_valid(uint64_t p,uint64_t n) {(void)n;return p!=0;}
static int copy_to_user(void *d,const void *s,uint64_t n) {memcpy(d,s,n);return 0;}
static int pending;
static int signal_check_pending(void) {return pending;}
static uint32_t readiness;
static int ready_fd;
static uint32_t epoll_compute_readiness(uint32_t fd,aegis_process_t *p) {(void)p;return fd==(uint32_t)ready_fd ? readiness : 0;}
typedef struct {waitq_t *q;} fd_pin_t;
static int inject_on_pin;
static int fd_waitq_pin(int fd,fd_pin_t *p) {(void)fd;p->q=NULL; if(inject_on_pin){inject_on_pin=0;k_epoll_event_t e={.events=EPOLLIN,.data=99};assert(epoll_ctl_impl(0,EPOLL_CTL_ADD,8,&e)==0);ready_fd=8;readiness=EPOLLIN;}return 0;}
static void fd_waitq_unpin(fd_pin_t *p) {(void)p;}
static int block_mode, blocks;
static void sched_block(void) {
 assert(!held);assert(++blocks<3);
 k_epoll_event_t e={.events=EPOLLIN,.data=99};
 if(block_mode==1) assert(epoll_ctl_impl(0,EPOLL_CTL_ADD,7,&e)==0);
 if(block_mode==2) assert(epoll_ctl_impl(0,EPOLL_CTL_MOD,7,&e)==0);
 readiness=EPOLLIN;
 assert(wake_latch); /* a parked task must actually be woken */
 wake_latch=0;
}
'''
for name in ['epoll_alloc','epoll_get','epoll_ctl_impl','epoll_wait_impl']:
    common += function('kernel/net/epoll.c',name)
common += r'''
static void reset(void) {memset(s_epoll,0,sizeof(s_epoll)); assert(epoll_alloc()==0); readiness=0;ready_fd=7;blocks=0;wake_latch=0;pending=0;assert(!registrations);}
int main(void) {
 k_epoll_event_t out, e={.events=EPOLLIN,.data=99};
 reset(); block_mode=1;
 assert(epoll_wait_impl(0,(uintptr_t)&out,1,UINT32_MAX)==1);
 assert(blocks==1 && out.data==99 && !registrations);
 reset();assert(epoll_ctl_impl(0,EPOLL_CTL_ADD,7,&e)==0);
 s_epoll[0].watches[0].oneshot_disabled=1;block_mode=2;
 assert(epoll_wait_impl(0,(uintptr_t)&out,1,UINT32_MAX)==1);
 assert(blocks==1 && !registrations);
 reset();assert(epoll_ctl_impl(0,EPOLL_CTL_ADD,7,&e)==0);
 inject_on_pin=1;block_mode=0;
 assert(epoll_wait_impl(0,(uintptr_t)&out,1,UINT32_MAX)==1);
 assert(blocks==0 && !registrations);
 reset();pending=1;
 assert(epoll_wait_impl(0,(uintptr_t)&out,1,UINT32_MAX)==-EINTR);
 assert(!registrations);
 puts("epoll empty-set ADD, ONESHOT rearm, registration race, EINTR cleanup: ok");
}
'''
event = r'''
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
typedef int irqflags_t;
struct waitq {int wakes;};
typedef struct {int lock;uint64_t count;unsigned flags;struct waitq read_waiters,write_waiters;} eventfd_t;
struct task {int read_nonblock;} task;
static struct task *sched_current(void){return &task;}
static int spin_lock_irqsave(int *l){(void)l;return 0;}
static void spin_unlock_irqrestore(int *l,int f){(void)l;(void)f;}
static int signal_fatal_pending(void){return 0;}
static void waitq_wake_all(struct waitq *q){q->wakes++;}
#define wait_event(q,c) assert(c)
#define EFD_SEMAPHORE 1
#define EFD_VALMAX 0xfffffffffffffffeULL
'''
for name in ['eventfd_read_fn','eventfd_poll_fn','eventfd_read_get_waitq_fn']:
    event += function('kernel/fs/eventfd.c',name)
event += r'''
int main(void){eventfd_t e={.count=EFD_VALMAX};uint64_t out;
struct waitq *q=eventfd_read_get_waitq_fn(&e);
assert(!(eventfd_poll_fn(&e)&4));assert(eventfd_read_fn(&e,&out,0,8)==8);
assert((eventfd_poll_fn(&e)&4) && q->wakes==1 && e.write_waiters.wakes==1);
puts("eventfd read wakes writable epoll observers: ok");}
'''
poll = r'''
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
typedef struct {uint16_t (*poll)(void *);} vfs_ops_t;
typedef struct {const vfs_ops_t *ops;void *priv;} vfs_file_t;
typedef struct {vfs_file_t file;} fd_table_pin_t;
typedef struct {void *fd_table;} aegis_process_t;
static int pins;
static int fd_table_pin(void *t,int fd,fd_table_pin_t *p){(void)t;(void)fd;(void)p;pins++;return 0;}
static void fd_table_unpin(fd_table_pin_t *p){(void)p;}
#define POLLIN 1
#define POLLOUT 4
#define POLLERR 8
#define POLLHUP 16
#define POLLNVAL 32
'''
poll += function('kernel/syscall/sys_poll.c','poll_fd')
poll += r'''
int main(void){aegis_process_t p={0};assert(poll_fd(&p,-1,POLLIN)==0);assert(pins==0);
assert(poll_fd(&p,9,POLLIN)==POLLNVAL);assert(pins==1);puts("poll negative fd ignored, closed positive fd invalid: ok");}
'''
with tempfile.TemporaryDirectory(prefix='aegis-poll-wakeup-') as tmp:
    for name, code in [('epoll',common),('eventfd',event),('poll',poll)]:
        path=Path(tmp)/f'{name}.c'; exe=Path(tmp)/name
        path.write_text(code)
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(path),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
