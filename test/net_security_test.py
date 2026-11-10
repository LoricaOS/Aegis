#!/usr/bin/env python3
"""Execute the production ownership/teardown helpers with bounded host stubs.

Run: python3 test/net_security_test.py (requires a C compiler).
Hardware, scheduling and user copies are stubbed; actual helper bodies and
object layouts are extracted from the tree, not reimplemented as a model.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def source(path):
    return (ROOT / path).read_text()


def function(path, name):
    text = source(path)
    match = re.search(r"(?m)^(?:static )?[\w *]+\s*" + name + r"\([^;]*?\)\n\{", text)
    assert match, name
    end = text.index("\n}", match.end()) + 2
    return text[match.start():end] + "\n"


def header(path):
    return "\n" + re.sub(r"(?m)^#include.*\n", "", source(path))


COMMON = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef int spinlock_t;
typedef int irqflags_t;
#define SPINLOCK_INIT 0
static int held;
static irqflags_t spin_lock_irqsave(spinlock_t *p) {
    assert(!*p); *p=1; held++; return 0;
}
static void spin_unlock_irqrestore(spinlock_t *p, irqflags_t f) {
    (void)f; assert(*p); *p=0; held--;
}
#define kmemset memset
typedef struct { int x; } waitq_t;
static void waitq_init(waitq_t *q) { q->x=0; }
static void waitq_wake_all(waitq_t *q) { assert(!held); q->x++; }
typedef struct { void (*close)(void *); } vfs_ops_t;
'''
# Keep the real descriptor size: it determines the teardown stack footprint.
VFS = source("kernel/fs/vfs.h")
COMMON += VFS[VFS.index("typedef struct {\n    const vfs_ops_t *ops;"):VFS.index("} vfs_file_t;") + len("} vfs_file_t;")]
COMMON += header("kernel/lib/refcount.h")
COMMON += r'''
#define PROC_MAX_FDS 16
#define VFS_O_RDWR 2
#define VFS_O_RDONLY 0
#define VFS_O_WRONLY 1
#define VFS_O_ACCMODE 3
#define CAP_TABLE_SIZE 64
#define CAP_KIND_FB 12
#define CAP_KIND_PROC_READ 10
#define CAP_KIND_IPC 15
#define CAP_RIGHTS_READ 1
#define CAP_RIGHTS_WRITE 2
#define ENOCAP 1
#undef SIGTTIN
#undef SIGINT
#undef SIGQUIT
#undef SIGTSTP
#undef SIG_IGN
#undef sa_handler
#define SIGTTIN 21
#define SIGINT 2
#define SIGQUIT 3
#define SIGTSTP 20
#define SIG_IGN 1
#define SIGWINCH 28
struct fd_table { spinlock_t lock; vfs_file_t fds[PROC_MAX_FDS]; };
typedef struct { int is_user; } aegis_task_t;
typedef struct {
    aegis_task_t task;
    uint32_t pid, sid, pgid, uid, gid;
    uint32_t caps[CAP_TABLE_SIZE];
    uint64_t signal_mask;
    struct { uintptr_t sa_handler; } sigactions[64];
    struct fd_table *fd_table;
} aegis_process_t;
static aegis_process_t process;
static aegis_task_t *sched_current(void) { return &process.task; }
static aegis_process_t *current_proc(void) { return &process; }
static int cap_check(const uint32_t *caps, unsigned n, unsigned kind, unsigned rights) {
    (void)n; return (caps[kind] & rights) == rights ? 0 : -1;
}
static int signals;
static void signal_send_pgrp(uint32_t p, int sig) { (void)p; (void)sig; signals++; }
'''

UNIX = COMMON + header("kernel/limits.h") + header("kernel/net/unix_socket.h") + r'''
static unix_sock_t s_unix[UNIX_SOCK_MAX];
static spinlock_t unix_lock;
const vfs_ops_t g_unix_sock_ops = {0};
static int pages, closes;
static void (*alloc_hook)(void);
static void *kva_alloc_pages(unsigned n) {
    assert(!held);
    if (alloc_hook) { void (*hook)(void)=alloc_hook; alloc_hook=NULL; hook(); }
    pages += n; return calloc(n, 4096);
}
static void kva_free_pages(void *p, unsigned n) { assert(!held); pages -= n; free(p); }
static void name_unregister(const char *path) { (void)path; }
static uint32_t listener_id;
static uint32_t name_lookup(const char *path) { (void)path; return listener_id; }
static void close_other(void *priv) { (void)priv; assert(!held); closes++; }
static const vfs_ops_t other_ops = { .close=close_other };
'''
for name in ("unix_sock_get", "unix_sock_alloc", "unix_close_staged", "unix_put_locked",
             "unix_sock_free", "unix_reaches_locked", "unix_sock_stage_fds",
             "unix_sock_pair", "unix_sock_listen", "unix_sock_connect", "unix_sock_peercred"):
    UNIX += function("kernel/net/unix_socket.c", name)
UNIX += r'''
static unix_passed_fd_t fd_for(unsigned id) {
    unix_passed_fd_t f={.file={.ops=&g_unix_sock_ops,.priv=(void *)(uintptr_t)id}};
    refcount_inc(&s_unix[id].refcount); return f;
}
static void stage(unsigned dst, unsigned id) {
    unix_passed_fd_t f=fd_for(id);
    assert(unix_sock_stage_fds(dst,&f,1)==0);
}
static unsigned live(void) {
    unsigned n=0; for(unsigned i=0;i<UNIX_SOCK_MAX;i++) n+=s_unix[i].in_use; return n;
}
static void reuse_listener(void) {
    unix_sock_free(listener_id);
    int replacement=unix_sock_alloc();
    assert(replacement>=0 && (unsigned)replacement!=listener_id);
    s_unix[replacement].state=UNIX_LISTENING;
    unix_sock_free(replacement);
}
int main(void) {
    process.task.is_user=1; process.pid=10; process.uid=20; process.gid=30;
    unsigned a=unix_sock_alloc(), b=unix_sock_alloc();
    unix_passed_fd_t f=fd_for(a);
    assert(unix_sock_stage_fds(a,&f,1)==-ELOOP); unix_sock_free(a);
    stage(a,b); f=fd_for(a);
    assert(unix_sock_stage_fds(b,&f,1)==-ELOOP); unix_sock_free(a);
    unix_sock_free(b); unix_sock_free(a); assert(live()==0);

    /* Full-pool deep acyclic ownership: one close must reclaim every slot. */
    for(unsigned i=0;i<UNIX_SOCK_MAX;i++) assert(unix_sock_alloc()==(int)i);
    for(unsigned i=0;i+1<UNIX_SOCK_MAX;i++) { stage(i,i+1); unix_sock_free(i+1); }
    unix_passed_fd_t other={.file={.ops=&other_ops}};
    assert(unix_sock_stage_fds(UNIX_SOCK_MAX-1,&other,1)==0);
    unix_sock_free(0); assert(live()==0 && closes==1);

    /* Duplicate edges decrement twice, without duplicate final-put work. */
    a=unix_sock_alloc(); b=unix_sock_alloc(); stage(a,b); stage(a,b);
    unix_sock_free(b); unix_sock_free(a); assert(live()==0);

    /* Listener ownership is a graph edge too. */
    a=unix_sock_alloc(); b=unix_sock_alloc();
    s_unix[a].accept_queue[0]=b; s_unix[a].accept_head=1;
    f=fd_for(a); assert(unix_sock_stage_fds(b,&f,1)==-ELOOP); unix_sock_free(a);
    unix_sock_free(a); assert(live()==0);

    /* Connected peer lingers with unread data until the other end closes. */
    assert(unix_sock_pair(&a,&b)==0); s_unix[a].ring[0]=42; s_unix[a].ring_head=1;
    unix_sock_free(a);
    assert(s_unix[a].in_use && s_unix[a].state==UNIX_CLOSED && s_unix[a].ring[0]==42);
    unix_sock_free(b); assert(live()==0 && pages==0);

    for(int round=0;round<UNIX_SOCK_MAX;round++) {
        listener_id=unix_sock_alloc(); s_unix[listener_id].state=UNIX_BOUND;
        assert(unix_sock_listen(listener_id)==0);
        process.pid=40; process.uid=50; process.gid=60;
        a=unix_sock_alloc(); assert(unix_sock_connect(a,"service")==0);
        uint32_t pid,uid,gid;
        assert(unix_sock_peercred(a,&pid,&uid,&gid)==0);
        if(round==0) assert(pid==10 && uid==20 && gid==30);
        unix_sock_free(listener_id); unix_sock_free(a);
        assert(live()==0 && pages==0);
    }
    listener_id=unix_sock_alloc(); s_unix[listener_id].state=UNIX_BOUND;
    assert(unix_sock_listen(listener_id)==0);
    a=unix_sock_alloc(); alloc_hook=reuse_listener;
    assert(unix_sock_connect(a,"service")==0);
    unix_sock_free(a); assert(live()==0 && pages==0 && !held);
    puts("UNIX ownership, deep teardown, peer linger, listener cleanup and credentials: ok");
}
'''

TCP = COMMON + header("kernel/limits.h") + r'''
typedef uint32_t ip4_addr_t;
typedef struct { int x; } netdev_t;
#define SOCK_NONE UINT32_MAX
#define TCP_RST 4
#define TCP_ACK 16
'''+header("kernel/net/tcp.h")+r'''
static tcp_conn_t s_tcp[TCP_MAX_CONNS];
static spinlock_t tcp_lock;
static int resets;
int tcp_send_segment(netdev_t *d, tcp_conn_t *c, uint8_t flags, const void *p, uint16_t n) {
    (void)d;(void)c;(void)p;(void)n; assert(!held && flags==(TCP_RST|TCP_ACK)); resets++;return 0;
}
'''
for name in ("tcp_claim_slot", "tcp_conn_owned_locked", "tcp_conn_abort",
             "tcp_listener_locked", "tcp_accept_ready", "tcp_accept"):
    TCP += function("kernel/net/tcp.c", name)
TCP += r'''
static void queue(unsigned conn) {
    tcp_conn_t *l=&s_tcp[0]; unsigned i=l->accept_tail++ & 7;
    l->accept_queue[i]=conn; l->accept_generation[i]=s_tcp[conn].generation;
}
int main(void) {
    tcp_claim_slot(0); s_tcp[0].state=TCP_LISTEN; s_tcp[0].sock_id=17;
    tcp_claim_slot(1); s_tcp[1].state=TCP_ESTABLISHED; s_tcp[1].listener_id=17; queue(1);
    /* RST, slot reuse, and a victim socket owning the new generation. */
    tcp_claim_slot(1); s_tcp[1].state=TCP_ESTABLISHED; s_tcp[1].sock_id=99;
    tcp_conn_t out;
    assert(tcp_accept_ready(17)); assert(tcp_accept(17,21,&out)==-EAGAIN);
    assert(s_tcp[1].sock_id==99 && !tcp_accept_ready(17));
    /* Even a same-generation entry cannot replace an existing owner. */
    queue(1); assert(tcp_accept(17,21,&out)==-EAGAIN); assert(s_tcp[1].sock_id==99);
    tcp_claim_slot(2); s_tcp[2].state=TCP_CLOSE_WAIT; s_tcp[2].listener_id=17;
    s_tcp[2].remote_port=1234; queue(2);
    assert(tcp_accept(17,21,&out)==2 && out.remote_port==1234);
    assert(s_tcp[2].sock_id==21); assert(tcp_accept(17,22,&out)==-EAGAIN);
    tcp_conn_abort(22,2); assert(s_tcp[2].state==TCP_CLOSE_WAIT && resets==0);
    tcp_conn_abort(21,2); assert(s_tcp[2].state==TCP_CLOSED && resets==1);
    assert(!held); puts("TCP stale accept generations, atomic ownership and abort: ok");
}
'''

UDP = COMMON + r'''
#define UDP_BINDINGS_MAX 8
#define SOCK_TYPE_DGRAM 2
#define SOCK_NONE UINT32_MAX
typedef struct { unsigned type; uint16_t local_port; } sock_t;
static sock_t socks[4];
static sock_t *sock_get(unsigned i) { return i<4 ? &socks[i] : NULL; }
typedef struct { uint16_t port; uint32_t sock_id; } udp_binding_t;
static udp_binding_t s_udp[UDP_BINDINGS_MAX];
static spinlock_t udp_lock;
'''+function("kernel/net/udp.c","udp_bind")+function("kernel/net/udp.c","udp_unbind")+r'''
int main(void) {
    for(unsigned i=0;i<4;i++) socks[i].type=SOCK_TYPE_DGRAM;
    assert(udp_bind(5000,0)==0 && socks[0].local_port==5000);
    assert(udp_bind(5000,1)<0 && socks[1].local_port==0);
    udp_unbind(5000,1); assert(udp_bind(5000,2)<0);
    assert(udp_bind(6000,0)<0 && socks[0].local_port==5000);
    assert(udp_bind(6000,2)==0); udp_unbind(6000,0);
    assert(udp_bind(6000,3)<0);
    udp_unbind(5000,0); assert(udp_bind(5000,1)==0);
    assert(!held); puts("UDP failed bind, rebind and identity-checked unbind: ok");
}
'''

TTY = COMMON+header("kernel/tty/tty.h")+header("kernel/tty/pty.h")+r'''
static tty_t console;
static tty_t *s_console_tty=&console;
static spinlock_t tty_global_lock, pty_pool_lock;
static pty_pair_t s_pty_pool[PTY_MAX_PAIRS];
static const vfs_ops_t s_slave_ops={0},s_master_ops={0},s_kbd_ops={0};
static tty_t *tty_console(void) { return s_console_tty; }
static vfs_file_t *kbd_vfs_open(void) {
    static vfs_file_t file={.ops=&s_kbd_ops};return &file;
}
static int kbd_has_data(void) { return 1; }
static int user_ptr_valid(uint64_t p,unsigned n) { (void)n;return p!=0; }
static int user_ptr_readable(uint64_t p,unsigned n) { return user_ptr_valid(p,n); }
static int copy_from_user(void *to,const void *from,unsigned n) { memcpy(to,from,n);return 0; }
static int copy_to_user(void *to,const void *from,unsigned n) { memcpy(to,from,n);return 0; }
static int tty_pgrp_in_session(uint32_t pgid,uint32_t sid) {
    return process.pgid==pgid && process.sid==sid;
}
static volatile uint32_t s_deferred_pgrp;
#define SYS_ERR(e) ((uint64_t)(int64_t)-(e))
static int consumed;
static int raw(tty_t *tty,char *out,int *interrupted) {
    (void)tty;*out='x';*interrupted=0;consumed++;return 1;
}
'''
TTY = TTY.replace("static tty_t *tty_console(void)","tty_t *tty_console(void)")
for path,names in (("kernel/fs/kbd_vfs.c",("kbd_vfs_is_tty","kbd_vfs_has_input_fd")),
                   ("kernel/tty/tty.c",("tty_claim","tty_console_allowed","tty_find_controlling","tty_init_defaults","tty_is_fg","tty_echo","tty_read","tty_ioctl")),
                   ("kernel/tty/pty.c",("try_acquire_ctty_locked","pts_open_pair","pts_open","pty_open_controlling","pty_find_by_session")),
                   ("kernel/fs/kbd_vfs.c",("tty_open_current",)),
                   ("kernel/arch/x86_64/kbd.c",("kbd_set_tty_pgrp",)),
                   ("kernel/syscall/sys_signal.c",("sys_setfg",))):
    for name in names: TTY+=function(path,name)
TTY += "\n#define s_console_tty console\n"+function("kernel/fs/kbd_vfs.c","kbd_vfs_poll_fn")+"\n#undef s_console_tty\n"
TTY += r'''
int main(void) {
    struct fd_table table={0}; process.fd_table=&table; process.task.is_user=1;
    process.pid=process.sid=process.pgid=11;
    tty_init_defaults(&console); console.termios.c_lflag=0; console.read_raw=raw;
    assert(tty_claim(&console,11,11)==0);
    char ch;
    assert(tty_read(&console,&ch,1)==1 && consumed==1);
    process.pid=process.sid=process.pgid=22; process.sigactions[SIGTTIN].sa_handler=SIG_IGN;
    assert(tty_read(&console,&ch,1)==-ENOCAP && consumed==1);
    process.caps[CAP_KIND_FB]=CAP_RIGHTS_WRITE;
    assert(tty_read(&console,&ch,1)==1 && consumed==2);
    process.caps[CAP_KIND_FB]=0;
    assert(tty_claim(&console,22,22)<0 && console.session_id==11);
    pty_pair_t *pair=&s_pty_pool[0]; pair->in_use=pair->master_open=1;
    tty_init_defaults(&pair->tty); pair->tty.termios.c_lflag=0; pair->tty.read_raw=raw;
    vfs_file_t out;
    assert(pts_open(0,0,&out)<0);
    table.fds[3]=(vfs_file_t){.ops=&s_master_ops,.priv=pair};
    assert(pts_open(0,0,&out)==0 && pair->tty.session_id==22);
    process.pid=process.sid=process.pgid=33;
    /* Delegated fd permits opening, but never steals another session's ctty. */
    assert(pts_open(0,0,&out)==0 && pair->tty.session_id==22);
    assert(tty_read(&pair->tty,&ch,1)==-5 && consumed==2);
    process.sid=22; assert(pty_open_controlling(22,&out)==0);
    assert(pty_open_controlling(0,&out)<0 && pty_open_controlling(33,&out)<0);
    table.fds[3]=(vfs_file_t){0}; assert(pts_open(0,0400,&out)<0);

    /* A spawn copies a chosen stdio description but gives the child a new
     * SID/PGID. An input description delegates access; foreground arbitration
     * still requires the controller to select that child's process group. */
    struct fd_table child_table={0};
    vfs_file_t input={.ops=&s_kbd_ops,.flags=VFS_O_RDONLY};
    process.fd_table=&child_table;
    process.pid=process.sid=process.pgid=44; process.uid=0;
    unsigned before=consumed;
    assert(tty_open_current(&out)==-ENXIO);
    assert(tty_read(&console,&ch,1)==-ENOCAP && consumed==(int)before);
    assert(tty_ioctl(&console,TIOCSCTTY,0)==-ENOCAP && console.session_id==11);
    child_table.fds[0]=input;child_table.fds[0].flags=VFS_O_WRONLY;
    assert(!kbd_vfs_has_input_fd() && tty_open_current(&out)==-ENXIO);
    child_table.fds[0].flags=VFS_O_RDONLY;
    assert(kbd_vfs_has_input_fd() && tty_open_current(&out)==0 && kbd_vfs_is_tty(&out));
    child_table.fds[0].flags=VFS_O_RDWR;assert(kbd_vfs_has_input_fd());
    child_table.fds[0].flags=VFS_O_RDONLY;
    assert(tty_read(&console,&ch,1)==-5 && consumed==(int)before); /* SIG_IGN */
    assert(!(kbd_vfs_poll_fn(NULL)&1));
    assert(tty_ioctl(&console,TIOCSCTTY,0)<0 && console.session_id==11);
    assert((int64_t)sys_setfg(44)<0); /* fd possession does not grant PROC_READ/WRITE */

    /* Parent explicitly selects the new session's pgrp. */
    process.fd_table=&table;table.fds[0]=input;
    process.pid=process.sid=process.pgid=11;
    process.caps[CAP_KIND_PROC_READ]=CAP_RIGHTS_WRITE;
    assert(sys_setfg(44)==0 && console.fg_pgrp==44);
    process.caps[CAP_KIND_PROC_READ]=0;
    process.fd_table=&child_table;process.pid=process.sid=process.pgid=44;
    assert(tty_read(&console,&ch,1)==1 && consumed==(int)before+1);
    assert(kbd_vfs_poll_fn(NULL)&1);
    k_termios_t termios;
    assert(tty_ioctl(&console,TCGETS,(uintptr_t)&termios)==0);
    assert(tty_ioctl(&console,TIOCSCTTY,0)==0 && console.session_id==44);
    /* Fork/dup preserves the same description and controlling session. */
    process.pid=45;child_table.fds[7]=child_table.fds[0];child_table.fds[0]=(vfs_file_t){0};
    assert(tty_read(&console,&ch,1)==1);

    /* A spawned shell with explicit control authority can select and restore
     * foreground even when another delegated session currently owns console. */
    process.fd_table=&table;process.pid=process.sid=process.pgid=11;
    process.caps[CAP_KIND_PROC_READ]=CAP_RIGHTS_WRITE;
    assert(sys_setfg(11)==0 && console.fg_pgrp==11);
    assert(tty_read(&console,&ch,1)==1);
    table.fds[0]=(vfs_file_t){0};
    assert((int64_t)sys_setfg(11)==-ENOCAP);
    assert(tty_open_current(&out)==-ENXIO);
    assert(tty_ioctl(&console,TIOCSCTTY,0)==-ENOCAP);
    assert(!held); puts("PTY ownership and delegated console spawn/fork/open/read/poll/claim/foreground gates: ok");
}
'''

with tempfile.TemporaryDirectory(prefix="aegis-net-security-") as tmp:
    for name, program in (("unix", UNIX), ("tcp", TCP), ("udp", UDP), ("tty", TTY)):
        path=Path(tmp)/f"{name}.c"
        path.write_text(program)
        exe=path.with_suffix("")
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1", "-g",
                        "-fsanitize=address,undefined", str(path), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)

# Ordering guard for the interrupt-driven path (host checks cannot run scheduler).
epoll=function("kernel/net/epoll.c", "epoll_wait_impl")
register=epoll.index("waitq_add(fd_queues[n]")
recheck=epoll.index("epoll_compute_readiness", register)
block=epoll.index("sched_block();", recheck)
assert register < recheck < block
print("epoll registration-before-recheck ordering: ok")
