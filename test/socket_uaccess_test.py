#!/usr/bin/env python3
"""Execute production socket/uaccess bodies with fault/permission/race injection.

Run: python3 test/socket_uaccess_test.py
Requires a host C compiler. MM, scheduling and copies are mocked; the syscall,
permission-walk, ancillary-output and fd-publication bodies are not models.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def text(path):
    return (ROOT / path).read_text()


def body(path, name):
    src = text(path)
    match = re.search(r"(?m)^(?:static )?[\w *]+\s*" + name + r"\([^;]*?\)\n\{", src)
    assert match, name
    return src[match.start():src.index("\n}", match.end()) + 2] + "\n"


def header(path):
    return re.sub(r"(?m)^#include.*\n", "", text(path)) + "\n"


def run(src):
    with tempfile.TemporaryDirectory(prefix="aegis-socket-uaccess-") as tmp:
        path = Path(tmp) / "test.c"
        binary = Path(tmp) / "test"
        path.write_text(src)
        subprocess.run([os.environ.get("HOSTCC", "cc"), "-std=c11", "-Wall", "-Wextra",
                        "-Werror", "-Wno-unused-function", "-Wno-unused-variable",
                        str(path), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)


base = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#define USER_ADDR_MAX 0x7fffffffffffULL
typedef int spinlock_t;
typedef int irqflags_t;
typedef int waitq_t;
static int held;
static int spin_lock_irqsave(int *lock) { assert(!*lock); *lock=1; held++; return 0; }
static void spin_unlock_irqrestore(int *lock, int f) { (void)f; assert(*lock); *lock=0; held--; }
typedef struct { int is_user; } aegis_task_t;
"""

permissions = base + header("kernel/mm/vmm.h") + header("kernel/mm/vma.h") + r"""
typedef struct { aegis_task_t task; uint64_t pml4_phys; } aegis_process_t;
static aegis_process_t process = {{1}, 4096};
static aegis_task_t *sched_current(void) { return &process.task; }
static vma_entry_t regions[3];
static uint64_t leaf, lookups;
int vma_find_copy(struct aegis_process *p, uint64_t va, vma_entry_t *out) {
    (void)p;
    for (int i=0; i<3; i++) if (va>=regions[i].base && va-regions[i].base<regions[i].len) {
        *out=regions[i]; return 1;
    }
    return 0;
}
uint64_t vmm_pte_of_user_raw(uint64_t p, uint64_t va) {
    (void)p; (void)va; lookups++; return leaf;
}
"""
# Match the production tag used in the VMA declarations.
permissions = permissions.replace("typedef struct { aegis_task_t task; uint64_t pml4_phys; }",
                                  "typedef struct aegis_process { aegis_task_t task; uint64_t pml4_phys; }")
permissions += body("kernel/syscall/uaccess_check.c", "uaccess_range_accessible")
permissions += body("kernel/syscall/uaccess_check.c", "uaccess_range_mapped")
permissions += header("kernel/syscall/syscall_util.h") + r"""
int main(void) {
    regions[0]=(vma_entry_t){.base=4096,.len=4096,.prot=3};
    regions[1]=(vma_entry_t){.base=8192,.len=4096,.prot=1};
    regions[2]=(vma_entry_t){.base=12288,.len=4096,.prot=0};
    assert(user_ptr_valid(4096,8192));
    assert(user_ptr_readable(4096,8192));
    assert(!user_ptr_writable(4096,8192));
    assert(user_ptr_writable(4097,4095)); /* lazy RW: no PTE walk/allocation */
    assert(lookups==0);
    leaf=VMM_FLAG_PRESENT|VMM_FLAG_USER|VMM_FLAG_WRITABLE;
    assert(!user_ptr_valid(12288,1)); /* no fallback around explicit PROT_NONE */
    assert(!user_ptr_writable(12288,1));
    assert(lookups==0);
    assert(user_ptr_writable(16384,4096)); /* VMA-less published mapping */
    leaf=VMM_FLAG_PRESENT|VMM_FLAG_USER;
    assert(user_ptr_valid(16384,1) && !user_ptr_writable(16384,1));
    leaf|=VMM_FLAG_COW;
    assert(user_ptr_writable(16384,1)); /* COW is logically writable */
    leaf=VMM_FLAG_PRESENT|VMM_FLAG_WRITABLE;
    assert(!user_ptr_valid(16384,1)); /* supervisor mapping */
    leaf=0;
    assert(!user_ptr_valid(16384,1)); /* hole */
    assert(user_ptr_valid(USER_ADDR_MAX,0));
    assert(!user_ptr_valid(USER_ADDR_MAX+1,0));
    assert(!user_ptr_writable(UINT64_MAX-1,8));
    assert(!user_ptr_valid(4096,UINT64_MAX));
    process.task.is_user=0;
    assert(user_ptr_writable(16384,4096));
    return 0;
}
"""
run(permissions)

sockets = base + r"""
typedef struct { void (*close)(void *); void (*dup)(void *); } vfs_ops_t;
"""
vfs = text("kernel/fs/vfs.h")
sockets += vfs[vfs.index("typedef struct {\n    const vfs_ops_t *ops;"):
               vfs.index("} vfs_file_t;") + len("} vfs_file_t;")]
sockets += "\n" + header("kernel/lib/refcount.h") + header("kernel/limits.h") + r"""
#define PROC_MAX_FDS 32
#define VFS_FD_CLOEXEC 0x10000
typedef struct { int lock; vfs_file_t fds[PROC_MAX_FDS]; } fd_table_t;
typedef struct { aegis_task_t task; uint64_t pml4_phys; fd_table_t *fd_table; } aegis_process_t;
typedef uint32_t ip4_addr_t;
typedef struct { uint8_t b[16]; } ip6_addr_t;
"""
sockets += header("kernel/net/socket.h") + header("kernel/net/unix_socket.h")
sockets += r"""
#define SYS_ERR(e) ((uint64_t)-(int64_t)(e))
#define MSG_DONTWAIT 0x40
#define MSG_CTRUNC 8
#define SOL_SOCKET 1
#define SCM_RIGHTS 1
#define BLOCK_EINTR -1
#define SCOPED_FD_PIN(name) int name=0
#define wait_event_interruptible(q,cond,rc) do { (void)(q); (void)(cond); (rc)=BLOCK_EINTR; } while(0)
#define wait_event_timeout(q,cond,deadline,rc) do { (void)(deadline); wait_event_interruptible(q,cond,rc); } while(0)
static fd_table_t table;
static aegis_process_t process = {.fd_table=&table};
static aegis_process_t *current_proc(void) { return &process; }
static sock_t sock;
static udp_rx_slot_t queue[UDP_RX_SLOTS];
static unix_sock_t s_unix[UNIX_SOCK_MAX];
static int unix_lock, sock_lock, is_unix, remaining, read_calls, pins, connects, last_force_nb;
static uint64_t bad_write, bad_read, fault_ptr, input_fault_ptr, fault_left;
static void (*copy_hook)(void);
static int user_ptr_valid(uint64_t p, uint64_t n) {
    return n<=USER_ADDR_MAX && p<=USER_ADDR_MAX-n && p!=bad_read;
}
static int user_ptr_writable(uint64_t p, uint64_t n) {
    return user_ptr_valid(p,n) && p!=bad_write;
}
static uint64_t copy_from_user(void *dst, const void *src, uint64_t n) {
    assert(!held);
    if ((uint64_t)(uintptr_t)src==bad_read) return n;
    if ((uint64_t)(uintptr_t)src==input_fault_ptr) {
        assert(fault_left<=n); memcpy(dst,src,n-fault_left); return fault_left;
    }
    memcpy(dst,src,n); return 0;
}
static uint64_t copy_to_user(void *dst, const void *src, uint64_t n) {
    assert(!held); /* including ancillary callback */
    if (!n) return 0;
    if (copy_hook) { void (*hook)(void)=copy_hook; copy_hook=NULL; hook(); }
    uint64_t left=(uint64_t)(uintptr_t)dst==fault_ptr ? fault_left : 0;
    assert(left<=n); memcpy(dst,src,n-left); return left;
}
static uint32_t get_proc_unix_sock(uint64_t fd, int *pin) {
    (void)fd; (void)pin; return is_unix ? 0 : UNIX_NONE;
}
static uint64_t get_sock_from_pin(int *pin, sock_t **out, uint32_t *id) {
    (void)pin; *out=&sock; *id=0; return 0;
}
void sock_ref(uint32_t id) { (void)id; pins++; }
void sock_unref(uint32_t id) { (void)id; pins--; }
void sock_wake(uint32_t id) { (void)id; assert(!held); }
irqflags_t sock_lock_acquire(void) { return spin_lock_irqsave(&sock_lock); }
void sock_lock_release(irqflags_t f) { spin_unlock_irqrestore(&sock_lock,f); }
static uint64_t arch_get_ticks(void) { return 0; }
static int tcp_conn_recv(uint32_t sid, uint32_t cid, void *dst, uint16_t len) {
    (void)sid; (void)cid;
    if (!len) return remaining ? remaining : -EAGAIN;
    int n=remaining<len ? remaining : len; memset(dst,'T',n); remaining-=n; read_calls++; return n;
}
int unix_sock_read(uint32_t id, void *dst, uint32_t len, int nb) {
    (void)id; last_force_nb=nb;
    if (!remaining && nb) return -EAGAIN;
    int n=remaining<(int)len ? remaining : (int)len;
    memset(dst,'U',n); remaining-=n; read_calls++; return n;
}
int unix_sock_wait_recv(uint32_t id, int nb) {
    (void)id; (void)nb; return remaining || s_unix[0].passed_fd_count ? 1 : 0;
}
int unix_sock_connect(uint32_t id, const char *path) { (void)id; (void)path; connects++; return 0; }
static int tcp_connect(uint32_t sid, ip4_addr_t ip, uint16_t port, uint32_t *out) {
    (void)sid; (void)ip; (void)port; *out=1; connects++; return 0;
}
static uint16_t htons(uint16_t x) { return __builtin_bswap16(x); }
static uint16_t ntohs(uint16_t x) { return htons(x); }
static int ipv6_addr_equal(const ip6_addr_t *a, const ip6_addr_t *b) { return !memcmp(a,b,sizeof(*a)); }
static void ipv6_get_linklocal(ip6_addr_t *out) { memset(out,1,sizeof(*out)); }
static int closes;
static void close_right(void *p) { (void)p; assert(!held); closes++; }
static const vfs_ops_t right_ops={.close=close_right}, other_ops={0};
unix_sock_t *unix_sock_get(uint32_t id) { return id==0 ? &s_unix[0] : NULL; }
"""
sockets += body("kernel/net/unix_socket.c", "unix_close_staged")
sockets += body("kernel/net/unix_socket.c", "unix_sock_recv_fds")
src = text("kernel/syscall/sys_socket.c")
sockets += src[src.index("typedef struct {\n    uint16_t sun_family;"):
               src.index("} k_sockaddr_un_t;") + len("} k_sockaddr_un_t;")]
sockets += src[src.index("typedef struct { void *iov_base;"):
               src.index("#define SCM_RIGHTS 1")]
sockets += src[src.index("typedef struct {\n    uint64_t control;"):
               src.index("} recv_rights_output_t;") + len("} recv_rights_output_t;")]
for name in ("recv_flags_supported", "sys_connect", "udp_recv_finish", "sys_recvfrom",
             "recv_rights_output", "recv_ranges_overlap", "sys_recvmsg"):
    sockets += body("kernel/syscall/sys_socket.c", name)
sockets_prefix = sockets
sockets += r"""
static void reset(void) {
    memset(&sock,0,sizeof(sock)); memset(queue,0,sizeof(queue));
    memset(&table,0,sizeof(table)); memset(s_unix,0,sizeof(s_unix));
    sock.udp_rx=queue; sock.domain=AF_INET; sock.type=SOCK_TYPE_DGRAM; sock.nonblocking=1;
    bad_write=bad_read=fault_ptr=input_fault_ptr=UINT64_MAX; fault_left=0;
    is_unix=remaining=read_calls=pins=connects=closes=last_force_nb=0; copy_hook=NULL;
}
static void packet(void) {
    sock.udp_rx_tail=1; queue[0].in_use=1; queue[0].len=4;
    memcpy(queue[0].data,"DATA",4); queue[0].src_port=123;
}
static void stage(int n) {
    s_unix[0].passed_fd_count=n;
    for (int i=0;i<n;i++) s_unix[0].passed_fds[i].file=(vfs_file_t){
        .ops=&right_ops,.priv=(void *)(uintptr_t)(i+1),.flags=VFS_FD_CLOEXEC};
}
static void slot_race(void) { table.fds[1].ops=&other_ops; }
static void second_receiver(void) {
    char other[4];
    assert(sock.udp_rx_busy && sock.udp_rx_head==0 && queue[0].in_use);
    assert(sys_recvfrom(0,(uintptr_t)other,4,MSG_DONTWAIT,0,0)==SYS_ERR(EAGAIN));
    assert(sock.udp_rx_head==0 && queue[0].in_use && pins==1);
}
int main(void) {
    /* The synthetic 4 GiB range test below needs room below USER_ADDR_MAX.
     * A stack address can sit within that margin depending on host ASLR. */
    static char buf[5000]={0}, control[128]={0};
    uint64_t b=(uintptr_t)buf, c=(uintptr_t)control;
    uint32_t alen; k_sockaddr_in_t addr;
    for (int domain=AF_INET; domain<=AF_INET6; domain+=AF_INET6-AF_INET) {
        reset(); sock.domain=domain;
        k_sockaddr_in6_t sa={.sin6_family=AF_INET6,.sin6_port=123};
        k_sockaddr_in_t sa4={.sin_family=AF_INET,.sin_port=456};
        uint64_t input=domain==AF_INET ? (uintptr_t)&sa4 : (uintptr_t)&sa;
        uint64_t size=domain==AF_INET ? sizeof(sa4) : sizeof(sa);
        input_fault_ptr=input; fault_left=size/2;
        sock_t before=sock;
        assert(sys_connect(0,input,size)==SYS_ERR(EFAULT));
        assert(!memcmp(&before,&sock,sizeof(sock)) && !connects);
    }
    reset(); is_unix=1; k_sockaddr_un_t un={.sun_family=AF_UNIX};
    input_fault_ptr=(uintptr_t)&un; fault_left=2;
    assert(sys_connect(0,(uintptr_t)&un,sizeof(un))==SYS_ERR(EFAULT) && !connects);
    for (int kind=0; kind<3; kind++) {
        reset(); is_unix=kind==0; sock.type=kind==1 ? SOCK_TYPE_STREAM : SOCK_TYPE_DGRAM;
        remaining=4; packet(); bad_write=b;
        assert(sys_recvfrom(0,b,4,0,0,0)==SYS_ERR(EFAULT));
        assert(!read_calls && sock.udp_rx_head==0 && queue[0].in_use);
        bad_write=UINT64_MAX; fault_ptr=b; fault_left=4;
        assert(sys_recvfrom(0,b,4,0,0,0)==SYS_ERR(EFAULT));
        assert(pins==0);
        if (kind==2) assert(sock.udp_rx_head==0 && queue[0].in_use && !sock.udp_rx_busy);
    }
    for (int kind=0;kind<2;kind++) {
        reset(); is_unix=kind==0; sock.type=SOCK_TYPE_STREAM; remaining=4;
        fault_ptr=b; fault_left=2;
        assert(sys_recvfrom(0,b,4,0,0,0)==2 && pins==0);
    }
    reset(); sock.type=SOCK_TYPE_STREAM; remaining=3000;
    fault_ptr=b+2048; fault_left=952;
    assert(sys_recvfrom(0,b,3000,0,0,0)==2048 && pins==0);
    reset(); is_unix=1; remaining=4;
    assert(sys_recvfrom(0,b,1ULL<<32,0,0,0)==4); /* clamp before narrowing */
    reset(); packet(); alen=sizeof(addr); bad_write=(uintptr_t)&addr;
    assert(sys_recvfrom(0,b,4,0,(uintptr_t)&addr,(uintptr_t)&alen)==SYS_ERR(EFAULT));
    assert(sock.udp_rx_head==0 && queue[0].in_use); /* invalid metadata preserves packet */
    reset(); packet(); alen=2; memset(&addr,0x7f,sizeof(addr));
    assert(sys_recvfrom(0,b,4,0,(uintptr_t)&addr,(uintptr_t)&alen)==4);
    assert(alen==sizeof(addr) && ((unsigned char *)&addr)[2]==0x7f);
    reset(); packet(); alen=sizeof(addr);
    assert(sys_recvfrom(0,0,0,MSG_DONTWAIT,(uintptr_t)&addr,(uintptr_t)&alen)==0);
    assert(alen==sizeof(addr) && addr.sin_family==AF_INET && addr.sin_port==htons(123));
    assert(sock.udp_rx_head==1 && !queue[0].in_use && !sock.udp_rx_busy && pins==0);
    reset();
    assert(sys_recvfrom(0,0,0,MSG_DONTWAIT,0,0)==SYS_ERR(EAGAIN) && pins==0);
    reset(); sock.domain=AF_INET6; packet(); k_sockaddr_in6_t addr6; alen=sizeof(addr6);
    assert(sys_recvfrom(0,b,4,0,(uintptr_t)&addr6,(uintptr_t)&alen)==4);
    assert(addr6.sin6_family==AF_INET6 && alen==sizeof(addr6));
    reset(); packet(); alen=sizeof(addr); fault_ptr=(uintptr_t)&alen; fault_left=4;
    assert(sys_recvfrom(0,b,4,0,(uintptr_t)&addr,(uintptr_t)&alen)==SYS_ERR(EFAULT));
    assert(sock.udp_rx_head==0 && queue[0].in_use && !sock.udp_rx_busy && pins==0);
    reset(); packet(); alen=sizeof(addr); fault_ptr=(uintptr_t)&addr; fault_left=sizeof(addr)/2;
    assert(sys_recvfrom(0,b,4,0,(uintptr_t)&addr,(uintptr_t)&alen)==SYS_ERR(EFAULT));
    assert(sock.udp_rx_head==0 && queue[0].in_use && !sock.udp_rx_busy && pins==0);
    fault_ptr=UINT64_MAX;
    assert(sys_recvfrom(0,b,4,0,0,0)==4 && sock.udp_rx_head==1 && !sock.udp_rx_busy);
    reset(); packet(); copy_hook=second_receiver;
    assert(sys_recvfrom(0,b,4,0,0,0)==4);
    assert(sock.udp_rx_head==1 && !queue[0].in_use && !sock.udp_rx_busy && pins==0);

    k_iovec_t iov[2]={{buf,4},{buf+4,4}};
    k_msghdr_t msg={.msg_iov=iov,.msg_iovlen=1};
    reset(); is_unix=1; remaining=4; bad_write=b;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EFAULT) && !read_calls);
    reset(); is_unix=1; remaining=4; fault_ptr=b; fault_left=4;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EFAULT));
    reset(); is_unix=1; remaining=4; fault_ptr=b; fault_left=2;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==2);
    reset(); is_unix=1; remaining=8; msg.msg_iovlen=2; bad_write=b+4;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EFAULT) && !read_calls);
    reset(); is_unix=1; remaining=8; input_fault_ptr=(uintptr_t)&iov[1]; fault_left=sizeof(iov[1])/2;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EFAULT) && !read_calls);
    reset(); packet(); fault_ptr=(uintptr_t)&msg.msg_controllen; fault_left=sizeof(uint64_t);
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EFAULT));
    assert(sock.udp_rx_head==0 && queue[0].in_use);
    msg.msg_iovlen=0; msg.msg_control=control;
    for (int where=0;where<4;where++) {
        reset(); is_unix=1; stage(2); msg.msg_controllen=sizeof(control);
        fault_ptr=where==0 ? c : where==1 ? c+sizeof(k_cmsghdr_t) :
                  where==2 ? (uintptr_t)&msg.msg_controllen : (uintptr_t)&msg.msg_flags;
        fault_left=where==0 ? sizeof(k_cmsghdr_t) : where==1 ? 8 :
                   where==2 ? sizeof(uint64_t) : sizeof(int);
        assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EFAULT));
        assert(closes==2 && !table.fds[0].ops && !table.fds[1].ops);
    }
    reset(); is_unix=1; stage(2); msg.msg_controllen=sizeof(control); copy_hook=slot_race;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EAGAIN));
    assert(!table.fds[0].ops && table.fds[1].ops==&other_ops && closes==2);
    /* Contention must be resolved before payload is consumed or copied. */
    reset(); is_unix=1; remaining=4; stage(2); msg.msg_iovlen=1;
    msg.msg_controllen=sizeof(control); memset(buf,0x5a,4); copy_hook=slot_race;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EAGAIN));
    assert(!read_calls && remaining==4 && buf[0]==0x5a);
    assert(!table.fds[0].ops && table.fds[1].ops==&other_ops && closes==2);
    /* Once rights have been reported and committed, a later data fault is a
     * rights-only success, not an error that hides the installed descriptors. */
    reset(); is_unix=1; remaining=4; stage(2); msg.msg_controllen=sizeof(control);
    msg.msg_flags=-1; fault_ptr=b; fault_left=4;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==0);
    assert(table.fds[0].ops==&right_ops && table.fds[1].ops==&right_ops && !closes);
    assert(msg.msg_controllen==sizeof(k_cmsghdr_t)+2*sizeof(int) && msg.msg_flags==0);
    assert(last_force_nb==1);
    reset(); is_unix=1; stage(2); msg.msg_controllen=sizeof(control); msg.msg_flags=-1;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==0 && last_force_nb==1);
    assert(table.fds[0].ops==&right_ops && table.fds[1].ops==&right_ops && !closes);
    assert(msg.msg_controllen==sizeof(k_cmsghdr_t)+2*sizeof(int) && msg.msg_flags==0);
    reset(); is_unix=1; remaining=4; stage(2); msg.msg_controllen=sizeof(control);
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==4 && last_force_nb==1);
    assert(table.fds[0].ops==&right_ops && table.fds[1].ops==&right_ops && !closes);
    msg.msg_iovlen=0;
    reset(); is_unix=1; stage(2); msg.msg_controllen=sizeof(k_cmsghdr_t)+sizeof(int);
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==0);
    assert(table.fds[0].ops==&right_ops && !table.fds[1].ops && closes==1);
    assert(!(table.fds[0].flags & VFS_FD_CLOEXEC));
    assert(msg.msg_controllen==sizeof(k_cmsghdr_t)+sizeof(int));
    assert(msg.msg_flags==MSG_CTRUNC);
    reset(); is_unix=1; stage(2); msg.msg_controllen=sizeof(control);
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==0 && !closes);
    assert(table.fds[0].ops==&right_ops && table.fds[1].ops==&right_ops);
    int numbers[2]; memcpy(numbers,control+sizeof(k_cmsghdr_t),sizeof(numbers));
    assert(numbers[0]==0 && numbers[1]==1);
    reset(); is_unix=1; stage(2); msg.msg_controllen=sizeof(control);
    for (int i=0;i<PROC_MAX_FDS;i++) table.fds[i].ops=&other_ops;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==0 && closes==2 && msg.msg_controllen==0);
    assert(msg.msg_flags==MSG_CTRUNC);
    return 0;
}
"""
run(sockets)

# Exercise the actual ring read/write/staging and new no-dequeue wait phase.
# Only scheduler waits, wakeups and final pin drops are simulated here.
real = sockets_prefix
for name in ("unix_sock_read", "unix_sock_wait_recv"):
    real, n = re.subn(r"(?m)^int " + name + r"\([^;]*?\)\s*\{[\s\S]*?\n}",
                      "", real, count=1)
    assert n == 1, name
real = real.replace(
    "unix_sock_t *unix_sock_get(uint32_t id) { return id==0 ? &s_unix[0] : NULL; }",
    body("kernel/net/unix_socket.c", "unix_sock_get"))
real += r"""
#undef wait_event_interruptible
static void (*wait_hook)(void);
static unsigned waits, wakes;
#define wait_event_interruptible(q,cond,rc) do { \
    (void)(q); assert(!held); (rc)=0; waits++; \
    while (!(cond)) { \
        if (!wait_hook) { (rc)=BLOCK_EINTR; break; } \
        void (*hook)(void)=wait_hook; wait_hook=NULL; hook(); \
    } \
} while(0)
#define trace_emit(...) ((void)0)
static void waitq_wake_all(waitq_t *q) { (void)q; assert(!held); wakes++; }
const vfs_ops_t g_unix_sock_ops={0};
void unix_sock_free(uint32_t id) {
    /* Production read/wait/stage pins must return to their original live fd
     * reference. Teardown itself is covered by net_security_test.py. */
    assert(!held && id<2 && refcount_read(&s_unix[id].refcount)>1);
    assert(!refcount_dec_and_test(&s_unix[id].refcount));
}
"""
for name in ("ring_used", "ring_free", "unix_read_ready", "unix_sock_read_impl",
             "unix_sock_read", "unix_sock_wait_recv", "unix_write_ready",
             "unix_sock_write_nonblock", "unix_sock_write", "unix_reaches_locked", "unix_sock_stage_fds"):
    real += body("kernel/net/unix_socket.c", name)
# Exercise the production AF_UNIX sendmsg branch against the real ring writer.
# The network branch is covered separately by socket_send_test.py.
real += "static int scm_fd_passable(const vfs_file_t *f) { (void)f; return 1; }\n"
sendmsg = body("kernel/syscall/sys_socket.c", "sys_sendmsg")
start = sendmsg.index("    /* Datagram iovecs")
end = sendmsg.index("\n    if (!user_ptr_valid(msg_ptr", sendmsg.index("return sent;"))
real += sendmsg[:start] + "    if (uid == UNIX_NONE) return SYS_ERR(ENOSYS);\n" + sendmsg[end:]
real += r"""
static uint8_t rings[2][UNIX_BUF_SIZE];
static void reset_real(void) {
    memset(&sock,0,sizeof(sock)); memset(queue,0,sizeof(queue));
    memset(&table,0,sizeof(table)); memset(s_unix,0,sizeof(s_unix));
    memset(rings,0,sizeof(rings));
    sock.udp_rx=queue; sock.domain=AF_INET; sock.type=SOCK_TYPE_DGRAM; sock.nonblocking=1;
    bad_write=bad_read=fault_ptr=input_fault_ptr=UINT64_MAX; fault_left=0;
    is_unix=1; remaining=read_calls=pins=connects=closes=0;
    waits=wakes=0; copy_hook=wait_hook=NULL;
    for (int i=0;i<2;i++) {
        s_unix[i].in_use=1; s_unix[i].state=UNIX_CONNECTED; s_unix[i].peer_id=1-i;
        s_unix[i].ring=rings[i]; refcount_init(&s_unix[i].refcount,1);
    }
}
static void stage_real(unsigned n) {
    unix_passed_fd_t f[2];
    assert(n<=2);
    for (unsigned i=0;i<n;i++) f[i].file=(vfs_file_t){
        .ops=&right_ops,.priv=(void *)(uintptr_t)(i+1),.flags=VFS_FD_CLOEXEC};
    assert(unix_sock_stage_fds(0,f,n)==0);
}
static void produce_payload_and_rights(void) {
    /* Real publication order: sender writes bytes, then stages rights, both
     * while the receiver is parked at the scheduler boundary. */
    assert(unix_sock_write(1,"DATA",4)==4);
    stage_real(2);
}
static void produce_rights_only(void) { stage_real(2); }
static void slot_race(void) { table.fds[1].ops=&other_ops; }
static void steal_readiness(void) {
    char other[4];
    assert(unix_sock_read(0,other,sizeof(other),1)==4);
    assert(!memcmp(other,"OLD!",4));
    wait_hook=produce_payload_and_rights;
}
static void assert_rights(const void *control) {
    k_cmsghdr_t cm; int fds[2];
    memcpy(&cm,control,sizeof(cm)); memcpy(fds,(const char *)control+sizeof(cm),sizeof(fds));
    assert(cm.cmsg_level==SOL_SOCKET && cm.cmsg_type==SCM_RIGHTS);
    assert(cm.cmsg_len==sizeof(cm)+sizeof(fds));
    assert(fds[0]!=fds[1]);
    for (int i=0;i<2;i++) assert(table.fds[fds[i]].ops==&right_ops);
    assert(refcount_read(&s_unix[0].refcount)==1 && refcount_read(&s_unix[1].refcount)==1);
}
static void udp_packets(void) {
    sock.udp_rx_tail=2;
    for (int i=0;i<2;i++) {
        queue[i].in_use=1; queue[i].len=4; queue[i].src_port=123+i;
        memcpy(queue[i].data,"DATA",4);
    }
}
int main(void) {
    char buf[32]={0}, control[128]={0};
    k_iovec_t iov[2]={{buf,4},{buf+4,4}};
    k_msghdr_t msg={.msg_iov=iov,.msg_iovlen=1,.msg_control=control,
                    .msg_controllen=sizeof(control),.msg_flags=-1};
    reset_real(); wait_hook=produce_payload_and_rights;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==4);
    assert(waits==1 && wakes>=2 && ring_used(&s_unix[1])==0);
    assert(!memcmp(buf,"DATA",4) && msg.msg_flags==0);
    assert(msg.msg_controllen==sizeof(k_cmsghdr_t)+2*sizeof(int));
    assert_rights(control);

    reset_real(); msg.msg_controllen=sizeof(control); msg.msg_flags=-1;
    wait_hook=produce_rights_only;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==0 && waits==1);
    assert(msg.msg_flags==0 && msg.msg_controllen==sizeof(k_cmsghdr_t)+2*sizeof(int));
    assert_rights(control);

    reset_real(); msg.msg_controllen=sizeof(control);
    assert(unix_sock_write(1,"OLD!",4)==4); copy_hook=steal_readiness;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==4 && waits==1);
    assert(!memcmp(buf,"DATA",4)); assert_rights(control);

    reset_real(); msg.msg_controllen=sizeof(control);
    wait_hook=produce_payload_and_rights; copy_hook=slot_race;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EAGAIN));
    assert(waits==1 && ring_used(&s_unix[1])==4 && closes==2);
    assert(!table.fds[0].ops && table.fds[1].ops==&other_ops);

    reset_real(); msg.msg_control=NULL; msg.msg_controllen=0; msg.msg_flags=-1;
    stage_real(2);
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==0 && !waits);
    assert(msg.msg_flags==MSG_CTRUNC && msg.msg_controllen==0 && closes==2);
    assert(!s_unix[0].passed_fd_count); /* rights-only readiness cannot spin */

    reset_real(); s_unix[1].state=UNIX_CLOSED;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==0 && !waits); /* EOF cannot spin */
    reset_real(); msg.msg_flags=-1;
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EINTR) && waits==1);
    assert(msg.msg_flags==-1); /* interrupt precedes metadata/descriptor effects */

    /* Unsafe output aliases fail before dequeue, fd detach or any output. */
    for (int alias=0;alias<3;alias++) {
        reset_real(); assert(unix_sock_write(1,"DATA",4)==4); stage_real(2);
        msg=(k_msghdr_t){.msg_iov=iov,.msg_iovlen=1,.msg_control=control,
                         .msg_controllen=sizeof(control),.msg_flags=-1};
        iov[0]=(k_iovec_t){buf,4};
        if (alias==0) iov[0].iov_base=control;
        if (alias==1) iov[0].iov_base=&msg.msg_controllen;
        if (alias==2) { msg.msg_control=&msg; msg.msg_controllen=sizeof(msg); }
        assert(sys_recvmsg(0,(uintptr_t)&msg,0)==SYS_ERR(EINVAL));
        assert(ring_used(&s_unix[1])==4 && s_unix[0].passed_fd_count==2);
        assert(!table.fds[0].ops && !closes && !waits && msg.msg_flags==-1);
    }
    /* Sequential payload aliases are legal; output may also overwrite the
     * snapshotted iovec array without changing the destination metadata. */
    reset_real(); assert(unix_sock_write(1,"ABCDEFGH",8)==8);
    iov[0]=(k_iovec_t){buf,4}; iov[1]=(k_iovec_t){buf+2,4};
    msg=(k_msghdr_t){.msg_iov=iov,.msg_iovlen=2};
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==8 && !memcmp(buf,"ABEFGH",6));
    reset_real(); assert(unix_sock_write(1,"DATA",4)==4); stage_real(2);
    union { k_iovec_t vec[4]; char bytes[64]; } alias_iov;
    alias_iov.vec[0]=(k_iovec_t){buf,4};
    msg=(k_msghdr_t){.msg_iov=alias_iov.vec,.msg_iovlen=1,
                    .msg_control=alias_iov.bytes,.msg_controllen=sizeof(alias_iov)};
    assert(sys_recvmsg(0,(uintptr_t)&msg,0)==4 && !memcmp(buf,"DATA",4));
    assert_rights(alias_iov.bytes);

    /* The Internet wrapper must call the actual UDP receive once even when
     * the iovec array is empty or has only zero-length elements. */
    for (int zero_iov=0;zero_iov<2;zero_iov++) {
        reset_real(); is_unix=0; udp_packets(); k_sockaddr_in_t name={0};
        iov[0]=(k_iovec_t){NULL,0};
        msg=(k_msghdr_t){.msg_iov=iov,.msg_iovlen=zero_iov,
                        .msg_name=&name,.msg_namelen=sizeof(name),.msg_flags=-1};
        assert(sys_recvmsg(0,(uintptr_t)&msg,MSG_DONTWAIT)==0);
        assert(sock.udp_rx_head==1 && !queue[0].in_use && queue[1].in_use);
        assert(msg.msg_namelen==sizeof(name) && name.sin_family==AF_INET);
        assert(name.sin_port==htons(123) && !msg.msg_flags && !msg.msg_controllen);
        sock.udp_rx_head=sock.udp_rx_tail;
        assert(sys_recvmsg(0,(uintptr_t)&msg,MSG_DONTWAIT)==SYS_ERR(EAGAIN));
    }
    /* Full/partial UNIX rings honor per-call nonblocking without waiting or
     * mutating the persistent mode; ordinary blocking write still waits. */
    reset_real(); s_unix[0].ring_head=UNIX_BUF_SIZE-1;
    assert(unix_sock_write_nonblock(0,"DATA",4,1)==-EAGAIN);
    assert(!waits && !s_unix[0].nonblocking);
    assert(unix_sock_write(0,"DATA",4)==-EINTR && waits==1);
    reset_real(); s_unix[0].nonblocking=1; s_unix[0].ring_head=UNIX_BUF_SIZE-1;
    assert(unix_sock_write(0,"DATA",4)==-EAGAIN && !waits);
    reset_real(); s_unix[0].ring_head=UNIX_BUF_SIZE-3;
    assert(unix_sock_write_nonblock(0,"DATA",4,1)==2);
    assert(!waits && !s_unix[0].nonblocking && !held);
    reset_real(); s_unix[0].ring_head=UNIX_BUF_SIZE-1;
    k_iovec_t send_iov[2]={{"DATA",4},{"TAIL",4}};
    k_msghdr_t send_msg={.msg_iov=send_iov,.msg_iovlen=2};
    assert(sys_sendmsg(0,(uintptr_t)&send_msg,MSG_DONTWAIT)==SYS_ERR(EAGAIN));
    assert(!waits && !s_unix[0].nonblocking);
    reset_real(); s_unix[0].ring_head=UNIX_BUF_SIZE-3;
    assert(sys_sendmsg(0,(uintptr_t)&send_msg,MSG_DONTWAIT)==2);
    assert(!waits && !s_unix[0].nonblocking && !held);
    /* Progress ending exactly on an iovec boundary must still publish
     * attached rights once the next iovec would block. */
    reset_real(); s_unix[0].ring_head=UNIX_BUF_SIZE-5;
    k_cmsghdr_t send_cm={.cmsg_len=sizeof(k_cmsghdr_t)+sizeof(int),
                        .cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
    memcpy(control,&send_cm,sizeof(send_cm)); int send_fd=3;
    memcpy(control+sizeof(send_cm),&send_fd,sizeof(send_fd));
    table.fds[3]=(vfs_file_t){.ops=&right_ops,.priv=(void*)1};
    send_msg.msg_control=control;send_msg.msg_controllen=send_cm.cmsg_len;
    assert(sys_sendmsg(0,(uintptr_t)&send_msg,MSG_DONTWAIT)==4);
    assert(!waits && s_unix[1].passed_fd_count==1);
    send_msg.msg_control=NULL;send_msg.msg_controllen=0;
    reset_real(); s_unix[0].ring_head=UNIX_BUF_SIZE-1;
    assert(sys_sendmsg(0,(uintptr_t)&send_msg,0)==SYS_ERR(EINTR) && waits==1);
    reset_real(); is_unix=0; udp_packets();
    msg=(k_msghdr_t){.msg_flags=-1}; fault_ptr=(uintptr_t)&msg.msg_flags; fault_left=sizeof(int);
    assert(sys_recvmsg(0,(uintptr_t)&msg,MSG_DONTWAIT)==SYS_ERR(EFAULT));
    assert(sock.udp_rx_head==0 && queue[0].in_use);
    assert(!held && !pins);
    return 0;
}
"""
run(real)

# Every direct copy in this owned syscall TU must consume its residual.
for call in re.findall(r"(?m)^\s*copy_(?:to|from)_user\s*\([^;]*;", src):
    assert re.search(r"!=\s*0", call), call
print("socket uaccess permission, residual, queue preflight and SCM_RIGHTS tests: PASS")
