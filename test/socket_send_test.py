#!/usr/bin/env python3
"""Run production send helpers with host transport/copy/scheduler stubs.

No NIC, scheduler, or guest execution is claimed. Run with a host C compiler.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(path, name):
    source = (ROOT / path).read_text()
    match = re.search(r'(?m)^(?:static )?[\w *]+\s*' + name + r'\([^;]*?\)\n\{', source)
    assert match, name
    return source[match.start():source.index('\n}', match.end()) + 2] + '\n'


code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define AF_INET 2
#define AF_INET6 10
#define SOCK_TYPE_STREAM 1
#define SOCK_TYPE_DGRAM 2
#define SOCK_CONNECTED 3
#define MSG_DONTWAIT 0x40
#define UNIX_NONE UINT32_MAX
#define UNIX_BUF_SIZE 4096
#define SYS_ERR(e) ((uint64_t)(int64_t)-(e))
#define SCOPED_FD_PIN(p) int p=0
#define wait_event_interruptible(q,c,r) do { (void)(q); (void)(c); waits++; (r)=-EINTR; } while(0)
typedef struct { uint8_t bytes[16]; } ip6_addr_t;
typedef uint32_t ip4_addr_t;
typedef struct { uint16_t sin_family, sin_port; ip4_addr_t sin_addr; char zero[8]; } k_sockaddr_in_t;
typedef struct { uint16_t sin6_family, sin6_port; uint32_t flow; ip6_addr_t sin6_addr; uint32_t scope; } k_sockaddr_in6_t;
typedef struct { int type, state, domain, nonblocking, poll_waiters; uint32_t sock_id, tcp_conn_id; uint16_t local_port, remote_port; ip4_addr_t remote_ip; ip6_addr_t remote_ip6, local_ip6; } sock_t;
typedef int netdev_t;
typedef int aegis_process_t;
typedef struct {void *iov_base; uint64_t iov_len;} k_iovec_t;
typedef struct {void *msg_name; uint32_t msg_namelen, pad; k_iovec_t *msg_iov; uint64_t msg_iovlen; void *msg_control; uint64_t msg_controllen; int msg_flags;} k_msghdr_t;
static sock_t socket;
static int packets, waits, send_budget, bound, netdev, is_unix, unix_calls, unix_force_nb;
static uint16_t packet_len;
static unsigned char packet[1472];
static const void *fault;
static aegis_process_t *current_proc(void) { return 0; }
static uint32_t get_proc_unix_sock(uint64_t f,int *p) { (void)f;(void)p;return is_unix ? 0 : UNIX_NONE; }
static uint64_t get_sock_from_pin(int *p,sock_t **s,uint32_t *id) { (void)p;*s=&socket;*id=0;return 0; }
static int user_ptr_valid(uint64_t p,uint64_t n) { return n == 0 || (p && p <= UINTPTR_MAX-n); }
static int copy_from_user(void *d,const void *s,uint64_t n) { if (n && s==fault) return 1; if(n) memcpy(d,s,n); return 0; }
static int unix_sock_write_nonblock(uint32_t id,const void *b,uint32_t n,int nb) {
 (void)id;(void)b;unix_calls++;unix_force_nb=nb;
 if(send_budget>0){int r=n<(uint32_t)send_budget?(int)n:send_budget;send_budget-=r;return r;}
 return -EAGAIN;
}
static void sock_ref(uint32_t id) {(void)id;}
static void sock_unref(uint32_t id) {(void)id;}
static uint16_t ntohs(uint16_t n) {return (n>>8)|(n<<8);}
static int ipv6_addr_equal(const ip6_addr_t *a,const ip6_addr_t *b) {return !memcmp(a,b,sizeof(*a));}
static void ipv6_get_linklocal(ip6_addr_t *a) {memset(a,1,sizeof(*a));}
static netdev_t *netdev_get(const char *name) {(void)name; return &netdev;}
static int udp_ensure_local_port(sock_t *s,uint32_t id) {(void)s;(void)id;bound++;return 0;}
static int udp_send(netdev_t *d,uint16_t sp,ip4_addr_t ip,uint16_t dp,const void *p,uint16_t n) {
 (void)d;(void)sp;(void)ip;(void)dp;assert(n<=sizeof(packet));packets++;packet_len=n;if(n)memcpy(packet,p,n);return 0;
}
static int udp6_send(netdev_t *d,uint16_t sp,const ip6_addr_t *ip,uint16_t dp,const void *p,uint16_t n) {
 (void)ip;return udp_send(d,sp,0,dp,p,n);
}
static int tcp_conn_send(uint32_t id,uint32_t c,const void *p,uint16_t n) {
 (void)id;(void)c;(void)p;if(send_budget>0){int r=n<send_budget?n:send_budget;send_budget-=r;return r;}return 0;
}
static int tcp_conn_send_ready(uint32_t id,uint32_t c) {(void)id;(void)c;return 0;}
'''
code += function('kernel/net/socket.c', 'sock_stream_send')
code += function('kernel/syscall/sys_socket.c', 'sock_send_datagram')
code += function('kernel/syscall/sys_socket.c', 'sys_sendto')
# The network branch is tested; unrelated AF_UNIX ancillary handling is omitted.
sendmsg = function('kernel/syscall/sys_socket.c', 'sys_sendmsg')
code += sendmsg[:sendmsg.index('\n    if (!user_ptr_valid(msg_ptr', sendmsg.index('return sent;'))] + '\nreturn SYS_ERR(ENOSYS);\n}\n'
code += r'''
static void reset(int domain,int type) {
 socket=(sock_t){.domain=domain,.type=type,.state=SOCK_CONNECTED};
 packets=waits=bound=0;send_budget=0;packet_len=0;fault=0;is_unix=unix_calls=unix_force_nb=0;
}
int main(void) {
 char data[1473]; memset(data,'x',sizeof(data));
 k_iovec_t iov[9]={{"header",6},{"payload",7}};
 k_msghdr_t m={.msg_iov=iov,.msg_iovlen=2};
 for(int family=AF_INET;family<=AF_INET6;family+=AF_INET6-AF_INET){
  int limit=family==AF_INET?1472:1452;
  iov[0]=(k_iovec_t){"header",6};iov[1]=(k_iovec_t){"payload",7};
  reset(family,SOCK_TYPE_DGRAM);
  assert(sys_sendmsg(1,(uintptr_t)&m,0)==13);
  assert(packets==1 && packet_len==13 && !memcmp(packet,"headerpayload",13));
  reset(family,SOCK_TYPE_DGRAM);m.msg_iovlen=0;
  assert(sys_sendmsg(1,(uintptr_t)&m,0)==0 && packets==1 && packet_len==0);
  reset(family,SOCK_TYPE_DGRAM);m.msg_iovlen=2;iov[0]=(k_iovec_t){0,0};iov[1]=iov[0];
  assert(sys_sendmsg(1,(uintptr_t)&m,0)==0 && packets==1);
  reset(family,SOCK_TYPE_DGRAM);iov[0]=(k_iovec_t){data,limit-1};iov[1]=(k_iovec_t){data,1};
  assert(sys_sendmsg(1,(uintptr_t)&m,0)==(uint64_t)limit && packets==1 && packet_len==limit);
  reset(family,SOCK_TYPE_DGRAM);iov[1].iov_len=2;
  assert(sys_sendmsg(1,(uintptr_t)&m,0)==SYS_ERR(EMSGSIZE) && packets==0 && bound==0);
  reset(family,SOCK_TYPE_DGRAM);iov[0]=(k_iovec_t){data,1};iov[1]=(k_iovec_t){data+1,1};fault=data+1;
  assert(sys_sendmsg(1,(uintptr_t)&m,0)==SYS_ERR(EFAULT) && packets==0);
  reset(family,SOCK_TYPE_DGRAM);m.msg_iovlen=9;
  assert(sys_sendmsg(1,(uintptr_t)&m,0)==SYS_ERR(EINVAL) && packets==0);m.msg_iovlen=2;
  reset(family,SOCK_TYPE_DGRAM);
  assert(sys_sendto(1,(uintptr_t)data,limit+1,0,0,0)==SYS_ERR(EMSGSIZE) && packets==0 && bound==0);
  assert(sys_sendto(1,(uintptr_t)data,limit,0,0,0)==(uint64_t)limit && packets==1);
 }
 reset(AF_INET,SOCK_TYPE_STREAM);
 assert(sys_sendto(1,(uintptr_t)data,4,MSG_DONTWAIT,0,0)==SYS_ERR(EAGAIN) && waits==0 && !socket.nonblocking);
 send_budget=2;
 assert(sys_sendto(1,(uintptr_t)data,4,MSG_DONTWAIT,0,0)==2 && waits==0 && !socket.nonblocking);
 assert(sys_sendto(1,(uintptr_t)data,4,0,0,0)==SYS_ERR(EINTR) && waits==1);
 reset(AF_INET,SOCK_TYPE_STREAM);socket.nonblocking=1;
 assert(sys_sendto(1,(uintptr_t)data,4,0,0,0)==SYS_ERR(EAGAIN) && waits==0);
 reset(AF_INET,SOCK_TYPE_STREAM);iov[0]=(k_iovec_t){data,1};iov[1]=(k_iovec_t){data+1,1};send_budget=1;
 assert(sys_sendmsg(1,(uintptr_t)&m,MSG_DONTWAIT)==1 && waits==0);
 assert(sys_sendmsg(1,(uintptr_t)&m,MSG_DONTWAIT)==SYS_ERR(EAGAIN) && waits==0);
 reset(AF_INET,SOCK_TYPE_STREAM);is_unix=1;
 assert(sys_sendto(1,(uintptr_t)data,4,MSG_DONTWAIT,0,0)==SYS_ERR(EAGAIN));
 assert(unix_calls==1 && unix_force_nb==1);
 send_budget=2;unix_calls=0;
 assert(sys_sendto(1,(uintptr_t)data,4,MSG_DONTWAIT,0,0)==2 && unix_calls==1);
 unix_calls=0;
 assert(sys_sendto(1,(uintptr_t)data,4,0,0,0)==SYS_ERR(EAGAIN) && !unix_force_nb);
 puts("socket send: datagram atomicity, bounds, faults, empty messages, TCP per-call nonblocking: ok");
}
'''
with tempfile.TemporaryDirectory(prefix='aegis-send-') as tmp:
    path = Path(tmp) / 'test.c'
    binary = Path(tmp) / 'test'
    path.write_text(code)
    subprocess.run([os.environ.get('HOSTCC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-function', '-Wno-unused-variable', str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
