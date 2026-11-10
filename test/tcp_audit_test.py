#!/usr/bin/env python3
"""Execute production tcp.c/ip.c with host allocator, NIC and wakeup stubs.

Run: python3 test/tcp_audit_test.py (CC selects the host C compiler).
SANITIZERS defaults to address,undefined; set it to undefined or "" on hosts
where the ASan runtime cannot start. Compilation and execution are bounded.
The full protocol translation units and real headers are compiled, not a
reimplementation of the state machine. No hardware, SMP or user copies run.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def code(path):
    return re.sub(r"(?m)^#include.*\n", "", (ROOT / path).read_text())


PROGRAM = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#undef htons
#undef ntohs
#undef htonl
#undef ntohl
''' + "".join(code(path) for path in (
    "kernel/net/net.h", "kernel/net/netdev.h", "kernel/net/ip.h",
    "kernel/limits.h", "kernel/net/tcp.h",
)) + r'''
#define kmemset memset
#define kmemcpy memcpy
static void printk(const char *fmt, ...) { (void)fmt; }
typedef unsigned spinlock_t;
typedef unsigned irqflags_t;
#define SPINLOCK_INIT 0
static unsigned held;
static irqflags_t spin_lock_irqsave(spinlock_t *p) {
    assert(!*p); *p=1; held++; return 0;
}
static void spin_unlock_irqrestore(spinlock_t *p, irqflags_t f) {
    (void)f; assert(*p && held); *p=0; held--;
}
#define SOCK_NONE UINT32_MAX
#define SOCK_CLOSED 0
#define SOCK_CONNECTING 1
#define SOCK_CONNECTED 2
#define EPOLLIN 1
#define EPOLLOUT 4
#define EPOLLERR 8
#define EPOLLHUP 16
typedef struct { unsigned wakes; } waitq_t;
typedef struct { unsigned state; waitq_t poll_waiters; } sock_t;
static sock_t socks[16];
static sock_t *sock_get(uint32_t id) {
    assert(!held); return id<16 ? &socks[id] : NULL;
}
static void waitq_wake_all(waitq_t *q) { assert(!held); q->wakes++; }
static void sock_wake(uint32_t id) { assert(!held && id<16); }
static void epoll_notify(uint32_t id, uint32_t events) {
    assert(!held && id<16 && events);
}
static uint32_t ticks=1;
static uint64_t arch_get_ticks(void) { return ticks; }
static const char *arch_get_cmdline(void) { return NULL; }
static int random_get_bytes(void *out, size_t n) {
    static uint32_t isn=10000;
    assert(n<=sizeof(isn)); isn+=1000; memcpy(out,&isn,n); return 0;
}
static unsigned pages, alloc_calls, fail_at;
static void *kva_alloc_pages(uint64_t n) {
    if (++alloc_calls==fail_at) return NULL;
    void *p=malloc(n*4096); assert(p); pages+=n; return p;
}
static void kva_free_pages(void *p, uint64_t n) {
    assert(p && pages>=n); pages-=n; free(p);
}
static netdev_t nic;
netdev_t *netdev_get(const char *name) { (void)name; return &nic; }
#define ETHERTYPE_IP 0x0800
static unsigned sent, udp_delivered;
static uint8_t last_packet[1500];
static uint16_t last_len;
static int arp_resolve(netdev_t *d, ip4_addr_t ip, mac_addr_t *mac) {
    (void)d; (void)ip; memset(mac,0,sizeof(*mac)); return 0;
}
static int eth_send(netdev_t *d, const mac_addr_t *mac, uint16_t type,
                    const void *p, uint16_t len) {
    (void)d; (void)mac; assert(type==ETHERTYPE_IP && len<=1500);
    memcpy(last_packet,p,len); last_len=len; sent++; return 0;
}
static void udp_rx(netdev_t *d, ip4_addr_t src, ip4_addr_t dst,
                    const void *p, uint16_t len) {
    (void)d; (void)src; (void)dst; (void)p; (void)len; udp_delivered++;
}
static void eth_init(void) {}
static void udp_init(void) {}
static void ipv6_init(netdev_t *d) { (void)d; }
static void ipv6_selftest(netdev_t *d) { (void)d; }
''' + code("kernel/net/tcp.c") + code("kernel/net/ip.c") + r'''
static const uint32_t me_host=0x0a00020f, peer_host=0x0a000202;
static ip4_addr_t me(void) { return htonl(me_host); }
static ip4_addr_t peer(void) { return htonl(peer_host); }
static void reset(void) {
    assert(!held);
    for(unsigned i=0;i<TCP_MAX_CONNS;i++) {
        if(s_tcp[i].rbuf) kva_free_pages(s_tcp[i].rbuf,TCP_RBUF_SIZE/4096);
        if(s_tcp[i].sbuf) kva_free_pages(s_tcp[i].sbuf,TCP_SBUF_SIZE/4096);
    }
    assert(!pages);
    tcp_init(); memset(socks,0,sizeof(socks));
    s_lo_head=s_lo_tail=s_lo_draining=0;
    ticks=1; alloc_calls=fail_at=sent=udp_delivered=0;
    net_set_config(me(),htonl(0xffffff00),peer());
}
static void inject_to(ip4_addr_t dst, uint16_t port, uint16_t remote_port,
                       uint8_t flags, uint32_t seq, uint32_t ack,
                       const void *data, uint16_t n, uint8_t proto) {
    struct {
        ip_hdr_t ip;
        tcp_hdr_t tcp;
        uint8_t data[1400];
    } pkt={0};
    assert(n<=sizeof(pkt.data));
    pkt.ip.ver_ihl=0x45;
    pkt.ip.total_len=htons(40+n); pkt.ip.ttl=64;
    pkt.ip.proto=proto; pkt.ip.src=peer(); pkt.ip.dst=dst;
    pkt.ip.checksum=net_checksum_finish(net_checksum(&pkt.ip,20));
    pkt.tcp.src_port=htons(remote_port); pkt.tcp.dst_port=htons(port);
    pkt.tcp.seq=htonl(seq); pkt.tcp.ack=htonl(ack);
    pkt.tcp.data_off=0x50; pkt.tcp.flags=flags;
    pkt.tcp.window=htons(65535);
    if(n) memcpy(pkt.data,data,n);
    tcp_pseudo_hdr_t ph={.src=peer(),.dst=dst,.proto=IP_PROTO_TCP,
                          .tcp_len=htons(20+n)};
    pkt.tcp.checksum=net_checksum_finish(net_checksum(&ph,sizeof(ph))+
                                        net_checksum(&pkt.tcp,20+n));
    ip_rx(&nic,&nic,&pkt,40+n);
    assert(!held);
}
static void inject(tcp_conn_t *c, uint8_t flags, uint32_t seq, uint32_t ack,
                    const void *data, uint16_t n) {
    inject_to(c->local_ip,c->local_port,c->remote_port,flags,seq,ack,data,n,IP_PROTO_TCP);
}
static tcp_conn_t *half_open(uint16_t remote_port) {
    inject_to(me(),8080,remote_port,TCP_SYN,500,0,NULL,0,IP_PROTO_TCP);
    tcp_conn_t *c=tcp_find(peer(),remote_port,me(),8080);
    assert(c && c->state==TCP_SYN_RCVD); return c;
}
static tcp_hdr_t last_tcp(void) {
    tcp_hdr_t hdr; assert(last_len>=40);
    memcpy(&hdr,last_packet+20,sizeof(hdr)); return hdr;
}
static void assert_reply(uint8_t flags, uint32_t ack) {
    tcp_hdr_t hdr=last_tcp();
    assert(hdr.flags==flags && ntohl(hdr.ack)==ack);
    const ip_hdr_t *ip=(const ip_hdr_t *)last_packet;
    assert(net_checksum_finish(net_checksum(ip,20))==0);
    tcp_pseudo_hdr_t ph={.src=ip->src,.dst=ip->dst,.proto=IP_PROTO_TCP,
                          .tcp_len=htons(last_len-20)};
    assert(net_checksum_finish(net_checksum(&ph,sizeof(ph))+
                                net_checksum(last_packet+20,last_len-20))==0);
}
static void expire_half_opens(void) {
    for(unsigned round=0;round<=TCP_RETRANSMIT_MAX;round++) {
        ticks+=TCP_RTO_MAX+1; tcp_tick();
    }
}
static void test_passive_memory(void) {
    reset(); assert(tcp_listen(8080,1)==0);
    for(unsigned cycle=0;cycle<4;cycle++) {
        for(unsigned i=0;i<TCP_SYN_BACKLOG_MAX;i++) {
            tcp_conn_t *c=half_open(1000+i);
            assert(!c->rbuf && !c->sbuf && !pages && !alloc_calls);
        }
        unsigned before=sent;
        inject_to(me(),8080,9000,TCP_SYN,500,0,NULL,0,IP_PROTO_TCP);
        assert(sent==before); /* backlog remains bounded */
        expire_half_opens();
        for(unsigned i=0;i<TCP_MAX_CONNS;i++)
            assert(s_tcp[i].state==TCP_CLOSED || s_tcp[i].state==TCP_LISTEN);
        assert(!pages && !alloc_calls);
    }
    tcp_conn_t *c=half_open(2000);
    assert_reply(TCP_SYN|TCP_ACK,501);
    inject(c,TCP_ACK,502,c->snd_nxt,NULL,0); /* wrong receive sequence */
    inject(c,TCP_ACK,501,c->snd_nxt+1,NULL,0); /* wrong ACK */
    assert(c->state==TCP_SYN_RCVD && !alloc_calls);
    /* Final ACK data and FIN must not be lost at the allocation boundary. */
    inject(c,TCP_ACK|TCP_FIN,501,c->snd_nxt,"abc",3);
    assert(c->state==TCP_CLOSE_WAIT && c->rcv_nxt==505);
    assert(c->rbuf && c->sbuf && pages==80 && alloc_calls==2);
    assert(c->rbuf_tail==3 && !memcmp(c->rbuf,"abc",3));
    assert_reply(TCP_ACK,505);
    tcp_conn_t out;
    assert(tcp_accept(1,2,&out)==(int)(c-s_tcp) && out.rbuf==c->rbuf);
    uint8_t *rb=c->rbuf,*sb=c->sbuf;
    tcp_conn_abort(2,(uint32_t)(c-s_tcp));
    c=half_open(2001); /* reused rings add no residency */
    assert(c->rbuf==rb && c->sbuf==sb && alloc_calls==2);
    expire_half_opens();
    assert(c->state==TCP_CLOSED && pages==80 && alloc_calls==2);
    puts("passive SYN flood/timeout, final ACK sequence/data/FIN, pooled reuse: ok");
}
static void test_allocation_failure(void) {
    for(unsigned fail=1;fail<=2;fail++) {
        reset(); assert(tcp_listen(8080,1)==0);
        tcp_conn_t *c=half_open(2000);
        fail_at=fail;
        inject(c,TCP_ACK,501,c->snd_nxt,NULL,0);
        assert(c->state==TCP_CLOSED && !c->retransmit_at);
        assert(!c->rbuf && !c->sbuf && !pages && !tcp_accept_ready(1));
        assert_reply(TCP_RST|TCP_ACK,501);
        fail_at=0; c=half_open(2001);
        inject(c,TCP_ACK,501,c->snd_nxt,NULL,0);
        assert(c->state==TCP_ESTABLISHED && pages==80);
    }
    reset(); assert(tcp_listen(8080,1)==0);
    tcp_conn_t *listener=tcp_find_listener(me(),8080);
    listener->accept_tail=8; /* no allocation when delivery is impossible */
    tcp_conn_t *c=half_open(2000);
    inject(c,TCP_ACK,501,c->snd_nxt,NULL,0);
    assert(c->state==TCP_CLOSED && !alloc_calls);
    puts("passive RX/TX allocation rollback, retry, full accept queue: ok");
}
static void test_outbound(void) {
    uint32_t id=UINT32_MAX;
    for(unsigned fail=1;fail<=2;fail++) {
        reset(); fail_at=fail;
        assert(tcp_connect(2,peer(),8080,&id)==-ENOMEM);
        assert(!pages && !sent && id==UINT32_MAX);
    }
    reset(); socks[2].state=SOCK_CONNECTING;
    assert(tcp_connect(2,peer(),8080,&id)==0);
    tcp_conn_t *c=&s_tcp[id];
    assert(c->state==TCP_SYN_SENT && c->rbuf && c->sbuf && pages==80);
    inject(c,TCP_SYN|TCP_ACK,800,c->snd_nxt,NULL,0);
    assert(c->state==TCP_ESTABLISHED && socks[2].state==SOCK_CONNECTED);
    inject(c,TCP_ACK,801,c->snd_nxt,"reply",5);
    char buf[8]; assert(tcp_conn_recv(2,id,buf,sizeof(buf))==5);
    assert(!memcmp(buf,"reply",5));
    reset(); socks[2].state=SOCK_CONNECTING;
    net_set_config(0,0,0); /* NIC-less loopback source is the destination */
    assert(tcp_connect(2,htonl(0x7f000001),8080,&id)==0);
    assert(tcp_listen(8080,1)==0);
    ip_loopback_poll(); /* full active + passive handshake through actual IPv4 */
    assert(s_tcp[id].state==TCP_ESTABLISHED && tcp_accept_ready(1) && pages==160);
    puts("outbound synchronous ENOMEM, SYN-ACK, data, real loopback handshake: ok");
}
static void test_broadcast(void) {
    reset(); assert(tcp_listen(8080,1)==0);
    ip4_addr_t broadcasts[]={htonl(0xffffffff),htonl(me_host|0xff)};
    for(unsigned i=0;i<2;i++) {
        for(unsigned port=8080;port<=8081;port++)
            inject_to(broadcasts[i],port,2000,TCP_SYN,500,0,NULL,0,IP_PROTO_TCP);
        assert(!sent && !alloc_calls);
        assert(!tcp_find(peer(),2000,broadcasts[i],8080));
        inject_to(broadcasts[i],68,67,0,0,0,NULL,0,IP_PROTO_UDP);
        assert(udp_delivered==i+1);
    }
    net_set_config(0,0,0); /* DHCP bootstrap must still reach UDP */
    inject_to(htonl(0xffffffff),68,67,0,0,0,NULL,0,IP_PROTO_UDP);
    inject_to(htonl(0xffffffff),8080,2000,TCP_SYN,500,0,NULL,0,IP_PROTO_TCP);
    assert(udp_delivered==3 && !sent && !alloc_calls);
    net_set_config(me(),htonl(0xffffff00),peer());
    tcp_conn_t *c=half_open(2000); assert(c && sent==1);
    /* /31 and /32 local unicast must not be mistaken for broadcasts. */
    for(unsigned prefix=31;prefix<=32;prefix++) {
        reset(); assert(tcp_listen(8080,1)==0);
        net_set_config(me(),htonl(prefix==31 ? 0xfffffffe : 0xffffffff),peer());
        assert(half_open(2000) && sent==1);
    }
    puts("limited/directed broadcast TCP suppression, UDP/DHCP and unicast: ok");
}
static tcp_conn_t *receive_conn(tcp_state_t state, uint32_t next) {
    reset(); tcp_conn_t *c=tcp_alloc(); assert(c);
    assert(tcp_attach_buffers(c)==0);
    c->state=state; c->dev=&nic; c->local_ip=me(); c->remote_ip=peer();
    c->local_port=8080; c->remote_port=2000; c->sock_id=2;
    c->rcv_nxt=next; c->snd_nxt=100; c->snd_una=99;
    c->retransmit_at=1000;
    return c;
}
static tcp_state_t fin_state(tcp_state_t state) {
    return state==TCP_ESTABLISHED ? TCP_CLOSE_WAIT :
           state==TCP_FIN_WAIT_1 ? TCP_CLOSING : TCP_TIME_WAIT;
}
static void test_fin(void) {
    tcp_state_t states[]={TCP_ESTABLISHED,TCP_FIN_WAIT_1,TCP_FIN_WAIT_2};
    for(unsigned i=0;i<3;i++) {
        tcp_state_t state=states[i];
        tcp_conn_t *c=receive_conn(state,500);
        inject(c,TCP_FIN,501,0,NULL,0);
        inject(c,TCP_FIN,499,0,NULL,0);
        assert(c->state==state && c->rcv_nxt==500);
        assert_reply(TCP_ACK,500);
        inject(c,TCP_FIN,500,0,NULL,0);
        assert(c->state==fin_state(state) && c->rcv_nxt==501);
        assert_reply(TCP_ACK,501);
        if(state==TCP_FIN_WAIT_1) assert(c->retransmit_at==1000);
        if(state==TCP_FIN_WAIT_2) assert(c->timewait_at==ticks+TCP_TIMEWAIT_TICKS);

        c=receive_conn(state,500);
        inject(c,TCP_FIN,501,0,"gap",3);
        assert(c->state==state && c->rcv_nxt==500 && !c->rbuf_tail);
        c->rbuf_tail=TCP_RBUF_SIZE-2; /* only one byte free */
        inject(c,TCP_FIN,500,0,"abc",3);
        assert(c->state==state && c->rcv_nxt==500 && c->rbuf_tail==TCP_RBUF_SIZE-2);
        c->rbuf_head=c->rbuf_tail;
        inject(c,TCP_FIN,500,0,"abc",3); /* receive ring wraps */
        assert(c->state==fin_state(state) && c->rcv_nxt==504);
        char buf[4]={0}; assert(tcp_conn_recv(2,0,buf,3)==3 && !memcmp(buf,"abc",3));

        c=receive_conn(state,500);
        inject(c,TCP_ACK,500,99,"abc",3);
        assert(c->rcv_nxt==503);
        inject(c,TCP_FIN,500,0,"abc",3); /* retransmitted data + new FIN */
        assert(c->state==fin_state(state) && c->rcv_nxt==504 && c->rbuf_tail==3);
        c=receive_conn(state,UINT32_MAX-1);
        inject(c,TCP_FIN,UINT32_MAX-1,0,"abc",3);
        assert(c->state==fin_state(state) && c->rcv_nxt==2);
    }
    /* ACKing our FIN is independent of accepting the peer's FIN position. */
    tcp_conn_t *c=receive_conn(TCP_FIN_WAIT_1,500);
    inject(c,TCP_ACK|TCP_FIN,501,100,NULL,0);
    assert(c->state==TCP_FIN_WAIT_2 && c->rcv_nxt==500 && !c->retransmit_at);
    inject(c,TCP_ACK|TCP_FIN,500,100,NULL,0);
    assert(c->state==TCP_TIME_WAIT && c->rcv_nxt==501);
    c=receive_conn(TCP_FIN_WAIT_1,500);
    inject(c,TCP_ACK|TCP_FIN,500,100,"abc",3);
    assert(c->state==TCP_TIME_WAIT && c->rcv_nxt==504);
    c=receive_conn(TCP_FIN_WAIT_1,500);
    inject(c,TCP_ACK|TCP_FIN,500,101,NULL,0); /* acknowledges unsent sequence */
    assert(c->state==TCP_FIN_WAIT_1 && c->rcv_nxt==500);
    puts("ESTABLISHED/FIN_WAIT FIN sequence, payload/gaps/full ring/wrap/ACK: ok");
}
static void test_finwait2_reclaim(void) {
    /* CVE-2026-68379 class (unbounded retention in a teardown state): a peer
     * that ACKs our FIN and then never sends its own must not pin the slot and
     * its 320 KiB ring pair forever.  FIN_WAIT_2 has no RTO, so this is the
     * only state that used to have no deadline at all. */
    tcp_conn_t *c=receive_conn(TCP_FIN_WAIT_1,500);
    inject(c,TCP_ACK,100,100,NULL,0);           /* ACK of our FIN */
    assert(c->state==TCP_FIN_WAIT_2 && !c->retransmit_at);
    assert(c->finwait2_at==ticks+TCP_FINWAIT2_TICKS);
    unsigned wakes=socks[2].poll_waiters.wakes;

    ticks+=TCP_FINWAIT2_TICKS-1; tcp_tick();
    assert(c->state==TCP_FIN_WAIT_2);           /* inside the deadline */
    inject(c,TCP_ACK,100,100,NULL,0);           /* dup ACK must not extend it */
    assert(c->finwait2_at==1+TCP_FINWAIT2_TICKS);

    ticks+=2; tcp_tick();
    assert(c->state==TCP_CLOSED);               /* reclaimed, not leaked */
    assert(socks[2].poll_waiters.wakes==wakes+1); /* blocked reader sees EOF */
    tcp_conn_t *fresh=tcp_alloc();
    assert(fresh==c && fresh->state==TCP_CLOSED);  /* slot reused from the pool */
    tcp_claim_slot((uint32_t)(fresh-s_tcp));

    /* A peer that does send its FIN still reaches TIME_WAIT normally. */
    c=receive_conn(TCP_FIN_WAIT_1,500);
    inject(c,TCP_ACK,100,100,NULL,0);
    assert(c->state==TCP_FIN_WAIT_2);
    inject(c,TCP_FIN,500,100,NULL,0);
    assert(c->state==TCP_TIME_WAIT && c->timewait_at==ticks+TCP_TIMEWAIT_TICKS);
    ticks+=TCP_TIMEWAIT_TICKS; tcp_tick();
    assert(c->state==TCP_CLOSED);
    puts("FIN_WAIT_2 deadline (peer never sends FIN), TIME_WAIT still bounded: ok");
}
static void test_timewait_reacks_fin(void) {
    /* RFC 793 3.9: a retransmitted FIN in TIME_WAIT must be acknowledged, or
     * the peer repeats it until it errors out.  The 2MSL deadline must not be
     * extended by the repeat (a replay could otherwise pin the slot). */
    tcp_conn_t *c=receive_conn(TCP_TIME_WAIT,501);
    c->timewait_at=ticks+TCP_TIMEWAIT_TICKS;
    unsigned before=sent, wake=c->timewait_at;

    inject(c,TCP_FIN,500,0,NULL,0);
    assert(sent==before+1);
    assert_reply(TCP_ACK,501);
    assert(c->state==TCP_TIME_WAIT && c->timewait_at==wake);

    inject(c,TCP_RST,500,0,NULL,0);
    assert(sent==before+1);                     /* RST is ignored */
    inject(c,TCP_ACK,500,0,"dup",3);
    assert(sent==before+1);                     /* dup data already acked */
    assert(c->state==TCP_TIME_WAIT);
    puts("TIME_WAIT re-ACKs retransmitted FIN without extending 2MSL: ok");
}
int main(void) {
    test_passive_memory(); test_allocation_failure(); test_outbound();
    test_broadcast(); test_fin();
    test_finwait2_reclaim(); test_timewait_reacks_fin();
    reset(); assert(!pages && !held);
    puts("TCP/IPv4 audit regressions: all passed");
}
'''

with tempfile.TemporaryDirectory(prefix="aegis-tcp-audit-") as tmp:
    path = Path(tmp) / "tcp_audit.c"
    path.write_text(PROGRAM)
    exe = path.with_suffix("")
    sanitizers = os.environ.get("SANITIZERS", "address,undefined")
    sanitizer_flags = [f"-fsanitize={sanitizers}"] if sanitizers else []
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1", "-g",
                    "-Wall", "-Wextra", "-Werror", *sanitizer_flags,
                    str(path), "-o", str(exe)], check=True, timeout=60)
    subprocess.run([str(exe)], check=True, timeout=30)

# A sequential host harness cannot demonstrate weak-memory reordering. Guard
# the producer's cross-lock publication/reuse edges explicitly as well.
udp = code("kernel/net/udp.c")
assert "__atomic_load_n(&s->udp_rx_head, __ATOMIC_ACQUIRE)" in udp
assert "__atomic_store_n(&s->udp_rx_tail, next, __ATOMIC_RELEASE)" in udp
print("UDP producer acquire-head/release-tail ordering guards: ok")
