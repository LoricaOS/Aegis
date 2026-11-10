#!/usr/bin/env python3
"""Run AX200 production DMA ownership helpers with ASan/UBSan host stubs.

No NIC is emulated: this checks descriptor construction, fixed allocation
bounds, completion parsing, failure retention and reuse beyond ring wrap.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "kernel/drivers/iwl_ax200.c").read_text()


def function(name):
    m = re.search(r"(?m)^static(?: inline)?[\w *]+\s*" + name + r"\([^;]*?\)\n\{", TEXT)
    assert m, name
    pos = TEXT.index("{", m.start())
    depth = 1
    end = pos + 1
    while depth:
        depth += (TEXT[end] == "{") - (TEXT[end] == "}")
        end += 1
    return TEXT[m.start():end] + "\n"


C = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int spinlock_t;
typedef int irqflags_t;
#define SPINLOCK_INIT 0
static irqflags_t spin_lock_irqsave(spinlock_t *l) { assert(!*l); *l=1; return 0; }
static void spin_unlock_irqrestore(spinlock_t *l, irqflags_t f) { (void)f;assert(*l);*l=0; }
#define CMD_Q_ID 0
#define QUEUE_TO_SEQ(q) (((q)&0x1f)<<8)
#define INDEX_TO_SEQ(i) ((i)&0xff)
#define IWL_FIRST_TB_SIZE 20
#define HBUS_TARG_WRPTR 0x460
#define CSR_INT 8
#define CSR_INT_BIT_SW_ERR (1u<<25)
#define CSR_INT_BIT_HW_ERR (1u<<29)
#define printk(...) ((void)0)
static void dump_fw_error(void) {}
static void busy_wait_us(uint32_t n) { (void)n; }
static uint32_t csr_rd(uint32_t r) { (void)r; return CSR_INT_BIT_SW_ERR; }
static unsigned doorbells;
static void csr_wr(uint32_t r,uint32_t v) { (void)v;assert(r==HBUS_TARG_WRPTR);doorbells++; }
static volatile uint8_t *s_cmd_ring;
static uint16_t s_cmd_wr,s_rx_read;
static volatile uint16_t rx_closed;
static volatile uint8_t *s_rb_stts=(volatile uint8_t *)&rx_closed;
static uint8_t s_rx_copy[4096],input[4096];
static const uint8_t *rx_at(uint16_t i) { (void)i; return input; }
static void rx_restock(uint16_t i) { (void)i; }
'''
a = TEXT.index("#define AX_DMA_SLOT_SIZE")
b = TEXT.index("static uint8_t s_tx_resp_ver, s_ba_notif_ver;") + len("static uint8_t s_tx_resp_ver, s_ba_notif_ver;")
C += TEXT[a:b] + r'''
static unsigned allocated,fail_alloc;
static void *kva_alloc_pages_low(uint64_t n) {
    assert(!s_tx_lock);
    if(fail_alloc && --fail_alloc==0) return NULL;
    allocated += n; return calloc(n,4096);
}
static uint64_t kva_page_phys(void *p) { return (uintptr_t)p; }
static void *dma_alloc(uint64_t bytes,uint64_t *phys) {
    void *p=kva_alloc_pages_low((bytes+4095)/4096);*phys=(uintptr_t)p;return p;
}
'''
for name in ("rd_le16", "rd_le32", "wr_le32b", "mcopy", "dma_slots_init", "set_tfd_tb",
             "tx_reclaim_locked", "tx_complete", "rx_take", "send_cmd", "send_frame", "alloc_tx_queue"):
    C += function(name)
# Exercise the production association builder without emulating a radio/auth flow.
connect = function("do_connect")
assoc_start = connect.index("    int ssid_len = 0;")
assoc_end = connect.index("    rx_skip_pending();", assoc_start)
C += r'''
static void check_association(unsigned length,int secured) {
    char s_target_ssid[33];memset(s_target_ssid,'S',sizeof(s_target_ssid));
    s_target_ssid[length]=0;
    const uint8_t s_ap_bssid[6]={1,2,3,4,5,6},s_our_mac[6]={7,8,9,10,11,12};
    int s_ap_sec=secured;
''' + connect[assoc_start:assoc_end] + r'''
    assert(sizeof(a)==100 && an==(int)(46+length+22*secured));
    assert(a[0]==0 && !memcmp(a+4,s_ap_bssid,6) && !memcmp(a+10,s_our_mac,6));
    assert(!memcmp(a+16,s_ap_bssid,6) && a[24]==(secured ? 0x11 : 1));
    assert(a[28]==0 && a[29]==length && !memcmp(a+30,s_target_ssid,length));
    unsigned offset=28,elements=0;
    while(offset<(unsigned)an) {
        assert(offset+2<=sizeof(a));
        offset+=2+a[offset+1];assert(offset<=(unsigned)an);elements++;
    }
    assert(offset==(unsigned)an && elements==(unsigned)(3+secured));
    if(secured) assert(a[an-22]==48 && a[an-21]==20 && a[an-3]==2);
}
static void notification_version(uint8_t command,uint8_t group,uint8_t version) {
    uint8_t tdata[4]={command,group,0,version};
    uint32_t o=0;uint8_t c=command,g=group;
'''
version_start = TEXT.index("                uint8_t nv = tdata[o+3]")
version_end = TEXT.index("\n", TEXT.index("s_ba_notif_ver=nv;", version_start))
C += TEXT[version_start:version_end] + "\n}\n"
C += r'''
static void le16(uint8_t *p,uint16_t v) {p[0]=v;p[1]=v>>8;}
static void response(uint8_t *p,unsigned q,unsigned next) {
    memset(p,0,4096);wr_le32b(p,52);p[4]=0x1c;p[8]=1;
    le16(p+44,q);wr_le32b(p+52,next);
}
static void setup(struct ax_txq *q,unsigned slots,unsigned id) {
    q->slots=slots;q->qid=id;
    q->ring=calloc(TXQ_SLOTS,256);q->bc=calloc(1,4096);
    assert(dma_slots_init(&q->buffers,q->buffer_phys,slots)==0);
}
static uint64_t tb_addr(const volatile uint8_t *tfd,unsigned tb) {
    uint64_t p=0;for(unsigned i=0;i<8;i++)p|=(uint64_t)tfd[4+tb*10+i]<<(8*i);return p;
}
int main(void) {
    for(unsigned length=0;length<=32;length++)
        for(int secured=0;secured<2;secured++)check_association(length,secured);
    setup(&s_mgmt_q,128,2); setup(&s_data_q,256,257);
    s_cmd_ring=calloc(AX_CMD_SLOTS,256);
    assert(dma_slots_init(&s_cmd_buffers,s_cmd_buffer_phys,AX_CMD_SLOTS)==0);
    unsigned baseline=allocated;
    uint8_t frame[1600]={0};
    assert(send_frame(&s_data_q,frame,1500,24,0,"data")==0);
    assert(tb_addr(s_data_q.ring,0)==s_data_q.buffer_phys[0]+AX_FIRST_TB_OFF);
    assert(tb_addr(s_data_q.ring,1)==s_data_q.buffer_phys[0]+IWL_FIRST_TB_SIZE);
    assert(tb_addr(s_data_q.ring,2)==s_data_q.buffer_phys[0]+48);
    assert(send_frame(&s_data_q,frame,5000,24,0,"oversize")<0);
    assert(send_frame(&s_data_q,frame,24,26,0,"bad header")<0);
    for(unsigned i=1;i<255;i++) assert(send_frame(&s_data_q,frame,100,24,0,"fill")==0);
    unsigned bells=doorbells;
    assert(send_frame(&s_data_q,frame,100,24,0,"full")<0 && doorbells==bells);
    response(input,257,255);
    tx_complete(input,55);assert(s_data_q.rd==0); /* truncated SSN */
    s_tx_resp_ver=8;tx_complete(input,56);assert(s_data_q.rd==0);
    notification_version(0x1c,1,0xff);tx_complete(input,56);assert(s_data_q.rd==0);
    notification_version(0x1c,0,99);assert(s_tx_resp_ver==0);
    s_tx_resp_ver=7;input[8]=2;tx_complete(input,56);assert(s_data_q.rd==0);
    input[8]=1;tx_complete(input,56);assert(s_data_q.rd==255);
    /* More than a dozen full wraps without allocating one more DMA page. */
    for(unsigned i=0;i<4096;i++) {
        assert(send_frame(&s_data_q,frame,sizeof(frame),24,0,"stream")==0);
        response(input,257,s_data_q.wr); assert(rx_take());
        assert(s_data_q.rd==s_data_q.wr && allocated==baseline);
    }
    /* Completion outside the outstanding interval cannot release live slots. */
    for(unsigned i=0;i<3;i++)assert(send_frame(&s_data_q,frame,100,24,0,"batch")==0);
    unsigned rd=s_data_q.rd;
    response(input,257,(rd-1)&255);tx_complete(input,56);assert(s_data_q.rd==rd);
    response(input,257,(s_data_q.wr+1)&255);tx_complete(input,56);assert(s_data_q.rd==rd);
    response(input,444,s_data_q.wr);tx_complete(input,56);assert(s_data_q.rd==rd);
    /* Compressed BA: reject partial arrays, then reclaim the complete one. */
    memset(input,0,4096);input[4]=0xc5;le16(input+36,2);le16(input+40,257);
    le16(input+42,s_data_q.wr);tx_complete(input,48);assert(s_data_q.rd==rd);
    le16(input+36,1);le16(input+38,1);tx_complete(input,48);assert(s_data_q.rd==rd);
    le16(input+38,0);s_ba_notif_ver=6;tx_complete(input,48);assert(s_data_q.rd==rd);
    notification_version(0xc5,0,0xff);tx_complete(input,48);assert(s_data_q.rd==rd);
    notification_version(0xc5,1,99);assert(s_ba_notif_ver==0);
    tx_complete(input,48);assert(s_data_q.rd==s_data_q.wr);
    /* Host command ring cannot reuse an outstanding command or an earlier hole. */
    for(unsigned i=0;i<31;i++)assert(send_cmd(0x117,frame,76)==0);
    assert(send_cmd(0x117,frame,76)<0);
    memset(input,0,4096);input[4]=0x17;input[5]=1;le16(input+6,0x8000);
    tx_complete(input,8);assert(s_cmd_pending[0]);
    le16(input+6,0x2000);tx_complete(input,8);assert(s_cmd_pending[0]);
    le16(input+6,0);input[4]=0x18;tx_complete(input,8);assert(s_cmd_pending[0]);
    input[4]=0x17;le16(input+6,1);tx_complete(input,8);
    assert(!s_cmd_pending[1] && s_cmd_rd==0 && send_cmd(0x117,frame,76)<0);
    le16(input+6,0);tx_complete(input,8);assert(s_cmd_rd==2);
    assert(send_cmd(0x118,frame,76)==0 && send_cmd(0x118,frame,76)==0);
    tx_complete(input,8);assert(s_cmd_pending[0]); /* stale different command */
    for(unsigned i=0;i<AX_CMD_SLOTS;i++) {
        input[4]=s_cmd_id[i]&255;input[5]=s_cmd_id[i]>>8;le16(input+6,i);tx_complete(input,8);
    }
    assert(s_cmd_rd==s_cmd_wr && allocated==baseline);
    assert(send_cmd(0x117,frame,AX_FIRST_TB_OFF)<0);
    /* Failed queue setup retains only bounded allocations. A submitted,
     * timed-out queue must never be reset or republished into live DMA. */
    struct ax_txq failed={.qid=-1};
    fail_alloc=2; assert(alloc_tx_queue(&failed,15)<0);
    assert(failed.ring && !failed.bc);
    unsigned after_partial=allocated;
    assert(alloc_tx_queue(&failed,15)<0 && failed.submitted);
    assert(allocated==after_partial+1+128);
    unsigned after_submit=allocated;
    for(unsigned i=0;i<100;i++)assert(alloc_tx_queue(&failed,15)<0 && allocated==after_submit);
    assert(!s_tx_lock);
    free((void *)failed.ring);free((void *)failed.bc);free(failed.buffers);
    puts("AX200 fixed DMA bound, TX/command ownership, completion versions, wrap, retries and 32-byte SSID: ok");
}
'''
with tempfile.TemporaryDirectory(prefix="aegis-driver-security-") as temp:
    path=Path(temp)/"test.c";path.write_text(C)
    exe=Path(temp)/"test"
    subprocess.run([os.environ.get("CC","cc"),"-std=c11","-O1","-g",
                    "-fsanitize=address,undefined",str(path),"-o",str(exe)],check=True)
    subprocess.run([str(exe)],check=True)

# Prohibit hot-path or scan DMA allocation.
assert "dma_alloc(" not in function("send_frame")
assert "dma_alloc(" not in function("send_cmd")
assert "dma_alloc(" not in function("do_scan")
assert "tx_complete(" in function("rx_take")
