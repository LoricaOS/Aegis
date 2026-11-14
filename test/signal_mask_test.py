#!/usr/bin/env python3
"""Host regression for production signal-mask and suspend helpers (not a VM test)."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
def extract(path,name):
    s=(ROOT/path).read_text(); pos=s.index(name+'('); start=s.rfind('\n',0,pos)+1
    if not s[start:pos].strip(): start=s.rfind('\n',0,start-1)+1
    brace=s.index('{',pos);end=brace+1;depth=1
    while depth:
        depth+=(s[end]=='{')-(s[end]=='}');end+=1
    return s[start:end]
header=r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#undef sa_handler
/* libc's sa_handler macro is not applicable to the kernel structure. */
typedef struct {void (*sa_handler)(int);uint64_t sa_flags;void (*sa_restorer)(void);uint64_t sa_mask;} k_sigaction_t;
typedef struct { uint64_t signal_mask,pending_signals,suspend_saved_mask;uint32_t suspend_restore,stop_signum; k_sigaction_t sigactions[64]; int is_user;} aegis_process_t;
typedef aegis_process_t aegis_task_t;
static aegis_process_t p;
static int blocks,stops;
static aegis_process_t *current_proc(void){return &p;}
static aegis_task_t *sched_current(void){return &p;}
static void caught(int sig){(void)sig;}
static int user_ptr_valid(uint64_t ptr,uint64_t n){(void)ptr;(void)n;return 1;}
static void sched_block(void){
    ++blocks;assert(blocks<8);
    if(blocks==2) p.pending_signals |= 1ULL<<SIGCHLD; /* ignored wake */
    if(blocks==3) p.pending_signals |= 1ULL<<SIGUSR1; /* handler wake */
}
static void sched_stop(aegis_task_t *t){++stops;t->pending_signals|=1ULL<<SIGCONT;}
#define COPY_FROM_USER(dst,src) memcpy((dst),(void *)(uintptr_t)(src),sizeof(*(dst)))
#define COPY_TO_USER(dst,src) memcpy((void *)(uintptr_t)(dst),(src),sizeof(*(src)))
#define SYS_ERR(e) ((uint64_t)(-(int64_t)(e)))
'''
parts=[('kernel/signal/signal.h','signal_mask_from_user'),('kernel/signal/signal.h','signal_mask_to_user'),('kernel/signal/signal.c','signal_check_pending'),('kernel/signal/signal.c','signal_next_delivery'),('kernel/signal/signal.c','signal_frame_mask'),('kernel/syscall/sys_signal.c','sys_rt_sigprocmask'),('kernel/syscall/sys_signal.c','sys_rt_sigaction'),('kernel/syscall/sys_signal.c','sys_rt_sigsuspend')]
main=r'''
static uint64_t libc_mask(int sig){sigset_t s;sigemptyset(&s);sigaddset(&s,sig);uint64_t b;memcpy(&b,&s,8);return b;}
int main(void){
 p.is_user=1;
 for(int sig=1;sig<64;sig++){
   uint64_t in=libc_mask(sig),out=~0ULL; if(!in) continue;
   assert(sys_rt_sigprocmask(2,(uintptr_t)&in,0,8)==0);
   assert(p.signal_mask==((sig==SIGKILL||sig==SIGSTOP)?0:1ULL<<sig));
   assert(sys_rt_sigprocmask(2,0,(uintptr_t)&out,8)==0);
   assert(out==((sig==SIGKILL||sig==SIGSTOP)?0:in));
 }
 uint64_t in=libc_mask(SIGUSR1)|libc_mask(SIGTERM),out=0;
 sys_rt_sigprocmask(2,(uintptr_t)&in,0,8);
 uint64_t one=libc_mask(SIGUSR1);
 sys_rt_sigprocmask(1,(uintptr_t)&one,(uintptr_t)&out,8);
 assert(out==in && p.signal_mask==(1ULL<<SIGTERM));
 k_sigaction_t sa={.sa_handler=caught,.sa_mask=in},old={0};
 assert(sys_rt_sigaction(SIGUSR1,(uintptr_t)&sa,0,8)==0);
 assert(p.sigactions[SIGUSR1].sa_mask==((1ULL<<SIGUSR1)|(1ULL<<SIGTERM)));
 assert(sys_rt_sigaction(SIGUSR1,0,(uintptr_t)&old,8)==0 && old.sa_mask==in);
 p.signal_mask=1ULL<<SIGUSR1;p.pending_signals=0;uint64_t empty=0;
 assert((int64_t)sys_rt_sigsuspend((uintptr_t)&empty,8)==-EINTR);
 assert(blocks==3 && p.signal_mask==0 && p.suspend_restore);
 assert(signal_next_delivery(&p)==SIGUSR1); /* skip lower priority ignored */
 uint64_t saved=signal_frame_mask(&p);
 assert(saved==libc_mask(SIGUSR1) && !p.suspend_restore);
 assert(signal_mask_from_user(saved)==(1ULL<<SIGUSR1));
 p.signal_mask=0;p.pending_signals=(1ULL<<SIGHUP)|(1ULL<<SIGUSR1);
 p.sigactions[SIGHUP].sa_handler=SIG_IGN;
 assert(signal_next_delivery(&p)==SIGUSR1 && !(p.pending_signals&(1ULL<<SIGHUP)));
 /* Stop/continue must not consume the suspend restoration obligation. */
 p.pending_signals=1ULL<<SIGSTOP;p.suspend_restore=1;blocks=0;
 assert(signal_next_delivery(&p)==SIGUSR1 && stops==1 && blocks==3 && p.suspend_restore);
 p.suspend_saved_mask=1ULL<<SIGTERM;
 assert(signal_frame_mask(&p)==libc_mask(SIGTERM));
 /* A second nested frame saves its current mask, not the old suspension. */
 p.signal_mask=1ULL<<SIGUSR1;
 assert(signal_frame_mask(&p)==libc_mask(SIGUSR1));
 puts("signal mask ABI and suspend regressions: PASS");
}
'''
# Check the real architecture delivery paths all save converted/deferred masks,
# and both sigreturn paths convert back; these assertions supplement host stubs.
signal=(ROOT/'kernel/signal/signal.c').read_text()
sys=(ROOT/'kernel/syscall/sys_signal.c').read_text()
assert signal.count('sf.uc_sigmask = signal_frame_mask(proc);')==4
assert sys.count('proc->signal_mask = signal_mask_from_user(sf.uc_sigmask);')==2
with tempfile.TemporaryDirectory(prefix='aegis-signals-') as d:
    source=Path(d)/'test.c';exe=Path(d)/'test'
    source.write_text(header+'\n'.join(extract(*x) for x in parts)+main)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
