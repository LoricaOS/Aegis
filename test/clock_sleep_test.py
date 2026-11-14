#!/usr/bin/env python3
"""Exercise production clock_nanosleep with a deterministic host clock/scheduler."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'kernel/syscall/sys_time.c').read_text()
start = source.index('uint64_t\nsys_clock_nanosleep(')
body = source[start:source.index('\n}', start) + 2]
stubs = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#define SYS_ERR(x) ((uint64_t)-(x))
#define COPY_FROM_USER(dst,src) do { if (!(src)) return SYS_ERR(EFAULT); memcpy(dst,(void*)(uintptr_t)(src),sizeof(*(dst))); } while(0)
#define TIMER_ABSTIME 1
typedef struct {uint64_t sleep_deadline;} aegis_task_t;
static aegis_task_t task;
static uint64_t now;
static int pending, interrupt_on_block, blocks, copy_fault;
aegis_task_t *sched_current(void){return &task;}
uint64_t arch_clock_mono_ns(void){return now;}
void arch_clock_gettime(uint64_t *s,uint64_t *n){*s=10+now/1000000000;*n=now%1000000000;}
uint64_t arch_get_ticks(void){return now/10000000;}
int signal_check_pending(void){return pending;}
void sched_block(void){assert(++blocks<10);now+=250000000;if(interrupt_on_block)pending=1;}
int user_ptr_valid(uint64_t p,uint64_t n){(void)n;return p!=1;}
int copy_to_user(void*d,const void*s,uint64_t n){if(copy_fault)return 1;memcpy(d,s,n);return 0;}
static void reset(void){now=0;pending=interrupt_on_block=blocks=copy_fault=0;task.sleep_deadline=77;}
'''
tests = r'''
int main(void) {
 struct {int64_t tv_sec,tv_nsec;} req={1,0},rem;
 reset();rem.tv_sec=rem.tv_nsec=-1;
 assert(!sys_clock_nanosleep(1,0,(uintptr_t)&req,(uintptr_t)&rem));
 assert(now==1000000000 && blocks==4 && !task.sleep_deadline);
 assert(rem.tv_sec==-1 && rem.tv_nsec==-1);
 reset();pending=1;
 assert(sys_clock_nanosleep(1,0,(uintptr_t)&req,(uintptr_t)&rem)==SYS_ERR(EINTR));
 assert(!blocks && !task.sleep_deadline && rem.tv_sec==1 && !rem.tv_nsec);
 reset();interrupt_on_block=1;
 assert(sys_clock_nanosleep(1,0,(uintptr_t)&req,(uintptr_t)&rem)==SYS_ERR(EINTR));
 assert(blocks==1 && rem.tv_sec==0 && rem.tv_nsec==750000000 && !task.sleep_deadline);
 reset();pending=1;
 assert(sys_clock_nanosleep(1,0,(uintptr_t)&req,0)==SYS_ERR(EINTR));
 reset();pending=1;rem.tv_sec=rem.tv_nsec=-1;
 assert(sys_clock_nanosleep(1,TIMER_ABSTIME,(uintptr_t)&req,(uintptr_t)&rem)==SYS_ERR(EINTR));
 assert(rem.tv_sec==-1 && rem.tv_nsec==-1 && !task.sleep_deadline);
 /* Absolute sleeps ignore even an invalid remainder pointer. */
 assert(sys_clock_nanosleep(1,TIMER_ABSTIME,(uintptr_t)&req,1)==SYS_ERR(EINTR));
 reset();pending=1;
 assert(sys_clock_nanosleep(1,0,(uintptr_t)&req,1)==SYS_ERR(EFAULT));assert(!task.sleep_deadline);
 reset();pending=1;copy_fault=1;
 assert(sys_clock_nanosleep(1,0,(uintptr_t)&req,(uintptr_t)&rem)==SYS_ERR(EFAULT));assert(!task.sleep_deadline);
 reset();now=2000000000;
 assert(!sys_clock_nanosleep(1,TIMER_ABSTIME,(uintptr_t)&req,1));assert(!blocks);
 reset();pending=1;req.tv_sec=11;
 assert(sys_clock_nanosleep(0,TIMER_ABSTIME,(uintptr_t)&req,0)==SYS_ERR(EINTR));
 puts("clock_nanosleep: completion, interruptions, remainder, absolute mode and user-copy faults PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='aegis-clock-sleep-') as tmp:
    c=Path(tmp)/'test.c';exe=Path(tmp)/'test'
    c.write_text(stubs+body+tests)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=30)
