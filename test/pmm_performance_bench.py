#!/usr/bin/env python3
"""Synthetic host PMM work benchmark. NOT target-kernel interrupt latency."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
s=(ROOT/'kernel/mm/pmm.c').read_text()
a=s.index('static uint64_t pmm_alloc_scan');b=s.index('\nuint64_t pmm_alloc_page(void)',a)
scan=s[a:b].replace('uint64_t rb = h + k;', 'scans++; uint64_t rb = h + k;')
query=s[s.index('uint64_t\npmm_free_pages(void)'):]
c=r'''
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define PAGE_SIZE 4096
static uint8_t *s_bitmap;
static int s_pmm_acct; static uint64_t s_acct_allocs,scans,s_free_pages;
typedef unsigned irqflags_t;static unsigned pmm_lock;
static irqflags_t spin_lock_irqsave(unsigned *l){(void)l;__asm__ volatile("":::"memory");return 0;}
static void spin_unlock_irqrestore(unsigned *l,irqflags_t f){(void)l;(void)f;__asm__ volatile("":::"memory");}
'''+scan+query+r'''
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
int main(void){
 s_bitmap=malloc(131072);if(!s_bitmap)abort();
 for(int mode=0;mode<2;mode++){
  memset(s_bitmap,0,131072);memset(s_bitmap,255,32768);s_free_pages=1048576-262144;
  uint64_t hint=0;scans=0;
  for(int i=0;i<8192;i++)if(!pmm_alloc_scan(0,1048576,mode?&hint:NULL))abort();
  printf("32 MiB low allocation / occupied 1 GiB prefix / %s: %lu bitmap probes\n",mode?"hint":"no hint",scans);
 }
 free(s_bitmap);
 int sizes[]={1,16,96,256};
 for(int i=0;i<4;i++){
  uint64_t pages=(uint64_t)sizes[i]*1024*1024*1024/4096;
  size_t bytes=(pages+7)/8;s_bitmap=malloc(bytes);if(!s_bitmap)abort();memset(s_bitmap,0x55,bytes);s_free_pages=pages/2;
  double t=now();volatile uint64_t sink=0;
  for(int j=0;j<30;j++){uint64_t n=0;for(size_t k=0;k<bytes;k++){uint8_t inv=(uint8_t)~s_bitmap[k];while(inv){n++;inv&=inv-1;}}sink=n;}
  double oldms=(now()-t)*1000/30;t=now();
  for(int j=0;j<1000000;j++)sink=pmm_free_pages();
  double newns=(now()-t)*1e9/1000000;
  printf("%d GiB model: old bitmap scan %.3f ms/query, counter %.1f ns/query, count=%lu\n",sizes[i],oldms,newns,(uint64_t)sink);
  free(s_bitmap);
 }
}
'''
with tempfile.TemporaryDirectory(prefix='aegis-pmm-bench-') as d:
 p=Path(d)/'bench.c';exe=Path(d)/'bench';p.write_text(c)
 subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
