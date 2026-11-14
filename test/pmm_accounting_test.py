#!/usr/bin/env python3
"""Run real PMM code with host architecture/locking/KVA stubs; no VM claim."""
from pathlib import Path
import re,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
src=(ROOT/'kernel/mm/pmm.c').read_text()
src=re.sub(r'^#include.*$', '',src,flags=re.M)
header=r'''
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#define PAGE_SIZE 4096ULL
#define CONFIG_PMM_BOOT_GB 1
#define ARCH_KERNEL_PHYS_BASE 0ULL
#define ARCH_KERNEL_VIRT_BASE ((uint64_t)(uintptr_t)_kernel_end)
#define SPINLOCK_INIT 0
#define LOCK_RANK_PMM 1
typedef int spinlock_t;
typedef int irqflags_t;
typedef struct {uint64_t base,len;} aegis_mem_region_t;
static aegis_mem_region_t regions[3],reserved[1];
static uint32_t nregions;
static int held;
char _kernel_end[1];
static irqflags_t spin_lock_irqsave(spinlock_t *l){(void)l;assert(!held);held=1;return 0;}
static void spin_unlock_irqrestore(spinlock_t *l,irqflags_t f){(void)l;(void)f;assert(held);held=0;}
static void lockrank_register(spinlock_t *l,int rank){(void)l;(void)rank;}
static uint32_t arch_mm_region_count(void){return nregions;}
static const aegis_mem_region_t *arch_mm_get_regions(void){return regions;}
static uint32_t arch_mm_reserved_region_count(void){return 1;}
static const aegis_mem_region_t *arch_mm_get_reserved_regions(void){return reserved;}
static uint64_t arch_kern_phys_slide(void){return 0;}
static void printk(const char *fmt,...){(void)fmt;}
static void panic_halt(const char *m){fprintf(stderr,"panic: %s\n",m);abort();}
static void print_backtrace_from(uint64_t a,int n){(void)a;(void)n;}
uint64_t pmm_alloc_page(void);
static void *allocations[8];static int nalloc;
static void *kva_alloc_pages(uint64_t n){
 for(uint64_t i=0;i<n;i++) assert(pmm_alloc_page()!=0);
 void *p=calloc(n,PAGE_SIZE);assert(p);allocations[nalloc++]=p;return p;
}
'''
main=r'''
static void check(void){uint64_t count=0;for(uint64_t i=0;i<s_scan_max_pages;i++)count+=!(s_bitmap[i/8]&(1U<<(i%8)));assert(pmm_free_pages()==count);}
int main(void){
 regions[0]=(aegis_mem_region_t){0,(1ULL<<30)+37*PAGE_SIZE};
 regions[1]=(aegis_mem_region_t){1ULL<<30,37*PAGE_SIZE}; /* duplicate region */
 nregions=2;reserved[0]=(aegis_mem_region_t){0,PAGE_SIZE};
 pmm_init();check();uint64_t initial=pmm_free_pages();
 pmm_reserve_region(PAGE_SIZE,10*PAGE_SIZE);check();assert(pmm_free_pages()==initial-10);
 pmm_reserve_region(PAGE_SIZE,10*PAGE_SIZE);check();assert(pmm_free_pages()==initial-10);
 assert(pmm_unreserve_region(PAGE_SIZE,10*PAGE_SIZE)==10);check();
 assert(pmm_unreserve_region(PAGE_SIZE,10*PAGE_SIZE)==0);check();
 uint64_t a=pmm_alloc_page_low();assert(a && a<4ULL*1024*1024*1024);check();
 pmm_init_late();check(); /* preserves low allocations, deduplicates high RAM */
 assert(s_bitmap_pages==(1ULL<<30)/PAGE_SIZE+37);
 assert(pmm_ref_page(a)==0);uint64_t before=pmm_free_pages();
 pmm_free_page(a);check();assert(pmm_free_pages()==before);
 pmm_free_page(a);check();assert(pmm_free_pages()==before+1);
 pmm_free_page(a);check();assert(pmm_free_pages()==before+1);
 uint64_t b=pmm_alloc_contig_low(9);assert(b);check();
 for(int i=0;i<9;i++){pmm_free_page(b+i*PAGE_SIZE);}check();
 /* Exercise hint wrap, exhaustion, holes and a partial final bitmap byte. */
 uint8_t *old=s_bitmap;uint64_t oldpages=s_bitmap_pages;
 uint8_t small[3]={0xff,0xff,0xff};s_bitmap=small;s_bitmap_pages=s_scan_max_pages=19;s_free_pages=0;s_low_hint_byte=900;
 pmm_free_region(3*PAGE_SIZE,PAGE_SIZE);pmm_free_region(18*PAGE_SIZE,PAGE_SIZE);check();
 assert(pmm_alloc_page_low()==3*PAGE_SIZE);assert(pmm_alloc_page_low()==18*PAGE_SIZE);assert(!pmm_alloc_page_low());check();
 pmm_free_page(3*PAGE_SIZE);assert(pmm_alloc_page_low()==3*PAGE_SIZE);check();
 pmm_free_page(17*PAGE_SIZE);pmm_free_page(18*PAGE_SIZE);check();
 assert(pmm_alloc_contig_low(2)==17*PAGE_SIZE);check();
 /* Validate random mixed operations against a slow bitmap oracle. */
 for(unsigned i=0;i<3000;i++){
  uint64_t pg=1+(i*17U%18U);
  switch(i%4){case 0:pmm_free_page(pg*PAGE_SIZE);break;case 1:(void)pmm_alloc_page_low();break;case 2:pmm_reserve_region(pg*PAGE_SIZE,PAGE_SIZE);break;case 3:(void)pmm_unreserve_region(pg*PAGE_SIZE,PAGE_SIZE);break;}
  check();
 }
 /* High preference must fall back through the independent low cursor. */
 uint8_t *zones=malloc((PMM_LOW_PAGES+17+7)/8);assert(zones);
 memset(zones,255,(PMM_LOW_PAGES+17+7)/8);
 s_bitmap=zones;s_bitmap_pages=s_scan_max_pages=PMM_LOW_PAGES+17;s_free_pages=0;
 pmm_free_region(5*PAGE_SIZE,PAGE_SIZE);
 pmm_free_region((PMM_LOW_PAGES+16)*PAGE_SIZE,PAGE_SIZE);
 pmm_set_alloc_high_pref(1);check();
 assert(pmm_alloc_page()==(PMM_LOW_PAGES+16)*PAGE_SIZE);check();
 assert(pmm_alloc_page()==5*PAGE_SIZE);check();
 assert(!pmm_alloc_page_low());check();free(zones);
 s_bitmap=old;s_bitmap_pages=oldpages;
 for(int i=0;i<nalloc;i++)free(allocations[i]);
 puts("PMM counter, bootstrap/late migration, refcounts and low hint: PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='aegis-pmm-') as d:
 p=Path(d)/'pmm.c';exe=Path(d)/'pmm';p.write_text(header+src+main)
 subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
