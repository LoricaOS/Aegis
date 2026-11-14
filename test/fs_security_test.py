#!/usr/bin/env python3
"""Run real filesystem C against bounded in-memory devices and host threads.

Hardware, allocation and process identity are stubbed; filesystem algorithms,
VFS open authorization and descriptor write gates come from the current tree.
Run: python3 test/fs_security_test.py
"""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def function(path, name):
    text = (ROOT / path).read_text()
    match = re.search(r"(?:static )?(?:int|uint64_t|uint32_t|void)\s+" + name + r"\([^;]*?\)\s*\{", text)
    assert match, name
    start = match.start()
    clean = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: ' ' * len(m[0]), text, flags=re.S)
    depth, end = 1, match.end()
    while depth:
        depth += (clean[end] == '{') - (clean[end] == '}')
        end += 1
    return text[start:end]

STUBS = {
'spinlock.h': r'''#pragma once
#include <stdint.h>
typedef unsigned long irqflags_t;
typedef struct { unsigned value; } spinlock_t;
#define SPINLOCK_INIT {0}
extern _Thread_local unsigned host_locks;
static inline void spin_lock(spinlock_t *s) { while (__atomic_exchange_n(&s->value,1,__ATOMIC_ACQUIRE)) {} host_locks++; }
static inline int spin_trylock(spinlock_t *s) { if (__atomic_exchange_n(&s->value,1,__ATOMIC_ACQUIRE)) return 0; host_locks++; return 1; }
static inline void spin_unlock(spinlock_t *s) { host_locks--; __atomic_store_n(&s->value,0,__ATOMIC_RELEASE); }
static inline irqflags_t arch_irq_save(void) { return 0; }
static inline void arch_irq_restore(irqflags_t f) { (void)f; }
static inline irqflags_t spin_lock_irqsave(spinlock_t *s) { spin_lock(s); return 0; }
static inline void spin_unlock_irqrestore(spinlock_t *s,irqflags_t f) { (void)f; spin_unlock(s); }
static inline void arch_pause(void) {}
''',
'sched.h': r'''#pragma once
typedef struct { int is_user; int read_nonblock,write_nonblock; } aegis_task_t;
extern _Thread_local aegis_task_t host_task;
static inline aegis_task_t *sched_current(void) { return &host_task; }
''',
'proc.h': r'''#pragma once
#include "cap.h"
#include "fd_table.h"
typedef struct { unsigned uid,gid,admin_session; cap_slot_t caps[64]; fd_table_t *fd_table; } aegis_process_t;
extern _Thread_local aegis_process_t host_proc;
static inline aegis_process_t *current_proc(void) { return &host_proc; }
''',
'kva.h': '#pragma once\n#include <stdint.h>\nvoid *kva_alloc_pages(uint64_t);\nvoid kva_free_pages(void *,uint64_t);\n',
'uaccess.h': r'''#pragma once
#include <stdint.h>
#include <string.h>
extern _Thread_local int host_fault;
static inline uint64_t copy_from_user(void *d,const void *s,uint64_t n) { if(host_fault) return n; memcpy(d,s,n); return 0; }
''',
'syscall_util.h': '#pragma once\n',
'smp.h': r'''#pragma once
#include "spinlock.h"
typedef struct { unsigned cpu_id; } host_cpu_t;
extern _Thread_local host_cpu_t host_cpu;
static inline host_cpu_t *percpu_self(void) { return &host_cpu; }
''',
'printk.h': '#pragma once\n#define printk(...) ((void)0)\n',
'arch.h': r'''#pragma once
#include "spinlock.h"
extern uint64_t host_ticks;
static inline uint64_t arch_get_ticks(void) { return host_ticks; }
static inline uint64_t arch_get_cycles(void) { return 1000; }
static inline uint64_t arch_tsc_hz(void) { return 1000; }
''',
'pmm.h': '#pragma once\n#include <stdint.h>\nuint64_t pmm_alloc_page(void);\nvoid pmm_free_page(uint64_t);\nint pmm_ref_page(uint64_t);\n',
'vmm.h': '#pragma once\n#include <stdint.h>\nvoid vmm_zero_page(uint64_t);\nvoid vmm_write_phys_bytes(uint64_t,uint32_t,const void *,uint32_t);\nvoid vmm_copy_from_phys(void *,uint64_t,uint32_t,uint32_t);\n',
'tlb.h': '#pragma once\nstatic inline void tlb_poll_incoming(void) {}\n',
}
COMMON = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#undef __unused
#include "proc.h"
#include "sched.h"
#include "smp.h"
#include "arch.h"
_Thread_local unsigned host_locks;
_Thread_local int host_fault;
_Thread_local aegis_task_t host_task = {1};
_Thread_local aegis_process_t host_proc;
_Thread_local host_cpu_t host_cpu;
static int check_alloc_locks;
static unsigned host_pages, host_frames;
void *kva_alloc_pages(uint64_t n) { if(check_alloc_locks) assert(!host_locks); void *p=calloc(n,4096); if(p) __atomic_add_fetch(&host_pages,n,__ATOMIC_SEQ_CST); return p; }
void kva_free_pages(void *p,uint64_t n) { if(check_alloc_locks) assert(!host_locks); free(p); __atomic_sub_fetch(&host_pages,n,__ATOMIC_SEQ_CST); }
void *kmemcpy(void *d,const void *s,size_t n) { return memcpy(d,s,n); }
void *kmemset(void *d,int c,size_t n) { return memset(d,c,n); }
int kmemcmp(const void *a,const void *b,size_t n) { return memcmp(a,b,n); }
uint64_t host_ticks=1000;
void arch_clock_gettime(uint64_t *s,uint64_t *n) { *s=1;*n=0; }
''' + function('kernel/cap/cap.c', 'cap_check') + '\n' + function('kernel/cap/cap.c', 'cap_grant')
OPEN_GATE = ('#define ADMIN_CRED_MIN_TICKS 200u\nstatic volatile uint64_t s_admin_cred_last_read;\n'
             + function('kernel/fs/vfs.c', 'vfs_open_ext2_inode') + '\n'
             + function('kernel/syscall/sys_io.c', 'fd_content_write_allowed'))
FIRSTBOOT = r'''
#include "kernel/fs/ramfs.h"
#include "kernel/fs/mount.h"
static ramfs_t s_run_ramfs, s_tmp_ramfs;
static unsigned fallback_opens;
int ptmx_open(int f,vfs_file_t*out){(void)f;(void)out;abort();}
int pts_open(uint32_t i,int f,vfs_file_t*out){(void)i;(void)f;(void)out;abort();}
int procfs_open(const char*p,int f,vfs_file_t*out){(void)p;(void)f;(void)out;abort();}
int initrd_open(const char*p,vfs_file_t*out){(void)p;(void)out;fallback_opens++;return -ENOENT;}
int ramfs_opendir(ramfs_t*r,vfs_file_t*out){(void)r;(void)out;abort();}
int ramfs_open(ramfs_t*r,const char*p,int f,uint16_t m,vfs_file_t*out){(void)r;(void)p;(void)f;(void)m;(void)out;abort();}
int mount_acquire(const char*p,void**ctx,const char**rel){(void)p;(void)ctx;(void)rel;return MOUNT_FS_NONE;}
void mount_release(void*ctx){(void)ctx;abort();}
int g_first_boot;
int cap_policy_lookup(const char*p,cap_policy_entry_t*out){assert(!host_locks);if(strcmp(p,"/bin/configure"))return 0;if(out)*out=(cap_policy_entry_t){.count=1,.caps={{.tier=CAP_TIER_FIRSTBOOT}}};return 1;}
''' + '\n'.join(function('kernel/fs/vfs.c', n) for n in ['vfs_open_ex', 'vfs_open']) + '\n' + '\n'.join(
    function('kernel/cap/cap_policy.c', n) for n in ['cap_policy_detect_first_boot', 'cap_policy_is_firstboot']) + r'''
static void marker_absent(void){
 vfs_file_t f;fallback_opens=0;
 assert(vfs_open("/etc/aegis/configured",0,0,&f)==-ENOENT);assert(fallback_opens==1);
 cap_policy_detect_first_boot();assert(g_first_boot);assert(cap_policy_is_firstboot("/bin/configure"));assert(!cap_policy_is_firstboot("/bin/other"));assert(g_first_boot);
}
static void marker_unavailable(int error){
 vfs_file_t f;fallback_opens=0;
 assert(vfs_open("/etc/aegis/configured",0,0,&f)==error);assert(!fallback_opens);
 cap_policy_detect_first_boot();assert(!g_first_boot);
 g_first_boot=1;assert(!cap_policy_is_firstboot("/bin/configure"));assert(!g_first_boot);
}
static void marker_present(void){
 fallback_opens=0;
 g_first_boot=1;assert(!cap_policy_is_firstboot("/bin/configure"));assert(!g_first_boot);
 cap_policy_detect_first_boot();assert(!g_first_boot);assert(!fallback_opens);
}
'''
RAMFS = r'''
#include "kernel/fs/ramfs.c"
static ramfs_t fs;
static void *writer(void *unused) { (void)unused; vfs_file_t f; assert(!ramfs_open(&fs,"race",VFS_O_RDWR,0600,&f)); for(int i=0;i<2000;i++) { char data[200];memset(data,0x55,sizeof data); assert(f.ops->write(f.priv,data,sizeof data)>0); } f.ops->close(f.priv);return 0; }
static void *truncater(void *unused) { (void)unused; for(int i=0;i<2000;i++){vfs_file_t f; assert(!ramfs_open(&fs,"race",VFS_O_RDWR|VFS_O_TRUNC,0600,&f));f.ops->close(f.priv);}return 0; }
int main(void) {
 check_alloc_locks=1; ramfs_init(&fs); vfs_file_t f,g; char buf[8];
 host_proc.uid=10;host_proc.gid=20;
 assert(!ramfs_open(&fs,"secret",VFS_O_CREAT|VFS_O_RDWR,0600,&f));
 assert(f.ops->write(f.priv,"secret",6)==6); k_stat_t st;assert(!ramfs_stat(&fs,"secret",&st));assert(st.st_mode==(S_IFREG|0600));assert(st.st_gid==20);
 host_proc.uid=11;host_proc.gid=21;
 assert(ramfs_open(&fs,"secret",VFS_O_RDONLY,0,&g)==-EACCES);
 assert(ramfs_open(&fs,"secret",VFS_O_RDWR,0,&g)==-EACCES);
 assert(!ramfs_mkdir(&fs,"private",0700));
 host_proc.uid=10;
 assert(ramfs_open(&fs,"private/x",VFS_O_CREAT|VFS_O_RDWR,0600,&g)==-EACCES);
 assert(ramfs_rmdir(&fs,"private")==-EACCES);
 assert(ramfs_open(&fs,"secret",VFS_O_TRUNC,0,&g)==-EINVAL);
 assert(!ramfs_unlink(&fs,"secret"));assert(f.ops->read(f.priv,buf,0,6)==6);assert(!memcmp(buf,"secret",6));f.ops->close(f.priv);
 host_proc.uid=11;assert(!ramfs_open(&fs,"private/x",VFS_O_CREAT|VFS_O_RDWR,0600,&f));f.ops->close(f.priv);
 assert(!ramfs_rename(&fs,"private","moved"));assert(!ramfs_open(&fs,"moved/x",VFS_O_RDONLY,0,&f));f.ops->close(f.priv);
 assert(ramfs_open(&fs,"private/x",VFS_O_RDONLY,0,&g)==-ENOENT);assert(!ramfs_unlink(&fs,"moved/x"));assert(!ramfs_rmdir(&fs,"moved"));
 host_proc.uid=0;host_proc.gid=0;
 assert(!ramfs_open(&fs,"race",VFS_O_CREAT|VFS_O_RDWR,0600,&f));
 pthread_t a,b;assert(!pthread_create(&a,0,writer,0));assert(!pthread_create(&b,0,truncater,0));pthread_join(a,0);pthread_join(b,0);
 assert(!ramfs_unlink(&fs,"race"));f.ops->close(f.priv);assert(host_pages==0);
 /* Directory descriptors follow inode identity across rename/removal. */
 assert(!ramfs_mkdir(&fs,"tree",0700));assert(!ramfs_mkdir(&fs,"tree/sub",0700));
 assert(!ramfs_open(&fs,"tree/item",VFS_O_CREAT|VFS_O_RDWR,0600,&f));f.ops->close(f.priv);
 assert(!ramfs_open(&fs,"tree/sub/deep",VFS_O_CREAT|VFS_O_RDWR,0600,&f));f.ops->close(f.priv);
 assert(!ramfs_open(&fs,"tree",VFS_O_RDONLY,0,&f));assert(f.ops->readdir);
 assert(!f.ops->stat(f.priv,&st)&&(st.st_mode&S_IFMT)==S_IFDIR);
 char name[128];uint8_t type;
 assert(!f.ops->readdir(f.priv,0,name,&type)&&!strcmp(name,"sub")&&type==4);
 assert(!f.ops->readdir(f.priv,1,name,&type)&&!strcmp(name,"item")&&type==8);
 assert(f.ops->readdir(f.priv,2,name,&type)<0);
 assert(!ramfs_rename(&fs,"tree","movedtree"));
 assert(!f.ops->readdir(f.priv,1,name,&type)&&!strcmp(name,"item"));
 assert(!ramfs_opendir(&fs,&g));unsigned trees=0;
 for(uint64_t i=0;!g.ops->readdir(g.priv,i,name,&type);i++){assert(!strchr(name,'/'));if(!strcmp(name,"movedtree"))trees++;}assert(trees==1);g.ops->close(g.priv);
 assert(!ramfs_unlink(&fs,"movedtree/sub/deep"));assert(!ramfs_rmdir(&fs,"movedtree/sub"));
 assert(!ramfs_unlink(&fs,"movedtree/item"));assert(!ramfs_rmdir(&fs,"movedtree"));
 assert(!ramfs_mkdir(&fs,"movedtree",0700));
 assert(!ramfs_open(&fs,"movedtree/new",VFS_O_CREAT|VFS_O_RDWR,0600,&g));g.ops->close(g.priv);
 assert(f.ops->readdir(f.priv,0,name,&type)<0); /* not the replacement directory */
 f.ops->dup(f.priv);vfs_file_t alias=f;f.ops->close(f.priv);assert(ramfs_busy(&fs));alias.ops->close(alias.priv);
 assert(!ramfs_unlink(&fs,"movedtree/new"));assert(!ramfs_rmdir(&fs,"movedtree"));
 assert(!ramfs_busy(&fs));assert(host_pages==0);
 assert(!ramfs_opendir(&fs,&g));g.ops->dup(g.priv);vfs_file_t root_alias=g;
 g.ops->close(g.priv);assert(ramfs_busy(&fs));root_alias.ops->close(root_alias.priv);
 assert(!ramfs_busy(&fs));assert(host_pages==0);
 puts("ramfs: nested directory enumeration and retained inode lifetime PASS");
 puts("ramfs: private modes, namespace DAC, open-unlinked, concurrent truncate/write PASS");
}
'''
RAMFS_POSITION = r'''
#include "kernel/fs/ramfs.c"
int vfs_read_nonblock;
typedef struct { uint64_t iov_base, iov_len; } aegis_iovec_t;
static int user_ptr_valid(uint64_t p,uint64_t n){return !n||p!=0;}
static uint64_t copy_to_user(void*d,const void*s,uint64_t n){if(host_fault)return n;memcpy(d,s,n);return 0;}
static void fd_table_assert_live(fd_table_t*t,const char*w){(void)w;assert(t->magic==FD_TABLE_MAGIC);}
''' + '\n'.join(function('kernel/fs/fd_table.c', n) for n in ['fd_table_pin','fd_table_unpin','fd_table_advance_offset','fd_table_set_offset']) + '\n' + function('kernel/syscall/sys_io.c','fd_content_write_allowed') + '\n' + '\n'.join(function('kernel/syscall/sys_io.c', n) for n in ['sys_read','sys_write','sys_writev','sys_readv','sys_pread64','sys_pwrite64']) + '\n' + '\n'.join(function('kernel/syscall/sys_file.c', n) for n in ['fd_dup_lowest','sys_dup','sys_lseek']) + r'''
static ramfs_t fs;
static fd_table_t table;
static char data[8192] __attribute__((aligned(4096)));
static unsigned legacy_calls;
static int legacy_partial(void*p,const void*b,uint64_t n){(void)p;(void)b;(void)n;return legacy_calls++ ? -ENOSPC : 3;}
static const vfs_ops_t legacy_ops={.write=legacy_partial};
static uint64_t addr(void*p){return (uint64_t)(uintptr_t)p;}
static void *position_writer(void *arg){
 unsigned fd=(unsigned)(uintptr_t)arg;host_proc.fd_table=&table;
 assert(cap_grant(host_proc.caps,64,CAP_KIND_VFS_WRITE,CAP_RIGHTS_WRITE)>=0);
 char ch=fd?'B':'A';
 for(unsigned i=0;i<100;i++)assert(sys_write(fd,addr(&ch),1)==1);
 return 0;
}
int main(void){
 ramfs_init(&fs);host_proc.fd_table=&table;table.magic=FD_TABLE_MAGIC;
 assert(cap_grant(host_proc.caps,64,CAP_KIND_VFS_READ,CAP_RIGHTS_READ)>=0);
 assert(cap_grant(host_proc.caps,64,CAP_KIND_VFS_WRITE,CAP_RIGHTS_WRITE)>=0);
 assert(!ramfs_open(&fs,"pos",VFS_O_CREAT|VFS_O_RDWR,0600,&table.fds[0]));
 memcpy(data,"abcdef",6);assert(sys_write(0,addr(data),6)==6);
 assert(sys_lseek(0,0,2)==6); /* live size, not open-time zero */
 assert(sys_lseek(0,0,0)==0);assert(sys_read(0,addr(data),1)==1&&data[0]=='a');
 data[0]='X';assert(sys_write(0,addr(data),1)==1);assert(sys_lseek(0,0,1)==2);
 assert(sys_pread64(0,addr(data),6,0)==6&&!memcmp(data,"aXcdef",6));
 assert(sys_lseek(0,0,1)==2); /* pread leaves shared offset */
 data[0]='Y';assert(sys_pwrite64(0,addr(data),1,4)==1);assert(sys_lseek(0,0,1)==2);
 assert(sys_pread64(0,addr(data),6,0)==6&&!memcmp(data,"aXcdYf",6));
 uint64_t alias=sys_dup(0);assert(alias==1);
 assert(sys_read(alias,addr(data),1)==1&&data[0]=='c');assert(sys_lseek(0,0,1)==3);
 data[0]='Z';assert(sys_write(0,addr(data),1)==1);assert(sys_lseek(alias,0,1)==4);
 assert(sys_lseek(alias,1,0)==1);assert(sys_read(0,addr(data),1)==1&&data[0]=='X');
 assert(!ramfs_open(&fs,"pos",VFS_O_RDWR,0,&table.fds[2]));
 assert(sys_read(2,addr(data),1)==1&&data[0]=='a');assert(sys_lseek(0,0,1)==2);
 assert(sys_lseek(0,2,2)==8);data[0]='Q';assert(sys_write(0,addr(data),1)==1);
 assert(sys_pread64(0,addr(data),9,0)==9&&!memcmp(data,"aXcZYf\0\0Q",9));
 assert(sys_lseek(alias,0,2)==9);
 assert(!ramfs_open(&fs,"pos",VFS_O_WRONLY|VFS_O_APPEND,0,&table.fds[3]));
 assert(sys_lseek(3,0,0)==0);data[0]='!';assert(sys_write(3,addr(data),1)==1);assert(sys_lseek(3,0,1)==10);
 assert(sys_pwrite64(3,addr(data),1,0)==1);assert(sys_lseek(3,0,1)==10); /* POSIX positional write ignores append */
 assert((int64_t)sys_lseek(0,(uint64_t)-11,2)==-EINVAL);
 assert((int64_t)sys_lseek(0,0,7)==-EINVAL);
 assert(sys_lseek(0,0,1)==9);
 assert((int64_t)sys_lseek(0,0,UINT64_C(0x100000000))==-EINVAL);
 assert(sys_lseek(0,0,0)==0);
 data[0]='M';data[1]='N';aegis_iovec_t vectors[2]={{addr(data),1},{addr(data+1),1}};
 assert(sys_writev(alias,addr(vectors),2)==1);assert(sys_writev(alias,addr(vectors+1),1)==1);assert(sys_lseek(0,0,1)==2);
 assert(sys_lseek(alias,0,0)==0);data[0]=data[1]=0;
 assert(sys_readv(0,addr(vectors),2)==1);assert(sys_readv(0,addr(vectors+1),1)==1&&!memcmp(data,"MN",2));assert(sys_lseek(alias,0,1)==2);
 assert((int64_t)sys_pwrite64(0,addr(data),1,UINT64_MAX)==-EINVAL);assert(sys_lseek(0,0,1)==2);
 /* A short final-page transfer followed by ENOSPC must report the bytes
  * already committed inside the current iovec, not the later error. */
 assert(sys_lseek(0,RAMFS_MAX_SIZE-3,0)==RAMFS_MAX_SIZE-3);
 memset(data,'R',8);vectors[0]=(aegis_iovec_t){addr(data),8};
 assert(sys_writev(0,addr(vectors),1)==3);assert(sys_lseek(alias,0,1)==RAMFS_MAX_SIZE);
 assert(sys_lseek(2,0,0)==0);memset(data,'B',sizeof(data));
 assert(sys_write(2,addr(data),sizeof(data))==4096); /* single atomic transfer */
 assert(sys_lseek(2,0,1)==4096);
 table.fds[4]=(vfs_file_t){.ops=&legacy_ops,.flags=VFS_O_WRONLY};
 vectors[0]=(aegis_iovec_t){addr(data),8};
 assert(sys_writev(4,addr(vectors),1)==3);assert(table.fds[4].offset==3);
 assert(!ramfs_unlink(&fs,"pos"));
 for(unsigned i=0;i<4;i++)table.fds[i].ops->close(table.fds[i].priv);
 assert(!ramfs_busy(&fs)&&host_pages==0);
 memset(&table.fds,0,sizeof(table.fds));
 assert(!ramfs_open(&fs,"concurrent",VFS_O_CREAT|VFS_O_RDWR,0600,&table.fds[0]));
 assert(sys_dup(0)==1);pthread_t pa,pb;
 assert(!pthread_create(&pa,0,position_writer,(void*)0));
 assert(!pthread_create(&pb,0,position_writer,(void*)1));pthread_join(pa,0);pthread_join(pb,0);
 assert(sys_lseek(0,0,1)==200);assert(sys_pread64(0,addr(data),200,0)==200);
 unsigned ac=0,bc=0;for(unsigned i=0;i<200;i++){ac+=data[i]=='A';bc+=data[i]=='B';}assert(ac==100&&bc==100);
 assert(!ramfs_unlink(&fs,"concurrent"));table.fds[0].ops->close(table.fds[0].priv);table.fds[1].ops->close(table.fds[1].priv);
 assert(!ramfs_busy(&fs)&&host_pages==0);
 puts("ramfs syscall positions: read/write, pread/pwrite, dup, independent opens, seek-end, append PASS");
}
'''
FAT = r'''
@CANON@
#include "kernel/fs/fat.c"
static uint8_t disk[128][512];
static int fail_write, fail_read_lba=-1;
static int disk_read(blkdev_t*d,uint64_t l,uint32_t n,void*b){(void)d;if(l+n>128||(fail_read_lba>=0&&l<=(uint64_t)fail_read_lba&&l+n>(uint64_t)fail_read_lba))return -1;memcpy(b,disk[l],n*512);return 0;}
static int disk_write(blkdev_t*d,uint64_t l,uint32_t n,const void*b){(void)d;if(fail_write||l+n>128)return -1;memcpy(disk[l],b,n*512);return 0;}
blkdev_t *blkdev_get(const char *s){(void)s;return 0;}
@OPEN@
@FIRSTBOOT@
int main(void) {
 blkdev_t dev={.block_count=128,.block_size=512,.read=disk_read,.write=disk_write};
 s_dev=&dev;s_bps=512;s_spc=1;s_fat_lba=1;s_data_lba=3;s_root_cluster=2;s_total_clusters=96;s_nfats=1;s_fat_size=1;s_next_free=3;
 assert(!fat_set(2,0x0fffffff));
 assert(fat_under_prot("/BiN/login"));assert(fat_under_prot("/LiB/loader"));assert(!fat_under_prot("/binary"));assert(fat_under_prot("/./BiN//login"));assert(fat_under_prot("/BiN/../LiB/loader"));assert(fat_path_guarded("/EtC"));
 assert(fat_ino_of((void*)1,(void*)1)==0);
 host_task.is_user=0;assert(!fat_mkdir("/etc",0755,1));host_task.is_user=1;
 assert(fat_create("/EtC/PASSWD",0600,1)==-EACCES);host_proc.admin_session=1;assert(!fat_create("/EtC/PASSWD",0600,1));
 uint32_t ino;assert(!fat_open("/etc/passwd",&ino));assert(fat_passwd_ino()==ino);
 vfs_file_t f;assert(!vfs_open_ext2_inode(ino,0,VFS_O_RDWR,&f,0,0));assert(f.kflags&VFS_KF_ACCOUNT_DB);host_proc.admin_session=0;assert(!fd_content_write_allowed(&host_proc,&f));f.ops->close(f.priv);
 assert(vfs_open_ext2_inode(ino,0,VFS_O_TRUNC,&f,0,0)==-EINVAL);
 assert(vfs_open_ext2_inode(FAT_ROOT_INO,0,VFS_O_RDWR,&f,1,0)==-EISDIR);
 host_task.is_user=0;assert(!fat_create("/sparse",0600,1));assert(!fat_open("/sparse",&ino));
 for(int i=10;i<128;i++)memset(disk[i],0xA5,512);
 assert(fat_write(ino,"A",0,1)==1);assert(fat_write(ino,"Z",1700,1)==1);
 uint8_t data[1701];assert(fat_read(ino,data,0,sizeof data)==sizeof data);assert(data[0]=='A'&&data[1700]=='Z');for(int i=1;i<1700;i++)assert(!data[i]);
 fail_write=1;assert(fat_write(ino,"x",3000,1)<0);fail_write=0;
 assert(!fat_mkdir("/etc/aegis",0755,1));marker_absent();
 fail_read_lba=cluster_lba(s_root_cluster);marker_unavailable(-EIO);fail_read_lba=-1;marker_absent();
 uint32_t parent;fat_dirent_t pd;assert(!resolve("/etc/aegis",&parent,&pd,0,0));uint32_t plba=cluster_lba(pd.first_cluster);
 fail_read_lba=(int)plba;marker_unavailable(-EIO);fail_read_lba=-1;
 uint8_t saved[512];memcpy(saved,disk[plba],512);for(unsigned i=2;i<16;i++)disk[plba][i*32]=0xE5;
 fail_read_lba=(int)s_fat_lba;marker_unavailable(-EIO);fail_read_lba=-1;marker_absent();
 assert(!fat_set(pd.first_cluster,pd.first_cluster));marker_unavailable(-EIO);assert(!fat_set(pd.first_cluster,0x0fffffff));
 memcpy(disk[plba],saved,512);assert(!fat_create("/etc/aegis/configured",0644,1));marker_present();
 for(unsigned i=0;i<sizeof(s_fds)/sizeof(s_fds[0]);i++)assert(!s_fds[i].in_use);
 fail_read_lba=(int)plba;marker_unavailable(-EIO);fail_read_lba=-1;marker_present();
 s_dev=0;marker_unavailable(-ENODEV);s_dev=&dev;
 puts("fat firstboot: missing marker, directory/FAT read faults, corrupt chain, present marker PASS");
 puts("fat: equivalent-name protection, account authority, foreign descriptors, sparse zeroing PASS");
}
'''
MEMFD = r'''
#include "kernel/fs/memfd.c"
uint64_t pmm_alloc_page(void){void*p=calloc(1,4096);if(p)__atomic_add_fetch(&host_frames,1,__ATOMIC_SEQ_CST);return(uintptr_t)p;}
void pmm_free_page(uint64_t p){free((void*)(uintptr_t)p);__atomic_sub_fetch(&host_frames,1,__ATOMIC_SEQ_CST);}
int pmm_ref_page(uint64_t p){(void)p;return 0;}
void vmm_zero_page(uint64_t p){memset((void*)(uintptr_t)p,0,4096);}
void vmm_write_phys_bytes(uint64_t p,uint32_t o,const void*s,uint32_t n){assert(!memfd_lock.value);memcpy((char*)(uintptr_t)p+o,s,n);}
void vmm_copy_from_phys(void*d,uint64_t p,uint32_t o,uint32_t n){memcpy(d,(char*)(uintptr_t)p+o,n);}
static void *grower(void *id){for(int i=0;i<1000;i++)assert(!memfd_truncate((uintptr_t)id,(i%8+1)*4096));return 0;}
static void partial_tail(void) {
 int id=memfd_alloc("tail");assert(id>=0);
 assert(!memfd_truncate(id,4096));
 unsigned char *p=(void*)(uintptr_t)memfd_get(id)->phys_pages[0];
 memset(p,0xA5,4096);
 assert(!memfd_truncate(id,100));
 for(int i=0;i<100;i++)assert(p[i]==0xA5);
 for(int i=100;i<4096;i++)assert(!p[i]);
 /* A mapping can dirty bytes outside EOF after the shrink. */
 memset(p+100,0xCC,3996);
 assert(!memfd_truncate(id,200));
 for(int i=100;i<200;i++)assert(!p[i]);
 assert(p[200]==0xCC);
 assert(!memfd_truncate(id,8192));
 for(int i=200;i<4096;i++)assert(!p[i]);
 assert(!memfd_truncate(id,4196));
 unsigned char *q=(void*)(uintptr_t)memfd_get(id)->phys_pages[1];
 memset(q,0xDD,100);
 assert(!memfd_truncate(id,8192));
 for(int i=0;i<100;i++)assert(q[i]==0xDD);
 for(int i=100;i<4096;i++)assert(!q[i]);
 memfd_vfs_close((void*)(uintptr_t)id);
 assert(!host_frames && !host_pages);
 puts("memfd: partial-page shrink/regrow, mapped tail writes and prefix preservation PASS");
}
int main(void){partial_tail();int id=memfd_alloc("race");assert(id>=0);pthread_t a,b;assert(!pthread_create(&a,0,grower,(void*)(uintptr_t)id));assert(!pthread_create(&b,0,grower,(void*)(uintptr_t)id));pthread_join(a,0);pthread_join(b,0);memfd_vfs_close((void*)(uintptr_t)id);assert(host_frames==0);assert(host_pages==0);puts("memfd: concurrent resize ownership and final reclamation PASS");}
'''
EXT2 = r'''
#define CONFIG_FS_EXT2 1
#include "kernel/fs/ext2.c"
#include "kernel/fs/ext2_cache.c"
#include "kernel/fs/ext2_dir.c"
#include "kernel/fs/ext2_vfs.c"
#include "kernel/fs/ext2_ops.c"
static uint8_t disk[256][512];
static int fail_read_lba=-1;
static int disk_read(blkdev_t*d,uint64_t l,uint32_t n,void*b){(void)d;if(l+n>256||(fail_read_lba>=0&&l<=(uint64_t)fail_read_lba&&l+n>(uint64_t)fail_read_lba))return -1;memcpy(b,disk[l],n*512);return 0;}
static int disk_write(blkdev_t*d,uint64_t l,uint32_t n,const void*b){(void)d;if(l+n>256)return -1;memcpy(disk[l],b,n*512);return 0;}
blkdev_t *blkdev_get(const char *s){(void)s;return 0;}
@OPEN@
@FIRSTBOOT@
@OPENAT@
/* Real ext2 resolution/DAC, live cap slots and the production VFS open gate.
 * Aliases to credential inodes retain AUTH; similarly named copies do not.
 * AUTH never authorizes directory traversal or any mutating open's DAC. */
static void credential_opens(void){
 host_task.is_user=0;
 assert(!ext2_create("/etc/shadow",0600,1));
 assert(!ext2_create("/etc/aegis/admin",0600,1));
 assert(!ext2_create("/shadow-copy",0600,1));
 assert(!ext2_symlink("/credential-alias","/etc/shadow",1));
 assert(!ext2_symlink("/wrong-alias","/shadow-copy",1));
 assert(!ext2_mkdir("/locked",0700,1));
 assert(!ext2_symlink("/locked/alias","/etc/shadow",1));
 /* Seed the mount-time credential/protected caches for this in-memory fs. */
 assert(!ext2_open("/etc/shadow",&s_shadow_ino));
 assert(!ext2_open("/etc/aegis/admin",&s_admin_ino));
 assert(!ext2_open("/etc/aegis",&s_etc_aegis_ino));
 uint32_t shadow=ext2_get_shadow_ino(),admin=ext2_get_admin_ino(),copy;
 assert(shadow&&admin);assert(!ext2_open("/shadow-copy",&copy));assert(copy!=shadow&&copy!=admin);
 ext2_inode_t inode;assert(!ext2_read_inode(shadow,&inode));assert(!inode.i_uid&&(inode.i_mode&0777)==0600);
 assert(ext2_write(shadow,"secret",0,6)==6);
 host_task.is_user=1;host_proc.uid=1000;host_proc.gid=1000;host_proc.admin_session=0;
 vfs_file_t f;
 assert(vfs_open("/etc/shadow",VFS_O_RDONLY,0,&f)==-EACCES);
 assert(vfs_open("/etc/aegis/admin",VFS_O_RDONLY,0,&f)==-EACCES);
 host_proc.caps[0]=(cap_slot_t){CAP_KIND_AUTH,CAP_RIGHTS_WRITE};
 assert(vfs_open("/etc/shadow",VFS_O_RDONLY,0,&f)==-EACCES);
 host_proc.caps[0].rights=CAP_RIGHTS_READ;
 assert(!vfs_open("/etc/shadow",VFS_O_RDONLY,0,&f));
 assert(f.kflags&VFS_KF_AUTH_GATED);assert(!fd_content_write_allowed(&host_proc,&f));f.ops->close(f.priv);
 assert(!vfs_open("/credential-alias",VFS_O_RDONLY,0,&f));
 assert(f.kflags&VFS_KF_AUTH_GATED);assert(((ext2_fd_priv_t*)f.priv)->ino==shadow);f.ops->close(f.priv);
 assert(!vfs_openat_ext2(2,2,"credential-alias",VFS_O_RDONLY,&f,0,0));
 assert(f.kflags&VFS_KF_AUTH_GATED);f.ops->close(f.priv);
 assert(vfs_open("/shadow-copy",VFS_O_RDONLY,0,&f)==-EACCES);
 assert(vfs_open("/wrong-alias",VFS_O_RDONLY,0,&f)==-EACCES);
 assert(vfs_open("/locked/alias",VFS_O_RDONLY,0,&f)==-EACCES);
 assert(vfs_openat_ext2(2,2,"locked/alias",VFS_O_RDONLY,&f,0,0)==-EACCES);
 /* No cached identity means no exemption, even for the familiar path. */
 uint32_t saved=s_shadow_ino;s_shadow_ino=0;
 assert(vfs_open("/etc/shadow",VFS_O_RDONLY,0,&f)==-EACCES);s_shadow_ino=saved;
 const int mutations[]={VFS_O_WRONLY,VFS_O_RDWR,VFS_O_WRONLY|VFS_O_TRUNC,
                        VFS_O_APPEND,VFS_O_WRONLY|VFS_O_APPEND,VFS_O_CREAT};
 host_proc.caps[1]=(cap_slot_t){CAP_KIND_VFS_WRITE,CAP_RIGHTS_WRITE};
 host_proc.caps[2]=(cap_slot_t){CAP_KIND_INSTALL,CAP_RIGHTS_WRITE};
 host_proc.admin_session=1;
 assert(vfs_open("/shadow-copy",VFS_O_RDONLY,0,&f)==-EACCES);
 for(unsigned i=0;i<sizeof mutations/sizeof mutations[0];i++){
  assert(vfs_open_ex("/etc/shadow",mutations[i],0,&f,1)==-EACCES);
  host_proc.caps[0].rights=CAP_RIGHTS_READ|CAP_RIGHTS_WRITE;
  assert(vfs_open_ex("/etc/shadow",mutations[i],0,&f,1)==-EACCES);
  host_proc.caps[0].rights=CAP_RIGHTS_READ;
 }
 host_proc.admin_session=0;
 assert(vfs_open("/etc/shadow",VFS_O_TRUNC,0,&f)==-EINVAL);
 assert(ext2_file_size(shadow)==6);
 /* Owner DAC still does not replace AUTH or protected-tree INSTALL. */
 host_proc.uid=host_proc.gid=0;host_proc.caps[0]=(cap_slot_t){0};
 assert(vfs_open("/etc/shadow",VFS_O_RDONLY,0,&f)==-EACCES);
 assert(vfs_open("/credential-alias",VFS_O_RDONLY,0,&f)==-EACCES);
 assert(vfs_open("/etc/aegis/admin",VFS_O_RDONLY,0,&f)==-EACCES);
 host_proc.caps[0]=(cap_slot_t){CAP_KIND_AUTH,CAP_RIGHTS_READ};
 assert(vfs_open_ex("/etc/aegis/admin",VFS_O_WRONLY,0,&f,1)==-EACCES);
 host_proc.caps[0].rights=CAP_RIGHTS_WRITE;
 assert(vfs_open_ex("/etc/aegis/admin",VFS_O_WRONLY,0,&f,0)==-EACCES);
 assert(s_admin_cred_last_read==host_ticks);
 assert(vfs_open_ex("/etc/aegis/admin",VFS_O_WRONLY,0,&f,1)==-EAGAIN);
 host_ticks+=ADMIN_CRED_MIN_TICKS;
 assert(!vfs_open_ex("/etc/aegis/admin",VFS_O_WRONLY,0,&f,1));f.ops->close(f.priv);
 /* Throttle is global for non-admin readers, unchanged at the boundary. */
 host_proc.uid=host_proc.gid=1000;host_proc.caps[0].rights=CAP_RIGHTS_READ;
 s_admin_cred_last_read=0;host_ticks=1000;
 assert(!vfs_open("/etc/aegis/admin",VFS_O_RDONLY,0,&f));
 assert((f.kflags&(VFS_KF_AUTH_GATED|VFS_KF_PROTECTED))==(VFS_KF_AUTH_GATED|VFS_KF_PROTECTED));f.ops->close(f.priv);
 host_proc.uid=1001;host_ticks=1199;
 assert(vfs_open("/etc/aegis/admin",VFS_O_RDONLY,0,&f)==-EAGAIN);
 assert(s_admin_cred_last_read==1000);
 host_ticks=1200;assert(!vfs_open("/etc/aegis/admin",VFS_O_RDONLY,0,&f));f.ops->close(f.priv);
 host_proc.admin_session=1;host_ticks=1201;
 assert(!vfs_open("/etc/aegis/admin",VFS_O_RDONLY,0,&f));f.ops->close(f.priv);
 assert(s_admin_cred_last_read==1200);
 host_proc.caps[0]=(cap_slot_t){0};
 assert(vfs_open("/etc/aegis/admin",VFS_O_RDONLY,0,&f)==-EACCES);
 assert(s_admin_cred_last_read==1200);
 memset(host_proc.caps,0,sizeof host_proc.caps);host_proc.admin_session=0;
 host_proc.uid=host_proc.gid=0;
 for(unsigned i=0;i<EXT2_FD_POOL;i++)assert(!s_ext2_pool[i].in_use);
 puts("credential opens: exact inode AUTH READ, aliases, DAC isolation, mutation denial, uid0 denial, throttle PASS");
}
static void drop_cache(void){assert(!ext2_sync());memset(s_cache,0,sizeof s_cache);icache_clear();}
int main(void){
 blkdev_t dev={.block_count=256,.block_size=512,.read=disk_read,.write=disk_write};s_dev=&dev;s_mounted=1;s_block_size=1024;s_num_groups=1;
 s_sb.s_inodes_count=32;s_sb.s_blocks_count=128;s_sb.s_blocks_per_group=128;s_sb.s_inodes_per_group=32;s_sb.s_inode_size=128;s_sb.s_first_data_block=1;
 s_bgd[0].bg_block_bitmap=2;s_bgd[0].bg_inode_bitmap=3;s_bgd[0].bg_inode_table=4;s_bgd[0].bg_free_blocks_count=110;s_bgd[0].bg_free_inodes_count=22;
 memset(disk[4],0xff,2);disk[6][0]=0xff;disk[6][1]=3;
 ext2_inode_t root={.i_mode=EXT2_S_IFDIR|0777,.i_links_count=2};assert(!ext2_write_inode(2,&root));
 assert(!ext2_dir_add_entry(2,2,".",EXT2_FT_DIR));assert(!ext2_dir_add_entry(2,2,"..",EXT2_FT_DIR));
 assert(!ext2_create("/held",0600,1));uint32_t ino;assert(!ext2_open("/held",&ino));assert(ext2_write(ino,"safe",0,4)==4);
 ext2_fd_priv_t *held=ext2_pool_alloc(ino);assert(held);assert(!ext2_unlink("/held",1));char data[8];assert(s_ext2_ops.read(held,data,0,4)==4&&!memcmp(data,"safe",4));
 assert(!ext2_create("/other",0600,1));uint32_t other;assert(!ext2_open("/other",&other)&&other!=ino);ext2_pool_free(held);ext2_inode_t old;assert(!ext2_read_inode(ino,&old)&&old.i_dtime);
 assert(ext2_write(2,"BAD",0,3)==-EISDIR);vfs_file_t f;assert(vfs_open_ext2_inode(2,0,VFS_O_WRONLY,&f,1,0)==-EISDIR);assert(vfs_open_ext2_inode(other,0,VFS_O_TRUNC,&f,1,0)==-EINVAL);
 host_proc.uid=11;host_proc.gid=11;assert(!ext2_mkdir("/private",0700,1));assert(!ext2_create("/private/readable",0644,1));
 host_proc.uid=12;host_proc.gid=12;uint32_t x;assert(ext2_open("/private/readable",&x)==-EACCES);assert(ext2_symlink("/private/link","/other",1)<0);assert(ext2_link("/other","/private/link",1)<0);
 host_proc.uid=0;host_proc.gid=0;assert(!ext2_mkdir("/grant",0777,1));assert(!ext2_mkdir("/grant/child",0777,1));assert(!ext2_mkdir("/outside",0777,1));
 uint32_t grant,child;assert(!ext2_open("/grant",&grant));assert(!ext2_open("/grant/child",&child));int prot=0;assert(!ext2_openat_protected(child,grant,".",&x,&prot));assert(!ext2_rename("/grant/child","/outside/child",1));assert(ext2_openat_protected(child,grant,"..",&x,&prot)==-EACCES);
 /* Renaming into one's own subtree must leave every source name intact,
  * including when the destination parent is reached through a symlink. */
 assert(!ext2_mkdir("/cycle",0777,1));assert(!ext2_mkdir("/cycle/child",0777,1));
 uint32_t cycle,cycle_child;assert(!ext2_open("/cycle",&cycle));assert(!ext2_open("/cycle/child",&cycle_child));
 assert(ext2_rename("/cycle","/cycle/child/moved",0)==-EINVAL);
 assert(ext2_rename("/cycle","/cycle/moved",0)==-EINVAL);
 assert(!ext2_symlink("/alias-child","/cycle/child",1));
 assert(ext2_rename("/cycle","/alias-child/moved",0)==-EINVAL);
 assert(!ext2_open("/cycle",&x)&&x==cycle);assert(!ext2_open("/cycle/child",&x)&&x==cycle_child);
 assert(!ext2_rename("/cycle","/cycle",0));
 assert(!ext2_rename("/cycle","/moved-cycle",0));
 assert(!ext2_open("/moved-cycle/child",&x)&&x==cycle_child);
 assert(!ext2_create("/destination",0600,1));uint32_t dst;assert(!ext2_open("/destination",&dst));assert(ext2_write(dst,"old",0,3)==3);held=ext2_pool_alloc(dst);assert(!ext2_rename("/other","/destination",1));assert(s_ext2_ops.read(held,data,0,3)==3&&!memcmp(data,"old",3));ext2_pool_free(held);
 assert(!ext2_mkdir("/empty",0700,1));assert(!ext2_open("/empty",&dst));held=ext2_pool_alloc(dst);assert(!ext2_rmdir("/empty",1));assert(!ext2_read_inode(dst,&old)&&!old.i_dtime);ext2_pool_free(held);assert(!ext2_read_inode(dst,&old)&&old.i_dtime);
 host_task.is_user=0;assert(!ext2_mkdir("/etc",0755,1));assert(!ext2_mkdir("/etc/aegis",0755,1));marker_absent();
 drop_cache();fail_read_lba=s_bgd[0].bg_inode_table*2;marker_unavailable(-EIO);fail_read_lba=-1;marker_absent();
 uint32_t parent;assert(!ext2_open("/etc/aegis",&parent));ext2_inode_t pd;assert(!ext2_read_inode(parent,&pd));uint32_t plba=pd.i_block[0]*2;
 drop_cache();fail_read_lba=(int)plba;marker_unavailable(-EIO);fail_read_lba=-1;marker_absent();
 drop_cache();uint8_t saved[1024];memcpy(saved,disk[plba],1024);disk[plba][4]=0;disk[plba][5]=0;marker_unavailable(-EIO);memcpy(disk[plba],saved,1024);drop_cache();marker_absent();
 assert(!ext2_create("/etc/aegis/configured",0644,1));marker_present();for(unsigned i=0;i<EXT2_FD_POOL;i++)assert(!s_ext2_pool[i].in_use);
 drop_cache();fail_read_lba=(int)plba;marker_unavailable(-EIO);fail_read_lba=-1;marker_present();
 s_mounted=0;marker_unavailable(-ENODEV);s_mounted=1;
 credential_opens();
 puts("ext2 firstboot: missing marker, inode/directory read faults, corrupt record, present marker PASS");
 puts("ext2: retained unlinked inode, content type, truncate DAC, ancestor DAC, confined moves PASS");
}
'''

GPT = r'''
#include "kernel/fs/gpt.c"
static uint8_t disk[4096];
static int disk_read(blkdev_t*d,uint64_t l,uint32_t n,void*b){(void)d;assert(!l&&n==1);memcpy(b,disk,4096);return 0;}
static int disk_write(blkdev_t*d,uint64_t l,uint32_t n,const void*b){(void)d;assert(!l&&n==1);memcpy(disk,b,4096);return 0;}
blkdev_t *blkdev_get(const char*s){(void)s;return 0;}
int blkdev_register(blkdev_t*d){(void)d;return 0;}
void blkdev_unregister_children(const char*s){(void)s;}
static blkdev_t part;
static void *writer(void *arg){unsigned sector=(unsigned)(uintptr_t)arg;host_cpu.cpu_id=sector+1;uint8_t b[512],r[512];memset(b,sector+17,sizeof b);for(int i=0;i<2000;i++){assert(!gpt_part_write(&part,sector,1,b));assert(!gpt_part_read(&part,sector,1,r));assert(!memcmp(b,r,512));}return 0;}
int main(void){blkdev_t diskdev={.block_count=1,.block_size=4096,.read=disk_read,.write=disk_write};gpt_part_priv_t priv={.parent=&diskdev,.lba_offset=0};part=(blkdev_t){.block_count=8,.block_size=512,.priv=&priv};pthread_t a,b;assert(!pthread_create(&a,0,writer,(void*)0));assert(!pthread_create(&b,0,writer,(void*)1));pthread_join(a,0);pthread_join(b,0);assert(gpt_part_read(&part,UINT64_MAX,2,disk)==-1);puts("gpt: shared 4Kn bounce read/modify/write serialization and overflow bounds PASS");}
'''

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--case', choices=('ramfs', 'ramfs-position', 'fat', 'memfd', 'ext2', 'gpt'),
                    help='run just one production-code host fixture')
parser.add_argument('--no-sanitize', action='store_true',
                    help='disable sanitizers when the host runtime is unavailable')
args = parser.parse_args()

with tempfile.TemporaryDirectory(prefix='aegis-fs-security-') as temp:
    temp = Path(temp)
    for name, contents in STUBS.items():
        (temp / name).write_text(contents)
    for name, source in [('ramfs', RAMFS), ('ramfs-position', RAMFS_POSITION), ('fat', FAT), ('memfd', MEMFD), ('ext2', EXT2), ('gpt', GPT)]:
        if args.case and name != args.case:
            continue
        file = temp / f'{name}.c'
        file.write_text(COMMON + source.replace('@OPEN@', OPEN_GATE).replace('@FIRSTBOOT@', FIRSTBOOT).replace('@CANON@', function('kernel/fs/vfs.c', 'path_canonicalize')).replace('@OPENAT@', function('kernel/fs/vfs.c', 'vfs_openat_ext2')))
        exe = temp / name
        sanitizers = [] if args.no_sanitize else ['-fsanitize=address,undefined']
        subprocess.run(['cc', '-O1', '-g', *sanitizers, '-pthread',
                        '-I'+str(temp), '-I'+str(ROOT), '-I'+str(ROOT/'kernel/fs'),
                        '-I'+str(ROOT/'kernel/cap'), '-I'+str(ROOT/'kernel/syscall'),
                        str(file), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True, timeout=60)

# Cross-file propagation is also required: the runtime checks above cannot
# substitute for the syscall keeping the lock through identity capture.
vfs = (ROOT/'kernel/fs/vfs.c').read_text()
file = (ROOT/'kernel/syscall/sys_file.c').read_text()
assert 'cap_root_gen = pin.file.cap_root_gen' in file
assert 'pin.file.cap_root_gen' in function('kernel/syscall/sys_file.c','sys_openat')
assert vfs.index('irqflags_t open_fl = g_rootfs->lock()') < vfs.index('int opened = g_rootfs->open_protected')
assert not re.search(r's_(?:passwd|shadow)\[', (ROOT/'kernel/fs/initrd.c').read_text())
print('filesystem security checks: PASS')
