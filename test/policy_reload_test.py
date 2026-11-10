#!/usr/bin/env python3
"""Run production policy reload/lookup/apply with concurrent host readers.

Only filesystem, interrupt/lock, and logging services are stubbed. Policy
parsing, table mutation, snapshot copying and capability grants are unchanged.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

C = r'''
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cap.h"
typedef pthread_mutex_t spinlock_t;
typedef int irqflags_t;
#define SPINLOCK_INIT PTHREAD_MUTEX_INITIALIZER
static _Thread_local unsigned lock_depth, filesystem_version;
static irqflags_t spin_lock_irqsave(spinlock_t *lock) {
    assert(!lock_depth); assert(!pthread_mutex_lock(lock)); lock_depth=1; return 0;
}
static void spin_unlock_irqrestore(spinlock_t *lock, irqflags_t flags) {
    (void)flags; assert(lock_depth==1); lock_depth=0; assert(!pthread_mutex_unlock(lock));
}
#define printk(...) ((void)0)
#define VFS_O_RDONLY 0
static void serial_write_string(const char *s) { (void)s; }
typedef struct {
    int (*readdir)(void *,uint64_t,char *,uint8_t *);
    int (*read)(void *,void *,uint64_t,uint64_t);
    int (*close)(void *);
} file_ops_t;
typedef struct { const file_ops_t *ops; void *priv; uint64_t size; } vfs_file_t;
static int protected_path(const char *path) {
    assert(lock_depth==1);
    return !strncmp(path,"/bin",4) || !strncmp(path,"/sbin",5) ||
           !strncmp(path,"/apps",5) || !strncmp(path,"/trusted",8);
}
static const struct { int (*path_under_protected)(const char *); }
    rootfs={protected_path}, *g_rootfs=&rootfs;
static const char *const names[2]={"alpha","beta"};
static const char *const policies[2][2]={
    {"service NET_SOCKET\n","admin POWER\n"},
    {"service NET_LISTEN\n","admin FB\n"}
};
static int read_dir(void *priv,uint64_t index,char *name,uint8_t *type) {
    (void)priv; assert(lock_depth==1); sched_yield();
    if(index>=2) return -ENOENT;
    /* Reuse each table slot for the OTHER binary on every reload. */
    strcpy(name,names[index ^ filesystem_version]); *type=8; return 0;
}
static int read_file(void *priv,void *out,uint64_t offset,uint64_t size) {
    assert(lock_depth==1); assert(!offset); sched_yield();
    assert(size<=strlen(priv)); memcpy(out,priv,size); return (int)size;
}
static int close_file(void *priv) { (void)priv; return 0; }
static const file_ops_t dir_ops={.readdir=read_dir,.close=close_file};
static const file_ops_t file_ops={.read=read_file,.close=close_file};
static int vfs_open(const char *path,int flags,int mode,vfs_file_t *out) {
    (void)flags; (void)mode; memset(out,0,sizeof(*out));
    if(!strcmp(path,"/etc/aegis/caps.d")) { out->ops=&dir_ops; return 0; }
    const char *data=NULL;
    for(unsigned i=0;i<2;i++) {
        char expected[64]; snprintf(expected,sizeof(expected),"/etc/aegis/caps.d/%s",names[i]);
        if(!strcmp(path,expected)) data=policies[filesystem_version][i];
    }
    if(!strcmp(path,"/etc/aegis/anchors")) data="/trusted\n";
    if(!data) return -ENOENT;
    out->ops=&file_ops; out->priv=(void *)data; out->size=strlen(data); return 0;
}
'''
for source in ("kernel/cap/cap.c", "kernel/cap/cap_policy.c"):
    C += re.sub(r'(?m)^#include[^\n]*\n', '', (ROOT / source).read_text())
C += r'''
static atomic_uint ready, start, reloads, concurrent_reads;
static atomic_int writer_done;
static void begin(void) {
    atomic_fetch_add(&ready,1);
    while(!atomic_load(&start)) sched_yield();
}
static void check_snapshot(const cap_policy_entry_t *entry,unsigned binary) {
    assert(!strcmp(entry->name,names[binary]) && entry->count==1);
    assert(entry->caps[0].rights==(CAP_RIGHTS_READ|CAP_RIGHTS_WRITE|CAP_RIGHTS_EXEC));
    assert(entry->caps[0].tier==(binary ? CAP_TIER_ADMIN : CAP_TIER_SERVICE));
    uint32_t kind=entry->caps[0].kind;
    assert(binary ? (kind==CAP_KIND_POWER || kind==CAP_KIND_FB)
                  : (kind==CAP_KIND_NET_SOCKET || kind==CAP_KIND_NET_LISTEN));
}
static void check_grants(const cap_slot_t *caps,unsigned binary,int elevated) {
    static const cap_slot_t baseline[]={
        {CAP_KIND_VFS_OPEN,CAP_RIGHTS_READ},{CAP_KIND_VFS_WRITE,CAP_RIGHTS_WRITE},
        {CAP_KIND_VFS_READ,CAP_RIGHTS_READ},{CAP_KIND_IPC,CAP_RIGHTS_READ},
        {CAP_KIND_THREAD_CREATE,CAP_RIGHTS_READ}
    };
    assert(!memcmp(caps,baseline,sizeof(baseline)));
    unsigned extra=0;
    for(unsigned i=5;i<CAP_TABLE_SIZE;i++) {
        if(caps[i].kind==CAP_KIND_NULL) { assert(!caps[i].rights); continue; }
        assert(caps[i].rights==7);
        assert(binary ? (caps[i].kind==CAP_KIND_POWER || caps[i].kind==CAP_KIND_FB)
                      : (caps[i].kind==CAP_KIND_NET_SOCKET || caps[i].kind==CAP_KIND_NET_LISTEN));
        extra++;
    }
    assert(extra==(!binary || elevated));
}
static void *writer(void *arg) {
    (void)arg; begin();
    for(unsigned i=0;i<2000;i++) {
        filesystem_version=i&1; cap_policy_load(); atomic_fetch_add(&reloads,1);
        if(!i) while(!atomic_load(&concurrent_reads)) sched_yield();
    }
    atomic_store(&writer_done,1); return NULL;
}
static void *reader(void *arg) {
    unsigned id=(unsigned)(uintptr_t)arg; begin();
    for(unsigned i=0;i<4000;i++) {
        unsigned binary=(i+id)&1;
        const char *path=binary ? "/bin/beta" : "/bin/alpha";
        cap_policy_entry_t copy;
        assert(cap_policy_lookup(path,&copy)); check_snapshot(&copy,binary);
        cap_policy_entry_t saved=copy; sched_yield();
        assert(!memcmp(&copy,&saved,sizeof(copy)));
        cap_slot_t caps[CAP_TABLE_SIZE];
        int elevated=(i/2)&1;
        cap_apply_policy(caps,path,elevated,elevated);
        check_grants(caps,binary,elevated);
        assert(cap_policy_lookup(path,NULL));
        assert(!cap_policy_lookup("/tmp/alpha",NULL));
        if(!(i%64)) cap_anchor_audit();
        if(!atomic_load(&writer_done)) atomic_fetch_add(&concurrent_reads,1);
    }
    return NULL;
}
int main(void) {
    /* A returned snapshot must survive its original slot being overwritten. */
    filesystem_version=0; cap_policy_load();
    cap_policy_entry_t snapshot;
    assert(cap_policy_lookup("/bin/alpha",&snapshot));
    cap_policy_entry_t saved=snapshot;
    filesystem_version=1; cap_policy_load();
    assert(!memcmp(&snapshot,&saved,sizeof(snapshot)));
    assert(snapshot.caps[0].kind==CAP_KIND_NET_SOCKET);
    cap_policy_entry_t current;
    assert(cap_policy_lookup("/bin/alpha",&current));
    assert(current.caps[0].kind==CAP_KIND_NET_LISTEN);
    assert(!cap_policy_lookup(NULL,NULL) && !cap_policy_lookup("/bin/missing",NULL));
    pthread_t threads[4];
    assert(!pthread_create(&threads[0],NULL,writer,NULL));
    for(unsigned i=1;i<4;i++) assert(!pthread_create(&threads[i],NULL,reader,(void *)(uintptr_t)i));
    while(atomic_load(&ready)!=4) sched_yield();
    atomic_store(&start,1);
    for(unsigned i=0;i<4;i++) assert(!pthread_join(threads[i],NULL));
    assert(atomic_load(&reloads)==2000 && atomic_load(&concurrent_reads)>0);
    puts("Policy reload: 2000 reloads, 12000 concurrent lookup/apply checks, stable snapshots: ok");
}
'''
with tempfile.TemporaryDirectory(prefix="aegis-policy-reload-") as temp:
    source = Path(temp) / "test.c"
    source.write_text(C)
    exe = Path(temp) / "test"
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1", "-g", "-pthread",
                    "-fsanitize=address,undefined", "-I", str(ROOT / "kernel/cap"),
                    str(source), "-o", str(exe)], check=True, timeout=30)
    subprocess.run([str(exe)], check=True, timeout=30)
