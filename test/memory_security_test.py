#!/usr/bin/env python3
"""Execute production C MM/waitq logic with mocked page tables and IRQ locks."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]

def function(path, name):
    source = (root / path).read_text()
    m = re.search(r"\n(?:static\s+)?(?:inline\s+)?(?:int|void|uint64_t|uint32_t)\s+" + name + r"\s*\(", source)
    assert m, name
    start = source.index("{", m.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[m.start():end]

def run_c(source):
    with tempfile.TemporaryDirectory(prefix="aegis-memory-test-") as tmp:
        path = Path(tmp) / "check.c"
        path.write_text(source)
        binary = Path(tmp) / "check"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Wno-unused-function", "-Wno-unused-variable", "-Wno-unused-but-set-variable", "-pthread", "-I", str(root), str(path), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)

common = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "kernel/mm/vmm.h"
typedef int spinlock_t;
typedef int irqflags_t;
static int vmm_window_lock, vmm_lock;
static uint64_t pages[32][512];
static unsigned refs[32], maps, fail_map, flushes, expect_old_pin;
static uint64_t child_pte;
static void spin_lock(int *l) { assert(!*l); *l = 1; }
static void spin_unlock(int *l) { assert(*l); *l = 0; }
static int spin_lock_irqsave(int *l) { spin_lock(l); return 0; }
static void spin_unlock_irqrestore(int *l, int f) { (void)f; spin_unlock(l); }
void *vmm_window_map(uint64_t p) { assert(p / 4096 < 32); return pages[p / 4096]; }
void *vmm_window_map2(uint64_t p) { return vmm_window_map(p); }
void vmm_window_unmap(void) {}
void vmm_window_unmap2(void) {}
static uint64_t *pv(uint64_t p) { return vmm_window_map(p); }
static uint64_t *walk_to_pte(uint64_t p, uint64_t v) { (void)p; (void)v; return &pages[4][0]; }
static void *arch_dmap(uint64_t p) { return vmm_window_map(p); }
static void arch_vmm_invlpg(uint64_t v) { (void)v; }
static void tlb_flush_local(void) { flushes++; }
static void tlb_flush_all_cpus(void) { assert(!vmm_window_lock); flushes++; }
static void tlb_shootdown(uint64_t p, uint64_t a, uint64_t b) {
    (void)p; assert(!vmm_window_lock); assert(a % 4096 == 0 && b == a + 4096);
    /* The replaced frame stays pinned until every stale reader is flushed. */
    if (expect_old_pin) assert(refs[9] == 2 && refs[10] == 1);
    flushes++;
}
uint32_t pmm_page_refcount(uint64_t p) { return refs[p / 4096]; }
int pmm_ref_page(uint64_t p) {
    if (refs[p / 4096] == 1023) return -1;
    refs[p / 4096]++; return 0;
}
void pmm_free_page(uint64_t p) { assert(refs[p / 4096]); refs[p / 4096]--; }
uint64_t pmm_alloc_page(void) { assert(!refs[10]); refs[10] = 1; return 10 * 4096; }
static int map_page_in(uint64_t p, uint64_t v, uint64_t frame, uint64_t flags, int unused) {
    (void)p; (void)v; (void)unused;
    int owned = !(flags & VMM_FLAG_SHARED) || (flags & VMM_FLAG_SHARED_OWNED);
    if (owned && frame == 9 * 4096) assert(refs[9] >= 2);
    if (fail_map) return -1;
    maps++; child_pte = frame | arch_pte_from_flags(flags); return 0;
}
static int vmm_map_user_page_nolock(uint64_t p, uint64_t v, uint64_t f, uint64_t flags) {
    return map_page_in(p, v, f, flags, 0);
}
#define VMM_PAGE_SIZE 4096UL
#define PTE_PS (1UL << 7)
static void reset(uint64_t flags, unsigned count) {
    memset(pages, 0, sizeof(pages)); memset(refs, 0, sizeof(refs));
    pages[1][0] = 2 * 4096 | 3; pages[2][0] = 3 * 4096 | 3;
    pages[3][0] = 4 * 4096 | 3;
    pages[4][0] = 9 * 4096 | arch_pte_from_flags(flags);
    refs[9] = count; maps = fail_map = flushes = 0; child_pte = 0;
}
'''
main = r'''
int main(void) {
    const uint64_t ro = VMM_FLAG_PRESENT | VMM_FLAG_USER | VMM_FLAG_NX;
    const uint64_t rw = ro | VMM_FLAG_WRITABLE;
    for (unsigned shared = 0; shared < 3; shared++) {
        uint64_t sh = shared == 1 ? VMM_FLAG_SHARED : shared == 2 ? VMM_FLAG_SHARED_OWNED : 0;
        for (unsigned saved = 0; saved < 2; saved++) {
            reset(ro | sh, 2);
            if (saved) assert(vmm_set_user_prot(4096, 0, 0) == 0);
            assert(vmm_set_user_prot(4096, 0, rw) == 0);
            uint64_t flags = decode(pages[4][0]);
            assert((flags & (VMM_FLAG_SHARED | VMM_FLAG_SHARED_OWNED)) == sh);
            assert(!!(flags & VMM_FLAG_WRITABLE) == !!sh);
            assert(!!(flags & VMM_FLAG_COW) == !sh);
        }
    }
    reset(ro | VMM_FLAG_COW, 2);
    assert(vmm_set_user_prot(4096, 0, ro) == 0);
    assert(!(decode(pages[4][0]) & VMM_FLAG_COW));
    assert(vmm_cow_fault_handle(4096, 0) == -1); /* read-only stays read-only */
    assert(vmm_set_user_prot(4096, 0, 0) == 0);
    assert(!(decode(pages[4][0]) & VMM_FLAG_COW));
    assert(vmm_cow_fault_handle(4096, 0) == -1);
    assert(vmm_set_user_prot(4096, 0, rw) == 0);
    assert(decode(pages[4][0]) & VMM_FLAG_COW);
    expect_old_pin = 1;
    assert(vmm_cow_fault_handle(4096, 17) == 0);
    expect_old_pin = 0;
    assert(ARCH_PTE_ADDR(pages[4][0]) == 10 * 4096 && refs[9] == 1 && refs[10] == 1);
#ifdef X86_TEST
    assert(flushes >= 1);
#endif
    reset(ro | VMM_FLAG_COW, 1);
    assert(vmm_set_user_prot(4096, 0, rw) == 0);
    assert((decode(pages[4][0]) & (VMM_FLAG_COW | VMM_FLAG_WRITABLE)) == VMM_FLAG_WRITABLE);
    for (unsigned mode = 0; mode < 4; mode++) {
        uint64_t flags = mode == 0 ? ro : mode == 1 ? rw : mode == 2 ? rw | VMM_FLAG_SHARED_OWNED : rw | VMM_FLAG_SHARED;
        reset(flags, 1);
        assert(vmm_cow_user_pages(4096, 5 * 4096) == 0);
        assert(maps == 1 && refs[9] == (mode == 3 ? 1 : 2));
        assert(!!(decode(child_pte) & VMM_FLAG_COW) == (mode == 1));
        reset(flags, 1); fail_map = 1;
        assert(vmm_cow_user_pages(4096, 5 * 4096) == -1);
        assert(!maps && refs[9] == 1);
        if (mode != 3) {
            reset(flags, 1023);
            assert(vmm_cow_user_pages(4096, 5 * 4096) == -1);
            assert(!maps && refs[9] == 1023);
        }
    }
    /* PROT_NONE before fork still carries bytes and lifetime ownership. */
    for (int eager = 0; eager < 2; eager++) {
        reset(ro, 1); pages[9][0] = 0xabcdef;
        assert(vmm_set_user_prot(4096, 0, 0) == 0);
        assert((eager ? vmm_copy_user_pages(4096, 5 * 4096)
                      : vmm_cow_user_pages(4096, 5 * 4096)) == 0);
        assert(maps == 1 && !(decode(child_pte) & VMM_FLAG_PRESENT));
        assert(refs[9] == (eager ? 1 : 2));
        pages[4][0] = child_pte; /* switch mock leaf to the child's mapping */
        assert(vmm_set_user_prot(4096, 0, ro) == 0);
        assert(pages[ARCH_PTE_ADDR(pages[4][0]) / 4096][0] == 0xabcdef);
        reset(ro, 1); vmm_set_user_prot(4096, 0, 0); fail_map = 1;
        assert((eager ? vmm_copy_user_pages(4096, 5 * 4096)
                      : vmm_cow_user_pages(4096, 5 * 4096)) == -1);
        assert(!maps && refs[9] == 1 && refs[10] == 0);
    }
    return 0;
}
'''
for arch, path in (("x86_64", "kernel/mm/vmm.c"), ("arm64", "kernel/arch/arm64/vmm.c")):
    header = f'#include "kernel/arch/{arch}/arch_vmm.h"\n'
    header += '#define X86_TEST\n#define decode(x) (x)\n' if arch == 'x86_64' else '#define decode(x) arch_pte_to_flags(x)\n'
    bodies = '\n'.join(function(path, f) for f in ('vmm_set_user_prot', 'vmm_copy_user_pages', 'vmm_cow_user_pages', 'vmm_cow_fault_handle'))
    # tlbi instructions cannot run on the host; the production call site remains.
    bodies = re.sub(r'__asm__ volatile\("dsb ishst.*?::: "memory"\);', 'tlb_flush_local();', bodies)
    run_c(header + common + bodies + main)

wait_source = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
typedef int irqflags_t;
typedef struct aegis_task_t { int state, wake_pending, on_cpu, woken; } aegis_task_t;
typedef struct waitq_entry { aegis_task_t *task; struct waitq_entry *next; } waitq_entry_t;
typedef struct { waitq_entry_t *head; int lock; } waitq_t;
static int sched_lock;
static waitq_t queue;
#define TASK_RUNNING 0
#define TASK_BLOCKED 1
#define TASK_ZOMBIE 2
#define SCHED_POLICY_FAIR 1
static int s_sched_policy = SCHED_POLICY_FAIR;
static void spin_lock(int *l) { assert(!*l); if (l == &queue.lock) assert(sched_lock); *l = 1; }
static void spin_unlock(int *l) { assert(*l); *l = 0; }
static int spin_lock_irqsave(int *l) { spin_lock(l); return 0; }
static void spin_unlock_irqrestore(int *l, int f) { (void)f; spin_unlock(l); }
static void run_list_insert_locked(aegis_task_t *t) { assert(sched_lock && queue.lock); t->woken++; }
'''
wait_source += function('kernel/sched/sched.c', 'sched_wake_locked')
wait_source += function('kernel/sched/waitq.c', 'waitq_wake_one')
wait_source += function('kernel/sched/waitq.c', 'waitq_wake_all')
wait_source += r'''
int main(void) {
    aegis_task_t tasks[130] = {0}; waitq_entry_t entries[130] = {0};
    waitq_wake_one(&queue); waitq_wake_all(&queue);
    for (int i = 0; i < 130; i++) {
        tasks[i].state = TASK_BLOCKED; tasks[i].on_cpu = -1;
        entries[i].task = &tasks[i]; entries[i].next = queue.head; queue.head = &entries[i];
    }
    tasks[20].state = TASK_ZOMBIE;
    waitq_wake_all(&queue);
    for (int i = 0; i < 130; i++) assert(tasks[i].woken == (i != 20));
    assert(tasks[20].state == TASK_ZOMBIE && !tasks[20].wake_pending);
    assert(!sched_lock && !queue.lock);
    return 0;
}
'''
run_c(wait_source)

process = (root / 'kernel/syscall/sys_process.c').read_text()
assert 'vmm_write_user_bytes(' not in process
clone = function('kernel/syscall/sys_process.c', 'sys_clone')
assert clone.index('user_rsp > USER_ADDR_MAX') < clone.index('return sys_fork(')
assert clone.index('copy_to_user(') < clone.index('sched_add(')
assert clone.index('child->vfork_parent = parent_task') < clone.index('sched_add(')

# Exercise the actual authorization prefixes; success returns before mapping.
memory = (root / 'kernel/syscall/sys_memory.c').read_text()
prefix = function('kernel/syscall/sys_memory.c', 'sys_mmap_impl').split('    /* Read-only MAP_SHARED', 1)[0] + 'return 123;\n}'
mprotect = function('kernel/syscall/sys_memory.c', 'sys_mprotect_impl').split('    /* Update the VMA table FIRST so', 1)[0] + 'return 123;\n}'
authority = r'''
#include <assert.h>
#include <stdint.h>
#undef __unused
#include "kernel/fs/vfs.h"
#include "kernel/mm/vmm.h"
#include "kernel/cap/cap.h"
#include "kernel/include/aegis_errno.h"
#define USER_ADDR_MAX 0x7fffffffffffUL
#define MM_MAX_RANGE_PAGES (1UL << 20)
#define VMA_SHARED 8
#define VMA_SHARED_RO 10
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 32
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
typedef struct { int type; uint64_t base, len; } vma_entry_t;
typedef struct { cap_slot_t caps[CAP_TABLE_SIZE]; int admin_session; } aegis_process_t;
static aegis_process_t proc;
static unsigned allowed;
static uint32_t auth_rights;
static int mapped_type;
static aegis_process_t *current_proc(void) { return &proc; }
int cap_check(const cap_slot_t *c, uint32_t n, uint32_t kind, uint32_t rights) {
    (void)c; (void)n;
    if (kind == CAP_KIND_AUTH && (auth_rights & rights) != rights) return -1;
    return allowed & (1U << kind) ? 0 : -1;
}
static int vma_find_copy(aegis_process_t *p, uint64_t a, vma_entry_t *v) {
    (void)p; v->base = a; v->len = 4096; v->type = mapped_type; return 1;
}
'''
authority += prefix + mprotect + r'''
int main(void) {
    vfs_file_t fd = { .flags = VFS_O_RDWR };
    assert(sys_mmap_impl(0,4096,PROT_READ,MAP_PRIVATE,3,0,&fd) == SYS_ERR(ENOCAP));
    allowed = 1U << CAP_KIND_VFS_READ;
    assert(sys_mmap_impl(0,4096,PROT_WRITE,MAP_PRIVATE,3,0,&fd) == 123);
    fd.flags = VFS_O_WRONLY;
    assert(sys_mmap_impl(0,4096,PROT_READ,MAP_PRIVATE,3,0,&fd) == SYS_ERR(EACCES));
    fd.flags = VFS_O_RDWR;
    assert(sys_mmap_impl(0,4096,PROT_WRITE,MAP_SHARED,3,0,&fd) == SYS_ERR(ENOCAP));
    allowed |= 1U << CAP_KIND_VFS_WRITE;
    assert(sys_mmap_impl(0,4096,PROT_WRITE,MAP_SHARED,3,0,&fd) == 123);
    fd.flags = VFS_O_RDONLY;
    assert(sys_mmap_impl(0,4096,PROT_WRITE,MAP_SHARED,3,0,&fd) == SYS_ERR(EACCES));
    fd.flags = VFS_O_RDWR; fd.kflags = VFS_KF_ACCOUNT_DB;
    assert(sys_mmap_impl(0,4096,PROT_WRITE,MAP_SHARED,3,0,&fd) == SYS_ERR(EACCES));
    proc.admin_session = 1;
    assert(sys_mmap_impl(0,4096,PROT_WRITE,MAP_SHARED,3,0,&fd) == 123);
    fd.kflags = VFS_KF_AUTH_GATED;
    fd.flags = VFS_O_RDONLY;
    /* An inherited credential fd is not AUTH authority, even in an elevated
     * session. Cover both read mappings and private writable copies. */
    for (int admin = 0; admin <= 1; admin++) {
        proc.admin_session = admin;
        allowed &= ~(1U << CAP_KIND_AUTH);
        assert(sys_mmap_impl(0,4096,PROT_READ,MAP_PRIVATE,3,0,&fd) == SYS_ERR(EACCES));
        assert(sys_mmap_impl(0,4096,PROT_WRITE,MAP_PRIVATE,3,0,&fd) == SYS_ERR(EACCES));
        assert(sys_mmap_impl(0,4096,PROT_READ,MAP_SHARED,3,0,&fd) == SYS_ERR(EACCES));
        allowed |= 1U << CAP_KIND_AUTH;
        auth_rights = CAP_RIGHTS_WRITE;
        assert(sys_mmap_impl(0,4096,PROT_READ,MAP_PRIVATE,3,0,&fd) == SYS_ERR(EACCES));
        assert(sys_mmap_impl(0,4096,PROT_WRITE,MAP_PRIVATE,3,0,&fd) == SYS_ERR(EACCES));
        assert(sys_mmap_impl(0,4096,PROT_READ,MAP_SHARED,3,0,&fd) == SYS_ERR(EACCES));
        auth_rights = CAP_RIGHTS_READ;
        assert(sys_mmap_impl(0,4096,PROT_READ,MAP_PRIVATE,3,0,&fd) == 123);
        assert(sys_mmap_impl(0,4096,PROT_WRITE,MAP_PRIVATE,3,0,&fd) == 123);
        assert(sys_mmap_impl(0,4096,PROT_READ,MAP_SHARED,3,0,&fd) == 123);
    }
    mapped_type = VMA_SHARED_RO;
    assert(sys_mprotect_impl(0,4096,PROT_WRITE) == SYS_ERR(EACCES));
    assert(sys_mprotect_impl(0,4096,PROT_READ) == 123);
    mapped_type = VMA_SHARED; allowed = 0;
    assert(sys_mprotect_impl(0,4096,PROT_WRITE) == SYS_ERR(ENOCAP));
    mapped_type = 5;
    assert(sys_mprotect_impl(0,4096,PROT_WRITE) == 123);
    return 0;
}
'''
run_c(authority)

# Compile the entire VMA implementation; race replacement/free with snapshots.
vma_header = re.sub(r'^#include.*$', '', (root / 'kernel/mm/vma.h').read_text(), flags=re.M)
vma_body = re.sub(r'^#include.*$', '', (root / 'kernel/mm/vma.c').read_text(), flags=re.M)
vma_test = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include "kernel/lib/refcount.h"
#define AEGIS_PAGE_SIZE 4096
#define SPINLOCK_INIT 0
typedef int spinlock_t;
typedef int irqflags_t;
static void spin_lock(int *l) { while (__atomic_exchange_n(l, 1, __ATOMIC_ACQUIRE)) {} }
static void spin_unlock(int *l) { __atomic_store_n(l, 0, __ATOMIC_RELEASE); }
static int spin_trylock(int *l) { int old = 0; return __atomic_compare_exchange_n(l,&old,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED); }
static int spin_lock_irqsave(int *l) { spin_lock(l); return 0; }
static void spin_unlock_irqrestore(int *l, int f) { (void)f; spin_unlock(l); }
static int arch_irq_save(void) { return 0; }
static void arch_pause(void) {}
static void tlb_poll_incoming(void) {}
static void *kva_alloc_pages(unsigned n) { return malloc(n * 4096); }
static void kva_free_pages(void *p, unsigned n) { (void)n; free(p); }
'''
vma_test += vma_header
vma_test += 'struct aegis_process { vma_entry_t *vma_table; uint32_t vma_capacity; };\n'
vma_test += vma_body
vma_test += r'''
static struct aegis_process p;
static void *writer(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000; i++) {
        assert(vma_init(&p) == 0);
        assert(vma_insert(&p, 4096, 4096, 3, VMA_MMAP) == 0);
        assert(vma_insert(&p, 12288, 4096, 3, VMA_MMAP) == 0);
        vma_free(&p);
    }
    return NULL;
}
int main(void) {
    pthread_t t; assert(!pthread_create(&t, NULL, writer, NULL));
    for (int i = 0; i < 10000; i++) {
        vma_entry_t entries[1];
        uint32_t n = vma_snapshot(&p, entries, 1); assert(n <= 1);
        if (n) assert(entries[0].base == 4096 && entries[0].len == 4096);
        assert(vma_count_get(&p) <= 2);
        uint64_t size = vma_size_bytes(&p); assert(size <= 8192 && size % 4096 == 0);
    }
    assert(!pthread_join(t, NULL));
    assert(vma_snapshot(&p, NULL, 0) == 0);
    return 0;
}
'''
run_c(vma_test)

# Run actual install helpers too: public kernel/user mappings must force PRESENT,
# while fork's internal mapper must preserve a saved PROT_NONE leaf descriptor.
mapper_common = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "kernel/mm/vmm.h"
#define VMM_PAGE_MASK (~0xfffUL)
#define printk(...) ((void)0)
typedef int spinlock_t;
typedef int irqflags_t;
static int vmm_window_lock, vmm_lock;
static uint64_t s_pml4_phys = 4096, s_ttbr1_phys = 4096;
static uint64_t tables[9][512];
static unsigned alloc_call, fail_alloc;
static void panic_halt(const char *why) { (void)why; abort(); }
static irqflags_t spin_lock_irqsave(int *lock) { assert(!*lock); *lock = 1; return 0; }
static void spin_unlock_irqrestore(int *lock, irqflags_t flags) { (void)flags; assert(*lock); *lock = 0; }
void *vmm_window_map(uint64_t phys) { assert(phys / 4096 < 9); return tables[phys / 4096]; }
void vmm_window_unmap(void) {}
static uint64_t *pv(uint64_t phys) { return vmm_window_map(phys); }
static uint64_t ensure_table_phys(uint64_t parent, uint64_t index, uint64_t flags) {
    (void)flags; assert(index < 512);
    if (++alloc_call == fail_alloc) return 0;
    return parent + 4096;
}
static uint64_t ensure_table(uint64_t parent, uint64_t index) { return ensure_table_phys(parent, index, 0); }
static void reset(void) {
    memset(tables, 0, sizeof(tables)); alloc_call = fail_alloc = 0;
    assert(!vmm_window_lock && !vmm_lock);
}
'''
mapper_main = r'''
int main(void) {
    const uint64_t pa = 0x9000, kernel_va = 0xffff800000000000UL;
    const uint64_t rw = VMM_FLAG_WRITABLE | VMM_FLAG_NX;
    reset();
    assert(vmm_try_map_page(kernel_va, pa, rw) == 0);
    assert(decode(tables[4][0]) & VMM_FLAG_PRESENT);
    assert(ARCH_PTE_ADDR(tables[4][0]) == pa);
    reset(); vmm_map_page(kernel_va, pa, rw);
    assert(decode(tables[4][0]) & VMM_FLAG_PRESENT);
    reset(); vmm_map_user_page(5 * 4096, 0, pa, rw | VMM_FLAG_USER);
    assert((decode(tables[8][0]) & (VMM_FLAG_PRESENT | VMM_FLAG_USER)) ==
           (VMM_FLAG_PRESENT | VMM_FLAG_USER));
    reset(); assert(vmm_try_map_user_page(5 * 4096, 0, pa, rw | VMM_FLAG_USER) == 0);
    assert(decode(tables[8][0]) & VMM_FLAG_PRESENT);
    assert(vmm_try_map_user_page(5 * 4096, 0, pa + 4096, rw | VMM_FLAG_USER) == 1);
    assert(ARCH_PTE_ADDR(tables[8][0]) == pa);
    reset(); assert(fork_map(5 * 4096, 0, pa, 0) == 0);
    assert(tables[8][0] == pa); /* saved frame; no hardware or COW permission */
    reset(); assert(fork_map(5 * 4096, 0, pa, VMM_FLAG_SHARED_OWNED) == 0);
    assert(!(decode(tables[8][0]) & VMM_FLAG_PRESENT));
    assert(decode(tables[8][0]) & VMM_FLAG_SHARED_OWNED);
    for (unsigned level = 1; level <= 3; level++) {
        reset(); fail_alloc = level;
        assert(vmm_try_map_page(kernel_va, pa, rw) == -1 && tables[4][0] == 0);
        reset(); fail_alloc = level;
        assert(fork_map(5 * 4096, 0, pa, 0) == -1 && tables[8][0] == 0);
    }
    return 0;
}
'''
for arch, path in (("x86_64", "kernel/mm/vmm.c"), ("arm64", "kernel/arch/arm64/vmm.c")):
    mapper = 'vmm_map_user_page_nolock' if arch == 'x86_64' else 'map_page_in'
    header = f'#include "kernel/arch/{arch}/arch_vmm.h"\n'
    header += '#define decode(x) (x)\n#define fork_map(p,v,f,flags) vmm_map_user_page_nolock(p,v,f,flags)\n' if arch == 'x86_64' else '#define decode(x) arch_pte_to_flags(x)\n#define fork_map(p,v,f,flags) map_page_in(p,v,f,flags,0)\n'
    names = (mapper, 'vmm_try_map_page', 'vmm_map_page', 'vmm_map_user_page', 'vmm_try_map_user_page')
    bodies = '\n'.join(function(path, name) for name in names)
    if arch == 'arm64':
        bodies = re.sub(r'__asm__ volatile\([\s\S]*?\);', '(void)0;', bodies)
    run_c(header + mapper_common + bodies + mapper_main)

print('memory mapping/COW/refcount, mmap authority, VMA lifetime and waitq checks: PASS')
