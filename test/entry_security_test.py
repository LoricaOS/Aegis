#!/usr/bin/env python3
"""Run production ELF/exec/TLS checks with host stubs; check trap-frame offsets."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text()


def function(path, name):
    text = read(path)
    match = re.search(r"(?m)^(?:static )?[\w *]+\s*" + name + r"\([^;]*?\)\n\{", text)
    assert match, name
    return text[match.start():text.index("\n}", match.end()) + 2] + "\n"


elf = read("kernel/proc/elf.c")
code = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "kernel/limits.h"
#include "kernel/proc/elf.h"
#include "kernel/arch/x86_64/idt.h"
#include "kernel/cap/cap.c"
void serial_write_string(const char *s) { (void)s; }
#define printk(...) ((void)0)
#define USER_ADDR_MAX 0x7fffffffffffULL
#define VMM_FLAG_USER 4ULL
#define VMM_FLAG_WRITABLE 2ULL
#define VMM_FLAG_NX (1ULL << 63)
#define VMA_ELF_TEXT 1
#define VMA_ELF_DATA 2
typedef struct aegis_process { void *vma_table; } aegis_process_t;
static unsigned allocations, mappings;
static uint64_t mapped[16];
static void *kva_alloc_pages(uint64_t n) {
    assert(n && n < 16); allocations++; return calloc(n, 4096);
}
static void kva_unmap_keep_frames(void *p, uint64_t n) { (void)n; free(p); }
static uint64_t kva_page_phys(void *p) { return (uintptr_t)p; }
static uint64_t vmm_phys_of_user_raw(uint64_t p, uint64_t a) {
    (void)p;
    for (unsigned i=0; i<mappings; i++) if (mapped[i]==a) return 4096;
    return 0;
}
static void vmm_map_user_page(uint64_t p, uint64_t a, uint64_t f, uint64_t flags) {
    (void)p; (void)f; (void)flags; assert(mappings<16); mapped[mappings++]=a;
}
static void arch_sync_icache_range(void *p, uint64_t n) { (void)p; (void)n; }
static int vma_insert(aegis_process_t *p, uint64_t a, uint64_t n, uint32_t prot, uint8_t t) {
    (void)p; (void)a; (void)n; (void)prot; (void)t; return 0;
}
'''
code += elf[elf.index("/* ELF64 header */"):elf.index("/* elf_interp_trusted")]
code += function("kernel/proc/elf.c", "elf_load")
code += function("kernel/syscall/sys_exec.c", "exec_gains_caps")
code += r'''
typedef struct { uint64_t fs_base, clear_child_tid; int is_user; } aegis_task_t;
static aegis_task_t task;
static aegis_task_t *sched_current(void) { return &task; }
static uint64_t installed_tls;
static void arch_set_fs_base(uint64_t a) { installed_tls=a; }
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define COPY_TO_USER(a,p) do { (void)(a); (void)(p); } while (0)
'''
code += function("kernel/syscall/sys_identity.c", "sys_arch_prctl")
code += r'''
static struct { Elf64_Ehdr eh; Elf64_Phdr ph[2]; } image;
static int load_at(uint64_t address, uint64_t bytes, uint64_t base) {
    memset(&image,0,sizeof(image));
    memcpy(image.eh.e_ident,"\177ELF",4); image.eh.e_ident[4]=2;
    image.eh.e_type=ET_EXEC; image.eh.e_machine=EM_CURRENT;
    image.eh.e_phoff=sizeof(Elf64_Ehdr); image.eh.e_phnum=1;
    image.eh.e_entry=address;
    image.ph[0].p_type=PT_LOAD; image.ph[0].p_flags=PF_X;
    image.ph[0].p_vaddr=address; image.ph[0].p_memsz=bytes;
    allocations=mappings=0;
    elf_load_result_t out;
    return elf_load(0,4096,(const uint8_t *)&image,sizeof(image),base,&out);
}
int main(void) {
    uint64_t bad[]={AEGIS_USER_STACK_BASE, AEGIS_USER_STACK_BASE+1,
                    AEGIS_USER_STACK_TOP-1};
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        assert(load_at(bad[i],1,0)<0); assert(!allocations && !mappings);
        assert(load_at(bad[i]-INTERP_BASE,1,INTERP_BASE)<0);
        assert(!allocations && !mappings);
    }
    assert(load_at(AEGIS_USER_STACK_BASE-1,2,0)<0 && !allocations);
    assert(load_at(AEGIS_USER_STACK_BASE-4096,4096,0)==0 && mappings==1);
    assert(load_at(AEGIS_USER_STACK_TOP,4096,0)==0 && mappings==1);
    assert(load_at(0x400000,4096,0)==0 && mappings==1);
    assert(load_at(UINT64_MAX-4096,4096,INTERP_BASE)<0 && !allocations);
    cap_slot_t before[CAP_TABLE_SIZE]={0}, after[CAP_TABLE_SIZE]={0};
    assert(!exec_gains_caps(before,after));
    cap_grant(after,CAP_TABLE_SIZE,CAP_KIND_AUTH,CAP_RIGHTS_READ);
    assert(exec_gains_caps(before,after));
    cap_grant(before,CAP_TABLE_SIZE,CAP_KIND_AUTH,CAP_RIGHTS_READ|CAP_RIGHTS_WRITE);
    assert(!exec_gains_caps(before,after));
    after[0].rights=CAP_RIGHTS_READ|CAP_RIGHTS_WRITE;
    before[0].rights=CAP_RIGHTS_READ;
    cap_grant(before,CAP_TABLE_SIZE,CAP_KIND_AUTH,CAP_RIGHTS_WRITE);
    assert(exec_gains_caps(before,after)); /* disjoint slots do not combine */
    const uint64_t invalid[]={0x800000000000ULL,0x1000000000000ULL,UINT64_MAX};
    for (unsigned i=0;i<3;i++) {
        task.fs_base=installed_tls=0x1234;
        assert(sys_arch_prctl(ARCH_SET_FS,invalid[i])==SYS_ERR(EFAULT));
        assert(task.fs_base==0x1234 && installed_tls==0x1234);
    }
    assert(sys_arch_prctl(ARCH_SET_FS,0)==0 && !installed_tls);
    assert(sys_arch_prctl(ARCH_SET_FS,USER_ADDR_MAX)==0 && installed_tls==USER_ADDR_MAX);
    assert(offsetof(cpu_state_t,rip)+8==144);
    assert(offsetof(cpu_state_t,cs)+8==152);
    assert(offsetof(cpu_state_t,rsp)+8==168);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="aegis-entry-test-") as tmp:
    path = Path(tmp) / "entry.c"
    path.write_text(code)
    binary = Path(tmp) / "entry"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-I", str(ROOT), str(path),
                    "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)

# Trap instructions cannot execute at host CPL3. Check the actual assembly
# choke points and the frame offsets exercised against cpu_state_t above.
isr = read("kernel/arch/x86_64/isr.asm")
entry = isr.split("isr_common_stub:\n", 1)[1].split("isr_post_dispatch:\n", 1)[0]
assert entry.index("cld") < entry.index("call isr_dispatch")
iret = isr.split("isr_post_dispatch:\n", 1)[1].split("    iretq", 1)[0]
assert iret.index("[rsp + 168]") < iret.index("pop  rax") < iret.index("swapgs")
sysret = read("kernel/arch/x86_64/syscall_entry.asm").split(".sig_sysret_done:\n", 1)[1]
assert sysret.index("shr  rcx, 47") < sysret.index("pop  rsp") < sysret.index("swapgs")
signal = function("kernel/syscall/sys_signal.c", "sys_rt_sigreturn")
assert "if (copy_from_user(&sf" in signal
assert "cs.rsp > USER_ADDR_MAX" in signal and "FRAME_SP(frame) > USER_ADDR_MAX" in signal
print("entry/exec security checks: PASS")
