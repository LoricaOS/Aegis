#!/usr/bin/env python3
"""Host-execute kernel-task creation on dirty allocator pages (ARM64/x86).

Actual task structure and creation function; only allocator, FPU initializer
and per-CPU/VMM boundaries are mocked. No privileged instructions execute.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
header = (ROOT / "kernel/sched/sched.h").read_text()
task = header[header.index("typedef struct aegis_task_t {"):
              header.index("} aegis_task_t;") + len("} aegis_task_t;")]
source = (ROOT / "kernel/sched/sched.c").read_text()
start = source.index("static aegis_task_t *\nsched_spawn_task_locked(")
begin = source.index("{", start)
depth, end = 1, begin + 1
while depth:
    depth += (source[end] == "{") - (source[end] == "}")
    end += 1
spawn = source[start:end]

PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#define TASK_RUNNING 0
#define STACK_PAGES 4
#define STACK_SIZE (STACK_PAGES * 4096)
'''
MOCKS = r'''
_Alignas(4096) static uint8_t tcbs[2][4096], stacks[2][5 * 4096];
static aegis_task_t *current;
static uint32_t s_next_tid, s_task_count;
static unsigned allocations, fail_at, freed, unmapped, released;
static void *kva_alloc_pages(unsigned n) {
    unsigned call = ++allocations;
    if (call == fail_at) return NULL;
    unsigned i = (call - 1) / 2;
    assert(i < 2);
    assert(n == ((call & 1) ? 1 : 5));
    return (call & 1) ? tcbs[i] : stacks[i];
}
static void kva_free_pages(void *p, unsigned n) {
    assert(p == tcbs[0] && n == 1); freed++;
}
static uint64_t kva_page_phys(void *p) { return (uintptr_t)p; }
static void vmm_unmap_page(uint64_t p) { assert(p == (uintptr_t)stacks[unmapped++]); }
static void pmm_free_page(uint64_t p) { assert(p == (uintptr_t)stacks[released++]); }
static aegis_task_t *sched_current(void) { return current; }
static void percpu_set_current(aegis_task_t *p) { current = p; }
static void fpu_state_init(aegis_task_t *p) { memset(p->fpu_state, 0, sizeof(p->fpu_state)); }
static void worker(void) {}
'''
MAIN = r'''
int main(void) {
    memset(tcbs, 0xa5, sizeof(tcbs));
    memset(stacks, 0xa5, sizeof(stacks));
    fail_at = 1;
    assert(!sched_spawn_task_locked(worker));
    assert(!current && !s_task_count && !freed && !unmapped && !released);
    allocations = 0; fail_at = 2;
    assert(!sched_spawn_task_locked(worker));
    assert(!current && !s_task_count && freed == 1 && !unmapped && !released);
    allocations = 0; fail_at = 0;
    for (unsigned i = 0; i < 2; i++) {
        aegis_task_t *t = sched_spawn_task_locked(worker);
        assert(t == (void *)tcbs[i] && t->tid == i && t->on_cpu == -1);
        assert(!t->fs_base && !t->sleep_deadline && !t->clear_child_tid);
        assert(!t->last_syscall && !t->read_nonblock && !t->write_nonblock);
        assert(!t->is_user && !t->is_idle && !t->wake_pending);
        assert(!t->sched_queued && t->sched_rq_cpu == -1 && t->last_cpu == -1);
        assert(t->stack_base == stacks[i] + 4096);
        assert(t->kernel_stack_top == (uintptr_t)stacks[i] + sizeof(stacks[i]));
#ifdef __aarch64__
        uint64_t *sp = (void *)(uintptr_t)t->sp;
        assert(sp[0] == 0 && sp[1] == (uintptr_t)worker);
        for (unsigned j = 2; j < 12; j++) assert(sp[j] == 0);
#else
        uint64_t *sp = (void *)(uintptr_t)t->sp;
        for (unsigned j = 0; j < 6; j++) assert(sp[j] == 0);
        assert(sp[6] == (uintptr_t)worker);
#endif
    }
    assert(s_task_count == 2 && current == (void *)tcbs[0]);
    assert(current->next == (void *)tcbs[1] && current->next->next == current);
    assert(unmapped == 2 && released == 2);
    puts("PASS dirty task pages, creation frames, guard pages and allocation refusals");
}
'''
with tempfile.TemporaryDirectory(prefix="aegis-spawn-init-") as directory:
    path = Path(directory) / "check.c"
    path.write_text(PREFIX + task + MOCKS + spawn + MAIN)
    for arch in ("arm64", "x86"):
        binary = Path(directory) / arch
        flags = ["-D__aarch64__=1"] if arch == "arm64" else []
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        *flags, str(path), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=5)
