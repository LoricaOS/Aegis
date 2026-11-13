/* Fixed ELF fixture, real loader/PCB/scheduler/ERET/SVC/uaccess/cap boundary.
 * No init bootstrap grants, entropy substitute, rootfs or syscall shortcut. */
#include "kernel_user.h"
#include "kernel_memory.h"
#include "kernel_timer.h"
#include "qr_report.h"
#include "probe_console.h"
#include "apple_user_layout.h"
#include "arch.h"
#include "proc.h"
#include "elf.h"
#include "pmm.h"
#include "kva.h"
#include "vmm.h"
#include "arch_vmm.h"
#include "../../../limits.h"

extern const uint8_t apple_user_elf[], apple_user_elf_end[];
extern volatile uint64_t apple_kernel_atomic_report[4];
volatile struct apple_user_report apple_user_report;
static aegis_process_t *subject;
#define USER_TOP AEGIS_USER_STACK_TOP
#define USER_STACK (USER_TOP - 4096)
#define KERNEL_TEST 0xffffffff80200000ULL

static void report(const char *phase)
{
    apple_qr_user[0] = apple_user_report.pid;
    apple_qr_user[1] = apple_user_report.uid;
    apple_qr_user[2] = apple_user_report.svcs;
    apple_qr_user[3] = apple_user_report.kernel_deny;
    apple_qr_user[4] = apple_user_report.text_deny;
    apple_qr_user[5] = apple_user_report.nx_deny;
    apple_qr_user[6] = apple_user_report.capdeny;
    apple_qr_user[7] = apple_user_report.badptr;
    apple_qr_user[8] = apple_user_report.reason;
    apple_qr_user[9] = apple_user_report.root;
    apple_qr_user[10] = apple_user_report.usp;
    apple_qr_user[11] = apple_user_report.entered;
    apple_qr_progress(phase, apple_kernel_atomic_report);
}

static __attribute__((noreturn)) void stop(uint64_t reason)
{
    arch_disable_irq();
    __asm__ volatile("msr cntp_ctl_el0, %0\nisb" : : "r"(2ULL) : "memory");
    apple_user_report.reason = reason;
    apple_user_report.free = pmm_free_pages();
    probe_puts(reason ? "AEGIS - EL0 CHECKPOINT FAILED\n" : "AEGIS - EL0 CHECKPOINT PASSED\n");
    probe_puts("HALTED - NO ROOTFS OR USER TIMER PREEMPTION\n");
    report(reason ? "user-failed" : "user-complete");
    apple_user_report.stage = reason ? 255 : 3;
    for (;;) __asm__ volatile("wfe");
}

static void context(cpu_state_t *s, uint64_t esr)
{
    uintptr_t frame = (uintptr_t)s;
    uint64_t root, far;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(root));
    __asm__ volatile("mrs %0, far_el1" : "=r"(far));
    if (apple_user_report.stage != 2 || !subject ||
        sched_current() != &subject->task || !subject->task.is_user ||
        subject->task.on_cpu != 0 || root != subject->pml4_phys ||
        frame < (uintptr_t)subject->task.stack_base ||
        frame > subject->task.kernel_stack_top - sizeof(*s) ||
        (s->spsr & 15) || (s->spsr & 0x3c0) != 0x3c0 ||
        s->sp_el0 != USER_TOP - 512) stop(2);
    for (unsigned i = 0; i < CAP_TABLE_SIZE; i++)
        if (subject->caps[i].kind || subject->caps[i].rights) stop(3);
    apple_user_report.entered = 1;
    apple_user_report.frame = frame;
    apple_user_report.usp = s->sp_el0;
    apple_user_report.esr = esr;
    apple_user_report.elr = s->elr;
    apple_user_report.far = far;
}

int apple_user_exception(cpu_state_t *s, uint64_t esr)
{
    context(s, esr);
    unsigned ec = (esr >> 26) & 63;
    uint64_t step = apple_user_report.step;
    static const uint64_t pcs[] = {
        APPLE_USER_USER_SVC_PID, APPLE_USER_USER_SVC_UID,
        APPLE_USER_USER_SVC_UNAME, APPLE_USER_USER_SVC_BADPTR, APPLE_USER_USER_SVC_SOCKET,
    };
    static const uint64_t calls[] = {172, 174, 160, 160, 198};
    if (ec == 0x15) {
        if (step >= 5 || s->elr != pcs[step] + 4 || s->x[8] != calls[step] ||
            (esr & 0xffff)) stop(4);
        if (step == 2 && s->x[0] != USER_TOP - 512) stop(5);
        if (step == 3 && s->x[0] != KERNEL_TEST) stop(5);
        if (step == 4 && (s->x[0] != 2 || s->x[1] != 1 || s->x[2])) stop(5);
        return 0; /* real syscall_dispatch and normal signal-return path */
    }
    uint64_t dfsc = esr & 63;
    if (step == 5 && ec == 0x24 && dfsc >= 0xc && dfsc <= 0xf &&
        !(esr & (1ULL << 6)) && s->elr == APPLE_USER_USER_KERNEL_READ &&
        apple_user_report.far == KERNEL_TEST) {
        apple_user_report.kernel_deny = 1;
        s->elr += 4;
    } else if (step == 6 && ec == 0x24 && dfsc >= 0xc && dfsc <= 0xf &&
               (esr & (1ULL << 6)) && s->elr == APPLE_USER_USER_TEXT_WRITE &&
               apple_user_report.far == APPLE_USER_START) {
        apple_user_report.text_deny = 1;
        s->elr += 4;
    } else if (step == 7 && ec == 0x20 && dfsc >= 0xc && dfsc <= 0xf &&
               s->elr == USER_TOP - 16 && apple_user_report.far == USER_TOP - 16 &&
               s->x[30] == APPLE_USER_USER_NX_RESUME) {
        apple_user_report.nx_deny = 1;
        s->elr = APPLE_USER_USER_NX_RESUME;
    } else if (step == 8 && ec == 0x3c && (esr & 0xffff) == 0x5a &&
               s->elr == APPLE_USER_USER_DONE && s->x[0] == 0x5a) {
        if (apple_user_report.svcs != 5 || !apple_user_report.capdeny ||
            !apple_user_report.badptr || !apple_user_report.kernel_deny ||
            !apple_user_report.text_deny || !apple_user_report.nx_deny) stop(6);
        stop(0);
    } else stop(7); /* no generic fault skipping or arbitrary PC recovery */
    apple_user_report.step++;
    return 1;
}

void apple_user_syscall_result(cpu_state_t *s)
{
    uint64_t step = apple_user_report.step;
    static const uint64_t expected[] = {1, 0, 0, (uint64_t)-14, (uint64_t)-1};
    if (step >= 5 || s->x[0] != expected[step]) stop(8);
    if (step == 3) apple_user_report.badptr = 1;
    if (step == 4) apple_user_report.capdeny = 1;
    apple_user_report.svcs++;
    apple_user_report.step++;
}

void apple_user_run(void)
{
    arch_disable_irq();
    if (apple_memory_report.stage != 5 || apple_timer_report.stage != 3 ||
        apple_timer_report.returned != 1 || apple_timer_report.failure ||
        apple_user_report.stage) stop(1);
    probe_console_reset();
    probe_puts("AEGIS - FIRST EL0 ISOLATION TEST\n");
    apple_user_report.stage = 1;
    uint64_t cpacr;
    __asm__ volatile("mrs %0, cpacr_el1" : "=r"(cpacr));
    cpacr |= 3ULL << 20;
    __asm__ volatile("msr cpacr_el1, %0\nisb" : : "r"(cpacr) : "memory");
    apple_user_report.cpacr = cpacr;
    report("user-before-elf");
    sched_init();
    subject = kva_alloc_pages((sizeof(*subject) + 4095) / 4096);
    if (!subject) stop(9);
    __builtin_memset(subject, 0, sizeof(*subject));
    subject->pml4_phys = vmm_create_user_pml4();
    if (!subject->pml4_phys || vma_init(subject)) stop(9);
    elf_load_result_t loaded;
    if (elf_load(subject, subject->pml4_phys, apple_user_elf,
                 apple_user_elf_end - apple_user_elf, 0, &loaded) ||
        loaded.entry != APPLE_USER_START || loaded.interp[0]) stop(10);
    uint64_t pa = pmm_alloc_page();
    if (!pa) stop(9);
    vmm_zero_page(pa);
    vmm_map_user_page(subject->pml4_phys, USER_STACK, pa,
                     VMM_FLAG_USER | VMM_FLAG_WRITABLE | VMM_FLAG_NX);
    if (vma_insert(subject, USER_STACK, 4096, 3, VMA_STACK)) stop(9);
    uint8_t *region = kva_alloc_pages(AEGIS_STACK_PAGES + 1);
    if (!region) stop(9);
    pa = kva_page_phys(region);
    vmm_unmap_page((uintptr_t)region);
    pmm_free_page(pa);
    subject->task.stack_base = region + 4096;
    subject->task.kernel_stack_top = (uintptr_t)region + (AEGIS_STACK_PAGES + 1) * 4096;
    subject->task.stack_pages = AEGIS_STACK_PAGES;
    subject->task.is_user = 1;
    subject->task.state = TASK_RUNNING;
    subject->pid = proc_alloc_pid();
    subject->tgid = subject->pid;
    subject->thread_count = 1;
    subject->auth_uid = subject->auth_gid = AUTH_ID_NONE;
    subject->uid = subject->gid = 0; /* cosmetic root still has no capabilities */
    subject->fd_table = fd_table_alloc(); /* empty; no inherited device handles */
    if (!subject->fd_table || subject->pid != 1) stop(9);
    fpu_state_init(&subject->task);
    /* Existing ctx_switch + proc_enter_user frame protocol, with all sources
     * masked for this first EL0 gate. No new entry trampoline or syscall ABI. */
    _Static_assert(ARCH_CTX_SLOTS == 12, "ARM64 context frame changed");
    uint64_t *sp = (uint64_t *)(uintptr_t)subject->task.kernel_stack_top - 4;
    sp[0] = 0x3c0; sp[1] = loaded.entry; sp[2] = USER_TOP; sp[3] = subject->pml4_phys;
    sp -= ARCH_CTX_SLOTS;
    __builtin_memset(sp, 0, ARCH_CTX_SLOTS * sizeof(*sp));
    sp[1] = (uintptr_t)proc_enter_user;
    subject->task.sp = (uintptr_t)sp;
    apple_user_report.pid = subject->pid;
    apple_user_report.uid = subject->uid;
    apple_user_report.process = (uintptr_t)subject;
    apple_user_report.root = subject->pml4_phys;
    apple_user_report.kstack = subject->task.kernel_stack_top;
    sched_add(&subject->task);
    report("user-before-eret");
    apple_user_report.stage = 2;
    sched_start();
    __builtin_unreachable();
}
