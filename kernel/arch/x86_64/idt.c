#include "idt.h"
#include "pic.h"
#include "pit.h"
#include "kbd.h"
#include "serial.h"
#include "ps2_mouse.h"
#include "acpi.h"
#include "lapic.h"
#include "ioapic.h"
#include "tlb.h"
#include "smp.h"   /* g_percpu[].self — #DB watchpoint diag */
#include "ksym.h"
#include "printk.h"
#include "arch.h"
#include "fb.h"
#include "signal.h"
#include "proc.h"
#include "vma.h"
#include "vmm.h"   /* vmm_cow_fault_handle — COW write-fault break */
#include "sched.h"

/* 256 entries: full IDT covering all x86-64 interrupt vectors */
static aegis_idt_gate_t s_idt[256];

/* Prototypes for the 48 ISR stubs defined in isr.asm */
extern void *isr_stubs[48];

/* LAPIC timer vector stub (vector 0x30) defined in isr.asm */
extern void *isr_stub_lapic_timer;

/* virtio-net MSI-X RX vector stub (vector 0x40) defined in isr.asm */
extern void *isr_stub_virtio_net;

/* virtio-net MSI-X RX interrupt handler (kernel/drivers/virtio_net.c). Drains
 * the RX used ring on IRQ instead of waiting for the 100 Hz poll. No-op if the
 * NIC is absent or MSI-X was not negotiated (vector 0x40 then never fires). */
void virtio_net_irq(void);

/* Remapped PIC stubs (vectors 0xF0-0xFD) defined in isr.asm.
 * pic_disable() remaps the 8259A to 0xF0-0xFF before masking.  On real
 * hardware a pending PIC interrupt can arrive after STI at these vectors.
 * Without IDT entries the CPU raises #GP. */
extern void *isr_stubs_remap_pic[14];

/* TLB shootdown IPI vector stub (vector 0xFE) defined in isr.asm */
extern void *isr_stub_tlb_shootdown;

/* LAPIC spurious vector stub (vector 0xFF) defined in isr.asm */
extern void *isr_stub_spurious;

static void
idt_gate_set(uint8_t vec, void *handler)
{
    uint64_t addr = (uint64_t)handler;
    s_idt[vec].offset_lo  = addr & 0xFFFF;
    s_idt[vec].selector   = ARCH_KERNEL_CS;  /* kernel code segment */
    s_idt[vec].ist        = 0;
    s_idt[vec].type_attr  = 0x8E;           /* present, DPL=0, interrupt gate */
    s_idt[vec].offset_mid = (addr >> 16) & 0xFFFF;
    s_idt[vec].offset_hi  = (addr >> 32) & 0xFFFFFFFF;
    s_idt[vec].zero       = 0;
}

void
idt_init(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr = {
        .limit = sizeof(s_idt) - 1,
        .base  = (uint64_t)s_idt
    };

    for (int i = 0; i < 48; i++)
        idt_gate_set((uint8_t)i, isr_stubs[i]);

    /* Vector 0x30 — LAPIC timer interrupt (periodic, ~100Hz). */
    idt_gate_set(0x30, isr_stub_lapic_timer);

    /* Vector 0x40 — virtio-net MSI-X RX interrupt (message-signalled, LAPIC). */
    idt_gate_set(0x40, isr_stub_virtio_net);

    /* Vectors 0xF0-0xFD — remapped PIC vectors.  pic_disable() moves the
     * 8259A to 0xF0-0xFF before masking.  On real hardware a pending PIC
     * interrupt can be in-flight and delivered after STI.  These stubs
     * catch it so isr_dispatch can silently drop it instead of #GP. */
    for (int i = 0; i < 14; i++)
        idt_gate_set((uint8_t)(0xF0 + i), isr_stubs_remap_pic[i]);

    /* Vector 0xFE — TLB shootdown IPI from tlb_shootdown().  The handler
     * does its own LAPIC EOI; isr_dispatch skips the normal EOI path. */
    idt_gate_set(0xFE, isr_stub_tlb_shootdown);

    /* Vector 0xFF — LAPIC spurious interrupt.  Per Intel spec, no EOI must
     * be sent for spurious interrupts; isr_dispatch returns immediately. */
    idt_gate_set(0xFF, isr_stub_spurious);

    /* #DF (double fault, vector 8) uses IST1 — dedicated stack prevents
     * triple fault when #DF occurs due to stack overflow or RSP corruption.
     * IST field value 1 in the gate maps to tss.ist[0] (Intel 1-indexed,
     * C array 0-indexed). */
    s_idt[8].ist = 1;

    __asm__ volatile ("lidt %0" : : "m"(idtr));
    printk("[IDT] OK: 256 vectors installed\n");
}

void
arch_load_idt(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr = {
        .limit = sizeof(s_idt) - 1,
        .base  = (uint64_t)s_idt
    };
    __asm__ volatile("lidt %0" : : "m"(idtr));
}

/* Walk the RBP frame-pointer chain and print return addresses.
 * Only valid for kernel-mode exceptions (CS=ARCH_KERNEL_CS).
 * At -O0 with -fno-omit-frame-pointer, every frame pushes RBP.
 * Each frame: [rbp+0] = saved previous RBP, [rbp+8] = return address.
 * Resolve addresses with: make sym ADDR=0x<addr>
 * Limit of 16 frames keeps us well within a single 4KB kernel stack page. */
/* Walk the frame-pointer chain and print up to `max` symbolized return
 * addresses.  Shared by panic_backtrace and the stackshot (dump_all_tasks).
 * At -fno-omit-frame-pointer every frame pushes RBP: [rbp+0]=saved RBP,
 * [rbp+8]=return address. */
void
print_backtrace_from(uint64_t rbp, int max)
{
    for (int i = 0; i < max; i++) {
        /* RBP must be 8-byte aligned and in the higher-half kernel VA range */
        if (rbp < 0xFFFFFFFF80000000ULL || (rbp & 7ULL))
            break;
        uint64_t retaddr = ((uint64_t *)rbp)[1];
        if (retaddr < 0xFFFFFFFF80000000ULL || retaddr == 0)
            break;
        uint64_t off = 0;
        const char *sym = ksym_lookup(retaddr, &off);
        if (sym)
            printk("    [%u] 0x%lx %s+0x%lx\n", i, retaddr, sym, off);
        else
            printk("    [%u] 0x%lx\n", i, retaddr);
        rbp = ((uint64_t *)rbp)[0];
    }
}

static void
panic_backtrace(uint64_t rbp)
{
    printk("[PANIC] backtrace (resolve: make sym ADDR=0x<addr>):\n");
    print_backtrace_from(rbp, 16);
}

/* user_exception — a CPU exception raised from ring 3.  Convert it to a
 * signal instead of panicking: signal_deliver (called by isr.asm on the
 * iretq return path) either runs the process's handler or terminates the
 * process (SIG_DFL).  Without this, any user-space segfault took down the
 * whole kernel.
 *
 * If the signal is blocked or ignored we force SIG_DFL and unblock it —
 * returning to the faulting instruction with the signal undeliverable
 * would re-fault forever (Linux force_sig semantics for synchronous
 * faults).  Note a handler that itself faults hits this path: the sigframe
 * masks the signal during the handler, so the second fault force-resets to
 * SIG_DFL and the process dies rather than looping. */
static void
user_exception(cpu_state_t *s)
{
    aegis_process_t *proc = current_proc();
    uint32_t sig;
    switch (s->vector) {
    case 0:                       /* #DE divide error      */
    case 16:                      /* #MF x87 FP            */
    case 19: sig = SIGFPE;  break; /* #XM SIMD FP          */
    case 3:                       /* #BP breakpoint        */
    case 4:  sig = SIGTRAP; break; /* #OF overflow (into)  */
    case 17: sig = SIGBUS;  break; /* #AC alignment check  */
    case 13:                      /* #GP                   */
    case 14: sig = SIGSEGV; break; /* #PF                  */
    case 6:                       /* #UD invalid opcode    */
    default: sig = SIGILL;  break;
    }

    uint64_t cr2 = 0;
    if (s->vector == 14)
        __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
    printk("[SIG] pid %u: exception %lu RIP=0x%lx err=0x%lx CR2=0x%lx -> signal %u\n",
           proc->pid, s->vector, s->rip, s->error_code, cr2, sig);

    if (proc->sigactions[sig].sa_handler == SIG_IGN ||
        (proc->signal_mask & (1ULL << sig)))
        proc->sigactions[sig].sa_handler = SIG_DFL;
    proc->signal_mask     &= ~(1ULL << sig);
    (void)__atomic_or_fetch(&proc->pending_signals, (1ULL << sig), __ATOMIC_RELAXED);
}



void __attribute__((used))
isr_dispatch(cpu_state_t *s)
{
    /* DIAG (#DB / vector 1): a hardware data watchpoint (DR0-3, armed by
     * hwwatch_arm_local when `hwwatch` is on) fired.  This is a TRAP — the
     * write to g_percpu[].self has already happened; s->rip is the instruction
     * just AFTER the store, and the rbp backtrace names the writer.  Print,
     * clear DR6, disarm THIS CPU (avoid re-trip spam), and continue. */
    if (s->vector == 1) {
        uint64_t dr6;
        __asm__ volatile("mov %%dr6, %0" : "=r"(dr6));
        printk("[HWWATCH] cpu%u WRITE-HIT DR6=0x%lx writer RIP=0x%lx CS=0x%lx rbp=0x%lx\n",
               (unsigned)lapic_id(), dr6, s->rip, s->cs, s->rbp);
        printk("[HWWATCH] self[0]=0x%lx self[1]=0x%lx self[2]=0x%lx self[3]=0x%lx\n",
               (uint64_t)(uintptr_t)g_percpu[0].self,
               (uint64_t)(uintptr_t)g_percpu[1].self,
               (uint64_t)(uintptr_t)g_percpu[2].self,
               (uint64_t)(uintptr_t)g_percpu[3].self);
        if (s->cs == ARCH_KERNEL_CS)
            panic_backtrace(s->rbp);
        __asm__ volatile("mov %0, %%dr6" :: "r"((uint64_t)0));   /* clear status */
        __asm__ volatile("mov %0, %%dr7" :: "r"((uint64_t)0));   /* disarm this CPU */
        return;
    }
    if (s->vector < 32) {
        /* Ring-3 fault: signal the process, never panic the kernel.
         * (s->cs is reliable here — only SS RPL is stripped on AMD.)
         * NMI (2), double fault (8), and machine check (18) are machine/
         * kernel-level failures even when the saved CS is ring 3 — those
         * still panic below. */
        if (s->cs == ARCH_USER_CS &&
            s->vector != 2 && s->vector != 8 && s->vector != 18 &&
            sched_current() && sched_current()->is_user) {
            /* Demand paging: a NOT-PRESENT (#PF err.P==0) page fault on a lazy
             * anonymous mmap page is resolved by populating it and resuming —
             * no signal. Present-protection faults (err.P==1, e.g. write to RO)
             * fall through to user_exception (SIGSEGV) as before. */
            if (s->vector == 14 && !(s->error_code & 1)) {
                uint64_t cr2;
                __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
                if (mm_populate_fault((aegis_process_t *)sched_current(), cr2) == 0)
                    return;
            }
            /* Copy-on-write: a WRITE (#PF err.W==1) to a PRESENT (err.P==1)
             * page may be a COW break from fork. vmm_cow_fault_handle checks
             * the leaf PTE for VMM_FLAG_COW and, if set, breaks the share
             * (reuse-in-place if singly-owned, else copy) and resumes with no
             * signal. Returns 0 = handled (retry the write), -1 = not a COW
             * page (real protection violation → SIGSEGV), -2 = OOM (SIGBUS). */
            if (s->vector == 14 && (s->error_code & 1) && (s->error_code & 2)) {
                uint64_t cr2;
                __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
                aegis_process_t *cp = (aegis_process_t *)sched_current();
                int cr = vmm_cow_fault_handle(cp->pml4_phys, cr2);
                if (cr == 0)
                    return;
                if (cr == -2) {
                    /* OOM breaking the COW share → SIGBUS (deliver via the
                     * pending-bit path like user_exception; force SIG_DFL if
                     * blocked/ignored so the write can't re-fault forever). */
                    if (cp->sigactions[SIGBUS].sa_handler == SIG_IGN ||
                        (cp->signal_mask & (1ULL << SIGBUS)))
                        cp->sigactions[SIGBUS].sa_handler = SIG_DFL;
                    cp->signal_mask &= ~(1ULL << SIGBUS);
                    (void)__atomic_or_fetch(&cp->pending_signals,
                                            (1ULL << SIGBUS), __ATOMIC_RELAXED);
                    return;
                }
                /* cr == -1: not COW → fall through to SIGSEGV below. */
            }
            user_exception(s);
            return;
        }
        /* COW break for KERNEL-mode writes to user pages (copy_to_user et al.).
         * A kernel rep-movsb writing into a user buffer that is a COW page
         * (read-only + VMM_FLAG_COW, inherited from a COW fork and not yet
         * written by userspace) faults in ring 0 because CR0.WP=1. Without
         * handling it here the fault would fall to the exception-table fixup
         * below, which SHORT-COPIES (leaves rcx bytes uncopied) and never breaks
         * the COW share — silently corrupting the buffer. Concretely: a block
         * read()/copy_to_user into a just-COW-forked process's still-shared
         * buffer writes only the bytes up to the first COW page, leaving the
         * rest stale → the installer's read-back/verify sees a mismatch (the
         * COW-only, eager-clean failure this fixes). Break the share and retry
         * the faulting instruction, exactly as the ring-3 COW path does. Only a
         * genuine COW page is handled (cr == 0); a real unmapped/RO user buffer
         * or OOM falls through to the exception-table fixup below unchanged. */
        if (s->cs == ARCH_KERNEL_CS && s->vector == 14 &&
            (s->error_code & 1) && (s->error_code & 2) &&
            sched_current() && sched_current()->is_user) {
            uint64_t cr2;
            __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
            aegis_process_t *cp = (aegis_process_t *)sched_current();
            if (cr2 <= USER_ADDR_MAX &&
                vmm_cow_fault_handle(cp->pml4_phys, cr2) == 0)
                return;   /* COW broken → retry the faulting kernel write */
        }
        /* Demand paging for KERNEL-mode accesses (copy_*_user et al.): a
         * NOT-PRESENT (#PF err.P==0) fault on a lazy anonymous user page.
         * Without this, a kernel copy into/out of a not-yet-faulted lazy buffer
         * would fall to the exception-table fixup below and short-copy/EFAULT —
         * forcing every uaccess pre-check to eagerly walk+populate the whole
         * range up front (O(pages) windowed page-table walks, which spun the
         * kernel for minutes under a self-hosting cc1's large buffers). Populate
         * and retry, mirroring the ring-3 lazy path above. Only lazy user pages
         * are handled (mm_populate_fault==0); a genuine unmapped address returns
         * non-zero and falls through to the exception-table fixup unchanged. */
        if (s->cs == ARCH_KERNEL_CS && s->vector == 14 &&
            !(s->error_code & 1) &&
            sched_current() && sched_current()->is_user) {
            uint64_t cr2;
            __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
            if (cr2 <= USER_ADDR_MAX &&
                mm_populate_fault((aegis_process_t *)sched_current(), cr2) == 0) {
                /* Flush any stale not-present TLB entry for this VA before
                 * retrying the rep-movsb: mm_populate_fault's already-present
                 * fast path (a sibling CPU mapped it) returns 0 without an
                 * invlpg, so without this the faulting instruction could re-read
                 * a stale TLB and fault on the same page forever. */
                arch_vmm_invlpg(cr2 & ~0xFFFULL);
                return;   /* lazy page populated → retry the faulting access */
            }
        }
        /* Fault-tolerant uaccess: a kernel-mode #PF (14) or #GP (13) inside a
         * copy_*_user rep-movsb whose RIP is registered in the exception table
         * is recovered by redirecting to its fixup, NOT panicking. This catches
         * the case where a user buffer was unmapped (sibling munmap) while the
         * kernel copied to/from it — the whole validate-then-block-then-copy
         * TOCTOU class. Only a faulting RIP that uaccess explicitly registered
         * matches, so a genuine kernel bug elsewhere still panics normally. */
        if (s->cs == ARCH_KERNEL_CS &&
            (s->vector == 14 || s->vector == 13)) {
            uint64_t fixup = ex_table_lookup(s->rip);
            if (fixup) {
                s->rip = fixup;
                return;
            }
        }
        /* CPU exception: print and halt */
        printk("[PANIC] cpu%u exception %lu at RIP=0x%lx error=0x%lx CS=0x%lx\n",
               (unsigned)lapic_id(), s->vector, s->rip, s->error_code, s->cs);
        /* For #PF: print CR2 and key registers */
        if (s->vector == 14) {
            uint64_t cr2, fsbase;
            __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
            /* IA32_FS_BASE MSR = 0xC0000100 */
            uint32_t fs_lo, fs_hi;
            __asm__ volatile("rdmsr" : "=a"(fs_lo), "=d"(fs_hi) : "c"(0xC0000100U));
            fsbase = ((uint64_t)fs_hi << 32) | fs_lo;
            printk("[PANIC] #PF CR2=0x%lx rax=0x%lx rbx=0x%lx\n",
                   cr2, s->rax, s->rbx);
            printk("[PANIC] #PF r12=0x%lx r13=0x%lx r14=0x%lx\n",
                   s->r12, s->r13, s->r14);
            printk("[PANIC] #PF rsp=0x%lx ss=0x%lx fs_base=0x%lx\n",
                   s->rsp, s->ss, fsbase);
        }
        /* For #GP at iretq: the original iretq frame overlaps cpu_state_t.rsp/ss.
         * Print all 5 slots of the frame so we can see what iretq was trying to load. */
        if (s->vector == 13) {
            uint64_t *f = (uint64_t *)&s->rsp;
            printk("[PANIC] #GP iretq frame: RIP=%lx CS=%lx FL=%lx RSP=%lx SS=%lx\n",
                   f[0], f[1], f[2], f[3], f[4]);
        }
        /* Print kernel backtrace for kernel-mode faults.
         * For ring-3 faults (CS=ARCH_USER_CS) rbp is a user-space pointer — skip. */
        if (s->cs == ARCH_KERNEL_CS)
            panic_backtrace(s->rbp);
        {
            uint64_t cr2_val = 0;
            if (s->vector == 14)
                __asm__ volatile("mov %%cr2, %0" : "=r"(cr2_val));
            panic_bluescreen(s->vector, s->rip, s->error_code,
                             cr2_val, s->rsp, s->rbp, s->rax, s->rbx);
        }
    } else if (s->vector >= 0xF0 && s->vector <= 0xFD) {
        /* Remapped PIC vector — stale interrupt from 8259A during IOAPIC
         * transition.  The PIC is already masked; just drop the interrupt.
         * No EOI needed — PIC is dead, LAPIC didn't generate this. */
        return;
    } else if (s->vector == 0xFE) {
        /* TLB shootdown IPI — handler does its own LAPIC EOI. */
        tlb_shootdown_handler();
        return;
    } else if (s->vector == 0xFF) {
        /* LAPIC spurious interrupt — per Intel spec, do NOT send EOI. */
        return;
    } else if (s->vector == 0x30) {
        /* LAPIC timer interrupt — send EOI before handler because
         * sched_tick may ctx_switch away, leaving the EOI unsent.
         * Edge-triggered periodic LAPIC timer: EOI-first is safe. */
        lapic_eoi();
        lapic_timer_handler();
    } else if (s->vector == 0x40) {
        /* virtio-net MSI-X RX interrupt — message-signalled, delivered straight
         * to the LAPIC (edge-triggered), so EOI before servicing. The handler
         * drains the RX ring with IF=0; it must not block. */
        lapic_eoi();
        virtio_net_irq();
    } else if (s->vector >= 0x20 && s->vector < 0x30) {
        /* Hardware IRQ: send EOI BEFORE the handler.
         * pit_handler calls sched_tick which calls ctx_switch — if we
         * switch away before EOI, the outgoing task carries the EOI
         * obligation and IRQ0 goes dark until that task is rescheduled. */
        uint8_t irq = (uint8_t)(s->vector - 0x20);

        if (lapic_active()) {
            lapic_eoi();
        } else {
            /* Guard against spurious IRQ7 (PIC1) and IRQ15 (PIC2 cascade).
             * Per 8259A spec: do NOT send EOI for spurious interrupts — doing
             * so clears the ISR bit of a real in-service interrupt.
             * For spurious IRQ15 (PIC2), PIC1 still received the cascade
             * interrupt on IRQ2, so we must EOI PIC1 only. */
            if ((irq == 7 || irq == 15) && !pic_irq_is_real(irq)) {
                if (irq == 15)
                    outb(0x20, 0x20);   /* spurious IRQ15: EOI to PIC1 only */
                /* No EOI to PIC2 for spurious IRQ15; no EOI at all for spurious IRQ7. */
            } else {
                pic_send_eoi(irq);
            }
        }

        if      (s->vector == 0x20) { pit_handler(); }
        else if (s->vector == 0x21) { kbd_handler(); }
        else if (s->vector == 0x24) { serial_rx_handler(); }
        else if (s->vector == 0x2C) { ps2_mouse_handler(); }
        else if (irq == acpi_get_sci_irq() && irq != 0) { acpi_sci_handler(); }
    }

    /* Sanity-check the iretq frame for ring-3 interrupts.
     * For a ring-3 interrupt (cs=ARCH_USER_CS), cpu_state_t.rsp=user_rsp and
     * cpu_state_t.ss must point to the user data descriptor (GDT index 3).
     *
     * AMD CPUs in 64-bit mode may strip SS RPL bits after loading, pushing
     * 0x18 (RPL=0) instead of 0x1B (RPL=3) on interrupt entry — both are
     * valid since SS is unused for addressing in 64-bit long mode.
     * Accept any RPL variant of the user data selector: (ss & ~3) == 0x18.
     * Reject kernel selectors (ARCH_KERNEL_CS, ARCH_KERNEL_DS) or user code (0x20). */
    if (s->cs == ARCH_USER_CS && (s->ss & ~(uint64_t)3) != (ARCH_USER_DS & ~(uint64_t)3)) {
        printk("[PANIC] corrupt ring-3 iretq frame vec=%lu rip=0x%lx rsp=0x%lx ss=0x%lx\n",
               s->vector, s->rip, s->rsp, s->ss);
        panic_bluescreen(s->vector, s->rip, s->ss,
                         0, s->rsp, s->rbp, s->rax, s->rbx);
    }

    /* Normalize SS RPL=3 for iretq back to ring-3.
     * AMD CPUs in 64-bit mode strip SS RPL bits on ring-3 interrupt entry,
     * pushing SS=0x18 (RPL=0) instead of SS=ARCH_USER_DS (RPL=3).  iretq to
     * ring-3 (CPL=3) requires SS.RPL == CPL=3; without normalization the
     * iretq faults #GP(SS) on AMD.  Force RPL=3 unconditionally on the return
     * path — harmless on Intel (which already pushes RPL=3), required on AMD. */
    if (s->cs == ARCH_USER_CS)
        s->ss |= 3;
}
