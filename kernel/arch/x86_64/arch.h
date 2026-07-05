#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>   /* uint32_t etc. from GCC freestanding headers */

/*
 * arch.h — Architecture-neutral boundary for kernel/core/.
 *
 * Every architecture provides its own arch.h with this same interface.
 * The build system selects the right one via -Ikernel/arch/<target>.
 * kernel/core/ includes only "arch.h" — never any arch-specific header by name.
 *
 * Design debt (Phase 2): the output function declarations below
 * (serial_write_string, vga_write_string, vga_available) are x86-specific
 * in semantics and should migrate to a kernel/core/output.h abstraction
 * when an ARM64 port begins.
 */

/* Initialize all arch-specific subsystems (serial, VGA).
 * Must be the first call in kernel_main. */
void arch_init(void);

/* arch_pat_init — program IA32_PAT MSR to set PA1 = Write-Combining.
 * Must be called before vmm_init() so that any subsequent vmm_map_page
 * calls using VMM_FLAG_WC produce the correct caching type.
 * No-op if CPU does not advertise PAT support (CPUID bit). */
void arch_pat_init(void);

/* Signal QEMU isa-debug-exit device. QEMU exits with code (value << 1) | 1.
 * Writing 0x01 → QEMU exit code 3. No-op if device is absent. */
void arch_debug_exit(unsigned char value);

/*
 * Output primitives used by printk (implemented in serial.c / vga.c).
 * Declared here so kernel/core/printk.c can reach them via arch.h
 * without including serial.h or vga.h directly.
 */
extern int vga_available;              /* set to 1 by vga_init() */
void serial_write_string(const char *s);
void vga_write_string(const char *s);

/* -------------------------------------------------------------------------
 * Arch-specific port I/O primitives
 * Used by serial, PIC, PIT, VGA hardware cursor — not for use in kernel/core/.
 * ------------------------------------------------------------------------- */
static inline void
outb(uint16_t port, uint8_t val)
{
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port) : "memory");
}

static inline uint8_t
inb(uint16_t port)
{
    uint8_t val;
    __asm__ volatile ("inb %1, %0" : "=a"(val) : "Nd"(port) : "memory");
    return val;
}

static inline void
outw(uint16_t port, uint16_t val)
{
    __asm__ volatile ("outw %0, %1" : : "a"(val), "Nd"(port) : "memory");
}

static inline uint16_t
inw(uint16_t port)
{
    uint16_t val;
    __asm__ volatile ("inw %1, %0" : "=a"(val) : "Nd"(port) : "memory");
    return val;
}

/* fw_cfg (kernel/arch/x86_64/fw_cfg.c) — QEMU/Proxmox firmware-config channel.
 * fw_cfg_init() probes the signature and applies any host-injected config
 * (e.g. opt/aegis.hostname). fw_cfg_read_file() reads a named blob; returns
 * bytes read (>=0) or -1 if absent / fw_cfg not present. */
void fw_cfg_init(void);
int  fw_cfg_read_file(const char *name, void *buf, uint32_t maxlen);

/* -------------------------------------------------------------------------
 * Physical memory interface (Phase 2+)
 * ------------------------------------------------------------------------- */

/* A contiguous physical memory region. Used for both usable RAM and
 * arch-reserved ranges (BIOS holes, MMIO, ROM regions, etc.). */
typedef struct {
    uint64_t base;
    uint64_t len;
} aegis_mem_region_t;

/* Parse the arch-specific firmware memory map (multiboot2 on x86).
 * Must be called before any pmm_* function. */
void arch_mm_init(void *mb_info);

/* Usable RAM regions reported by firmware (multiboot2 type=1 entries).
 * Valid after arch_mm_init(). */
uint32_t                   arch_mm_region_count(void);
const aegis_mem_region_t  *arch_mm_get_regions(void);

/* Arch-reserved physical ranges that pmm_init() must never hand out
 * (BIOS data areas, VGA framebuffer hole, ISA ROMs, MMIO windows, etc.).
 * pmm_init() calls this instead of hard-coding platform addresses, so
 * kernel/mm/pmm.c contains no x86-specific knowledge.
 * Valid after arch_mm_init(). */
uint32_t                   arch_mm_reserved_region_count(void);
const aegis_mem_region_t  *arch_mm_get_reserved_regions(void);

/* ACPI RSDP physical address — saved during multiboot2 tag scan.
 * Returns 0 if no ACPI tag was found (e.g. -machine pc with SeaBIOS). */
uint64_t arch_get_rsdp_phys(void);

/*
 * Framebuffer info extracted from the multiboot2 type-8 tag.
 * Populated by arch_mm_init(); read by fb_init() after VMM+KVA are up.
 * addr == 0 if no framebuffer tag was present.
 */
typedef struct {
    uint64_t addr;    /* physical base address of linear framebuffer */
    uint32_t pitch;   /* bytes per scan line */
    uint32_t width;   /* pixels per row */
    uint32_t height;  /* rows */
    uint8_t  bpp;     /* bits per pixel (32 for our use case) */
    uint8_t  type;    /* 1 = RGB/BGR linear, 2 = EGA text */
} arch_fb_info_t;

/* arch_get_fb_info — fill *out with the framebuffer info saved during
 * arch_mm_init().  Returns 1 if a usable (type==1, bpp==32) framebuffer
 * was found, 0 otherwise. */
int arch_get_fb_info(arch_fb_info_t *out);

/* arch_get_module — return physical address and size of the first multiboot2
 * module (rootfs image loaded by GRUB). Returns 1 if a module was found,
 * 0 if no module present (diskless boot). */
int arch_get_module(uint64_t *phys_out, uint64_t *size_out);

/* arch_get_module2 — return physical address and size of the second multiboot2
 * module (ESP image for installer). Returns 1 if found, 0 if not present. */
int arch_get_module2(uint64_t *phys_out, uint64_t *size_out);

/* arch_get_cmdline — return kernel command line from multiboot2 tag.
 * Returns pointer to static buffer (empty string if no cmdline tag). */
const char *arch_get_cmdline(void);

/* Limine boot protocol path (kernel/core/limine.c → kernel_main_limine):
 * adopt the ingested bootinfo into the same statics the mb2 parser fills. */
struct aegis_bootinfo;
void arch_mm_ingest(const struct aegis_bootinfo *bi);

/* Physical slide of the kernel image: PA(sym) = sym - KERN_VMA + slide.
 * 0 on the multiboot2 path; from the Limine executable-address response
 * otherwise. */
uint64_t arch_kern_phys_slide(void);

/* Early phys→virt offset for pre-vmm_init physical access:
 * VA = PA + arch_early_pv_off(). 0 on the multiboot2 path (identity map);
 * the HHDM offset on the Limine path. Invalid after vmm_init loads the
 * kernel's own tables (use the identity map / window from then on). */
uint64_t arch_early_pv_off(void);

/* -------------------------------------------------------------------------
 * x86-64 GDT segment selectors
 * ------------------------------------------------------------------------- */
#define ARCH_KERNEL_CS  0x08   /* GDT index 1, RPL=0 */
#define ARCH_KERNEL_DS  0x10   /* GDT index 2, RPL=0 */
#define ARCH_USER_DS    0x1B   /* GDT index 3, RPL=3 */
#define ARCH_USER_CS    0x23   /* GDT index 4, RPL=3 */

/* Highest canonical user-space virtual address. Used by syscall handlers
 * to validate user pointers. Architecture-dependent: x86-64 uses 47-bit
 * canonical addresses; ARM64 48-bit VA uses 0x0000FFFFFFFFFFFF. */
#define USER_ADDR_MAX 0x00007FFFFFFFFFFFUL

/* Physical base address of the kernel image (arch-defined load address).
 * pmm_init() uses this to reserve the kernel image pages. */
#define ARCH_KERNEL_PHYS_BASE 0x100000UL

/* Virtual base address of the kernel in the higher half. */
#define ARCH_KERNEL_VIRT_BASE 0xFFFFFFFF80000000UL

/* Physmap (direct map): all usable physical RAM is mapped 1:1 at this base by
 * vmm_init, so any frame is reachable at (phys + ARCH_PHYSMAP_BASE) without a
 * per-access page-table window. PML4[256], the canonical higher-half start;
 * one PML4 entry spans 512GB. Distinct from the kernel image map (PML4[511])
 * and the torn-down boot identity map (PML4[0]). */
#define ARCH_PHYSMAP_BASE 0xFFFF800000000000UL

/* -------------------------------------------------------------------------
 * Virtual memory interface (Phase 3+)
 * ------------------------------------------------------------------------- */

/* Load a physical PML4 page table address into CR3, replacing the current
 * address space. Called by vmm_init() after building the higher-half map. */
void arch_vmm_load_pml4(uint64_t phys);

/* Invalidate the TLB entry for a single virtual address.
 * Must be called after any PTE modification to ensure coherency. */
void arch_vmm_invlpg(uint64_t virt);

/* -------------------------------------------------------------------------
 * Context switch (Phase 4+)
 * ------------------------------------------------------------------------- */

/* Forward declaration for the scheduler's TCB type.
 * sched.h defines the full struct; arch.h only needs the pointer. */
struct aegis_task_t;

/* Save outgoing task's callee-saved registers and stack pointer; restore incoming task's.
 * Implemented in kernel/arch/x86_64/ctx_switch.asm.
 *   outgoing — pointer to the current task's aegis_task_t (sp field saved here)
 *   incoming — pointer to the next task's aegis_task_t   (sp field loaded from here)
 * Never returns to the caller in the outgoing task until ctx_switch is called
 * again with that task as the incoming argument. */
void ctx_switch(struct aegis_task_t *outgoing, struct aegis_task_t *incoming);

/* Number of callee-saved register slots pushed by ctx_switch.
 * x86-64: rbx, rbp, r12-r15 (6) + return address (1) = 7 slots.
 * sched_spawn must build a matching frame. */
#define ARCH_CTX_SLOTS 7

/* -------------------------------------------------------------------------
 * Phase 4: Interrupt infrastructure
 * ------------------------------------------------------------------------- */

/* IDT: install 48 interrupt gate descriptors and load with lidt. */
void idt_init(void);

/* PIC: remap 8259A dual PIC so IRQ0-15 land at vectors 0x20-0x2F.
 * Masks all IRQs after init; drivers call pic_unmask(irq) when ready. */
void pic_init(void);

/* PIT: program channel 0 at 100 Hz and unmask IRQ0. */
void pit_init(void);

/* Returns the current PIT tick count (incremented 100x/second).
 * Use this instead of accessing the pit.c-internal counter directly. */
uint64_t arch_get_ticks(void);

/* arch_tsc_calibrate — engage TSC-derived timekeeping using a measured
 * cycles-per-10ms window (from lapic_timer_init).  No-op without invariant TSC. */
void arch_tsc_calibrate(uint64_t cycles_per_10ms);

/* arch_tsc_hz — calibrated TSC frequency in cycles/sec (0 if uncalibrated). */
uint64_t arch_tsc_hz(void);

/* arch_clock_gettime — returns {seconds, nanoseconds} since Unix epoch.
 * seconds = epoch_offset + ticks/100, nanoseconds = (ticks%100)*10000000.
 * epoch_offset is set by arch_clock_settime (NTP daemon). */
void arch_clock_gettime(uint64_t *sec, uint64_t *nsec);

/* arch_clock_settime — set wall clock epoch offset from current ticks.
 * Called by sys_clock_settime after NTP sync. */
void arch_clock_settime(uint64_t sec);

/* Request a clean shutdown. Sets a flag checked by pit_handler on the next
 * timer tick; actual arch_debug_exit is deferred to ISR context (IF=0) to
 * prevent the QEMU async isa-debug-exit race where task code re-runs after
 * the port write. */
void arch_request_shutdown(void);

/* -------------------------------------------------------------------------
 * Phase 4: Keyboard
 * ------------------------------------------------------------------------- */

/* Initialize PS/2 keyboard and unmask IRQ1. */
void kbd_init(void);

/* Blocking read — spins until a keypress is available. */
char kbd_read(void);

/* Non-blocking read. Returns 1 if a char was available and written to *out. */
int kbd_poll(char *out);

/* -------------------------------------------------------------------------
 * Phase 5: Ring-3 support
 * ------------------------------------------------------------------------- */

/* Build a 7-entry runtime GDT (null, kernel code/data, user data/code, TSS),
 * install with lgdt, reload segment registers, load TSS with ltr.
 * Prints [GDT] OK. */
void arch_gdt_init(void);

/* Set TSS.iomap_base = 104 (disables I/O permission bitmap).
 * Prints [TSS] OK. */
void arch_tss_init(void);

/* Update TSS.RSP0 and percpu.kernel_stack to rsp0.
 * Called by scheduler before every ctx_switch so:
 *   — CPU loads correct kernel stack top on ring-3 interrupts (via TSS.RSP0)
 *   — syscall_entry.asm loads correct kernel stack (via gs:24 percpu.kernel_stack)
 * Both values must always be identical. */
void arch_set_kernel_stack(uint64_t rsp0);

/* Store the master (kernel) PML4 physical address in g_master_pml4.
 * Must be called once after vmm_init(). isr.asm and syscall_entry.asm
 * load g_master_pml4 into CR3 at the start of every interrupt/syscall
 * so that kernel code always runs with the master PML4 (where TCBs and
 * kernel stacks are identity-mapped). */
void arch_set_master_pml4(uint64_t pml4_phys);

/* Program IA32_EFER (SCE), IA32_STAR, IA32_LSTAR, IA32_SFMASK.
 * Prints [SYSCALL] OK. */
void arch_syscall_init(void);

/* -------------------------------------------------------------------------
 * Phase 8: SMAP (Supervisor Mode Access Prevention)
 * ------------------------------------------------------------------------- */

/* arch_smap_init — detect SMAP via CPUID and enable CR4.SMAP if supported.
 * Prints [SMAP] OK: supervisor access prevention active, or
 * [SMAP] WARN: not supported by CPU. Must be called after arch_syscall_init(). */
void arch_smap_init(void);

/* arch_smep_init — detect SMEP via CPUID and enable CR4.SMEP if supported.
 * Call after arch_smap_init. Prints [SMEP] OK or [SMEP] WARN. */
void arch_smep_init(void);

/* arch_sse_init — enable SSE/SSE2 for user-mode execution.
 * Clears CR0.EM, sets CR0.MP, sets CR4.OSFXSR + CR4.OSXMMEXCPT.
 * Must be called before sched_start() so that user processes can execute
 * SSE instructions without triggering #UD (exception 6).
 * The kernel itself is compiled -mno-sse and never touches XMM registers. */
void arch_sse_init(void);

/* Set to 1 by arch_smap_init() after successfully enabling CR4.SMAP.
 * Checked by arch_stac/arch_clac to avoid #UD on CPUs without SMAP. */
extern int arch_smap_enabled;

/* arch_stac — set RFLAGS.AC, temporarily permitting ring-0 access to
 * user-mode pages under SMAP. Bracket ONLY the single instruction that
 * loads from a user address; always pair with arch_clac() immediately after.
 * Never call any function between arch_stac() and arch_clac().
 * The "memory" clobber prevents the compiler from hoisting user-memory
 * loads before stac. No-op if SMAP is not enabled (guards against #UD). */
static inline void arch_stac(void) { if (arch_smap_enabled) __asm__ volatile("stac" ::: "memory"); }

/* arch_clac — clear RFLAGS.AC, re-enabling SMAP protection.
 * Must be called after every arch_stac(). The "memory" clobber prevents
 * the compiler from sinking user-memory loads past clac.
 * No-op if SMAP is not enabled (guards against #UD). */
static inline void arch_clac(void) { if (arch_smap_enabled) __asm__ volatile("clac" ::: "memory"); }

/* __uaccess_copy — fault-tolerant user<->kernel byte copy (arch_smap.c). The
 * user-touching instruction is in the __ex_table, so a fault (e.g. the buffer
 * was unmapped mid-syscall) is caught by isr_dispatch and redirected to a fixup
 * instead of panicking. Handles stac/clac internally. Returns bytes NOT copied
 * (0 = success). Backs copy_from_user/copy_to_user. */
uint64_t __uaccess_copy(void *dst, const void *src, uint64_t len);

/* ex_table_lookup — map a faulting kernel RIP to its registered fixup address
 * (0 if not in the table). Used by the #PF/#GP path in isr_dispatch. */
uint64_t ex_table_lookup(uint64_t rip);

/* -------------------------------------------------------------------------
 * Phase 14: FS segment base (TLS)
 * ------------------------------------------------------------------------- */

/* arch_set_fs_base — write addr to IA32_FS_BASE MSR (0xC0000100).
 * Used by sys_arch_prctl(ARCH_SET_FS) to configure musl's TLS pointer.
 * The SYSCALL instruction does not save/restore FS.base, so the value
 * set here persists across all subsequent syscalls for the lifetime of
 * the process. When a second user process is introduced, ctx_switch must
 * save proc->fs_base on outgoing and call arch_set_fs_base(proc->fs_base)
 * on incoming before returning to user space. */
static inline void
arch_set_fs_base(uint64_t addr)
{
    uint32_t lo = (uint32_t)addr;
    uint32_t hi = (uint32_t)(addr >> 32);
    __asm__ volatile ("wrmsr" : : "c"(0xC0000100U), "a"(lo), "d"(hi));
}

/* -------------------------------------------------------------------------
 * Phase 38b: GS segment base (per-CPU data)
 * ------------------------------------------------------------------------- */

/* arch_set_gs_base — write addr to IA32_GS_BASE MSR (0xC0000101).
 * Sets the active GS segment base. In kernel mode, GS.base points to the
 * per-CPU percpu_t structure. */
static inline void
arch_set_gs_base(uint64_t addr)
{
    uint32_t lo = (uint32_t)addr;
    uint32_t hi = (uint32_t)(addr >> 32);
    __asm__ volatile("wrmsr" : : "c"(0xC0000101U), "a"(lo), "d"(hi));
}

/* arch_write_kernel_gs_base — write addr to IA32_KERNEL_GS_BASE MSR (0xC0000102).
 * This value is swapped into GS.base by the SWAPGS instruction at syscall/
 * interrupt entry from ring 3. */
static inline void
arch_write_kernel_gs_base(uint64_t addr)
{
    uint32_t lo = (uint32_t)addr;
    uint32_t hi = (uint32_t)(addr >> 32);
    __asm__ volatile("wrmsr" : : "c"(0xC0000102U), "a"(lo), "d"(hi));
}

/* -------------------------------------------------------------------------
 * Arch-portable helpers — used by kernel/core/, kernel/drivers/, kernel/net/
 * Each architecture provides its own implementation in arch.h.
 * ------------------------------------------------------------------------- */

/* arch_wmb — write memory barrier. Ensures all preceding stores are globally
 * visible before any subsequent MMIO writes. Used by DMA-capable drivers
 * (virtio, NVMe, xHCI) before doorbell writes. */
static inline void arch_wmb(void) { __asm__ volatile("sfence" ::: "memory"); }

/* arch_enable_irq / arch_disable_irq — unmask/mask hardware interrupts. */
static inline void arch_enable_irq(void)  { __asm__ volatile("sti" ::: "memory"); }
static inline void arch_disable_irq(void) { __asm__ volatile("cli" ::: "memory"); }

/* Save interrupt flags and disable interrupts.
 * Returns the previous RFLAGS value (for restoring later). */
static inline unsigned long
arch_irq_save(void)
{
    unsigned long flags;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(flags) : : "memory");
    return flags;
}

/* Restore interrupt flags to a previously saved state. */
static inline void
arch_irq_restore(unsigned long flags)
{
    __asm__ volatile("push %0; popfq" : : "r"(flags) : "memory");
}

/* arch_get_cycles — read the CPU timestamp counter (RDTSC).
 * Returns monotonically increasing cycle count. Used by the CSPRNG
 * for entropy and by interrupt timing. */
static inline uint64_t
arch_get_cycles(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* Hint to the CPU that we are in a spin loop. */
static inline void
arch_pause(void)
{
    __asm__ volatile("pause");
}

/* arch_halt — halt CPU until next interrupt. Caller must ensure interrupts
 * are enabled (arch_enable_irq) before calling, or CPU will hang forever. */
static inline void arch_halt(void) { __asm__ volatile("hlt" ::: "memory"); }

/* arch_wait_for_irq — enable interrupts, halt until next interrupt fires,
 * then disable interrupts again. Atomic: no window for nested interrupts
 * between enable and halt on x86 (STI shadow covers HLT). */
static inline void arch_wait_for_irq(void) {
    __asm__ volatile("sti; hlt; cli" ::: "memory");
}

/* arch_early_key_held — poll PS/2 keyboard for any held key during early boot.
 * No initialization required — PS/2 controller is active from firmware.
 * Returns non-zero if any key is being held, 0 otherwise.
 * Used for debug boot mode: hold any key during POST to skip boot splash
 * and show all kernel output on the framebuffer. */
static inline int arch_early_key_held(void)
{
    uint8_t status;
    __asm__ volatile("inb $0x64, %0" : "=a"(status));
    if (status & 1) {
        uint8_t scancode;
        __asm__ volatile("inb $0x60, %0" : "=a"(scancode));
        (void)scancode;
        return 1;
    }
    return 0;
}

#endif
