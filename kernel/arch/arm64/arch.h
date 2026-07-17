#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>

/*
 * arch.h — ARM64 (aarch64) architecture boundary.
 *
 * Fresh port (2026-07): boots exclusively via the Limine boot protocol
 * (EL1, MMU on, kernel higher-half, 4K granule — see kernel/core/limine.c
 * and kernel/arch/arm64/entry.S). Same interface as the x86-64 arch.h;
 * the build selects this file via -Ikernel/arch/arm64.
 *
 * Reference platform: QEMU virt (PL011 UART, GICv3, generic timer).
 */

/* Initialize arch early subsystems. On arm64 this is a no-op placeholder —
 * the UART needs the kernel's own page tables (vmm_init) before it can be
 * mapped, so serial_init runs later in the arm64 kernel_main. */
void arch_init(void);

/* Output primitives used by printk. vga_* are x86 text mode — absent here. */
extern int vga_available;              /* always 0 on arm64 */
void serial_write_string(const char *s);
void vga_write_string(const char *s);

void serial_init(void);
void serial_putc(char c);
void serial_set_base(volatile void *va);

/* GICv3 (gic.c) — interrupt enables for PPIs (per-CPU) and SPIs (shared). */
void gic_enable_ppi(uint32_t intid);
void gic_enable_spi(uint32_t intid);

/* arch_debug_exit / shutdown — PSCI SYSTEM_OFF (HVC conduit on QEMU virt). */
void arch_debug_exit(unsigned char value);
void arch_request_shutdown(void);

/* -------------------------------------------------------------------------
 * Physical memory interface
 * ------------------------------------------------------------------------- */

typedef struct {
    uint64_t base;
    uint64_t len;
} aegis_mem_region_t;

/* arm64 boots only via Limine: arch_mm_ingest() (called from
 * kernel_main_limine) fills the region/cmdline/module/fb state; a NULL
 * arch_mm_init is kept for interface parity. */
void arch_mm_init(void *info);

uint32_t                   arch_mm_region_count(void);
const aegis_mem_region_t  *arch_mm_get_regions(void);
uint32_t                   arch_mm_reserved_region_count(void);
const aegis_mem_region_t  *arch_mm_get_reserved_regions(void);

uint64_t arch_get_rsdp_phys(void);

typedef struct {
    uint64_t addr;
    uint32_t pitch;
    uint32_t width;
    uint32_t height;
    uint8_t  bpp;
    uint8_t  type;
} arch_fb_info_t;

int arch_get_fb_info(arch_fb_info_t *out);
int arch_get_module(uint64_t *phys_out, uint64_t *size_out);
int arch_get_module2(uint64_t *phys_out, uint64_t *size_out);
const char *arch_get_cmdline(void);

struct aegis_bootinfo;
void arch_mm_ingest(const struct aegis_bootinfo *bi);
uint64_t arch_kern_phys_slide(void);
uint64_t arch_early_pv_off(void);
uint64_t arch_get_dtb_phys(void);

/* Native (non-Limine) boot path -- kernel/arch/arm64/native/native_entry.c.
 * arch_mm_init_native() plays the same role arch_mm_ingest() does for
 * Limine (sets dtb_phys/slide/pv_off/cmdline), but there is no
 * aegis_bootinfo_t: no memory map is handed to us at entry, no HHDM
 * exists (the native path runs off boot_probe.S's own identity map).
 * arch_mm_populate_regions_from_dtb() fills regions[] from the DTB's
 * memory nodes afterward -- must be called after fdt_init() has
 * captured the tree, and is a no-op if Limine already gave us regions. */
void arch_mm_init_native(uint64_t dtb_phys);
void arch_mm_populate_regions_from_dtb(void);

/* Platform UART physical base, for code that needs it after vmm_init has
 * replaced the early identity map (vmm.c's DMAP device window, main.c's
 * post-vmm_init serial_set_base call). Defaults to QEMU virt's PL011
 * (0x09000000); arch_mm_init_native() overrides it for real Pi 5
 * hardware (0x107D001000 -- confirmed this address on real hardware
 * during the native-boot bring-up, see rpi5-port-research memory). */
uint64_t arch_mm_get_uart_phys(void);

/* Highest canonical user-space virtual address (48-bit VA, TTBR0 half). */
#define USER_ADDR_MAX 0x0000FFFFFFFFFFFFUL

/* Linked base of the kernel image. PHYS_BASE is the link-time offset of the
 * first section (the image's physical placement comes from Limine +
 * arch_kern_phys_slide). */
#define ARCH_KERNEL_PHYS_BASE 0x200000UL
#define ARCH_KERNEL_VIRT_BASE 0xFFFFFFFF80000000UL

/* Kernel direct map of physical RAM (built by vmm_init, TTBR1):
 * VA = ARCH_DMAP_BASE + PA for every usable/module/kernel RAM byte, plus
 * the QEMU-virt device window mapped Device-nGnRE. This replaces both the
 * x86 identity map and the mapped-window allocator. */
#define ARCH_DMAP_BASE 0xFFFF900000000000UL

static inline void *arch_dmap(uint64_t phys)
{
    return (void *)(ARCH_DMAP_BASE + phys);
}

/* -------------------------------------------------------------------------
 * Virtual memory interface
 * ------------------------------------------------------------------------- */

/* Load a user address space: TTBR0_EL1 + full TLB invalidate.
 * (Kernel mappings live in TTBR1 and are never switched.) */
void arch_vmm_load_pml4(uint64_t phys);

/* Invalidate the TLB entry for a single VA.
 * ponytail: full EL1&0 TLB flush, not a per-VA tlbi. The by-VA form
 * (tlbi vaae1is, VA>>12) did not reliably evict the stale entry on the
 * QEMU-virt cortex-a72 target — a COW fault would make the PTE writable
 * yet the retry kept taking a permission fault, looping forever. A full
 * flush is unconditionally correct; per-VA invalidation is a throughput
 * optimization to revisit. The `is` (inner-shareable) variant broadcasts
 * to every core in hardware, so it is SMP-correct with no IPI — a COW/
 * unmap on one core evicts the stale entry on sibling CLONE_VM threads
 * running on other cores. */
static inline void
arch_vmm_invlpg(uint64_t virt)
{
    (void)virt;
    __asm__ volatile(
        "dsb ishst\n\t"
        "tlbi vmalle1is\n\t"
        "dsb ish\n\t"
        "isb"
        : : : "memory");
}

/* -------------------------------------------------------------------------
 * Context switch
 * ------------------------------------------------------------------------- */

struct aegis_task_t;
void ctx_switch(struct aegis_task_t *outgoing, struct aegis_task_t *incoming);

/* ctx_switch.S pushes 6 pairs (x19..x30) = 12 slots. */
#define ARCH_CTX_SLOTS 12

/* -------------------------------------------------------------------------
 * Interrupts / exceptions
 * ------------------------------------------------------------------------- */

/* Install VBAR_EL1 + GICv3 + generic timer (arm64 main.c calls these). */
void idt_init(void);          /* installs the EL1 vector table */
void gic_init(void);
void timer_init(void);

uint64_t arch_get_ticks(void);
void arch_tsc_calibrate(uint64_t cycles_per_10ms);
uint64_t arch_tsc_hz(void);
uint64_t arch_clock_mono_ns(void);   /* ns since counter start (CNTVCT-derived) */
void arch_clock_gettime(uint64_t *sec, uint64_t *nsec);
void arch_clock_settime(uint64_t sec);

/* PL011-RX-backed console input (kbd-equivalent). */
void kbd_init(void);
char kbd_read(void);
int  kbd_poll(char *out);

/* -------------------------------------------------------------------------
 * User mode support
 * ------------------------------------------------------------------------- */

/* Update the per-CPU kernel stack top. On arm64 SP_EL1 self-manages (the
 * eret path fully unwinds the exception frame), so this only records the
 * value in percpu for diagnostics. */
void arch_set_kernel_stack(uint64_t sp0);

/* Record the master (kernel) translation table. On arm64 the kernel half
 * is TTBR1 (never switched); the "master pml4" is the empty user table
 * loaded while no user task runs. */
void arch_set_master_pml4(uint64_t pml4_phys);

/* proc_enter_user — trampoline (proc_enter.S): pops
 * [spsr][elr][user_sp][ttbr0] from the kernel stack, loads them and ERETs
 * to EL0. Referenced by proc.c / sys_process.c frame builders. */
void proc_enter_user(void);

/* TLS base (TPIDR_EL0, the aarch64 IA32_FS_BASE analogue): a NO-OP on arm64.
 *
 * TPIDR_EL0 is owned solely by ctx_switch.S, which snapshots the LIVE outgoing
 * register into task.fs_base and restores the incoming task's on every switch.
 * That save-on-switch-out is mandatory on arm64 because musl writes TPIDR_EL0
 * directly from EL0 (no syscall), so the kernel only learns a task's TLS base
 * by reading the register when it switches away.
 *
 * The generic scheduler calls arch_set_fs_base(next->fs_base) *before*
 * ctx_switch to load the incoming task's base — correct on x86 (whose
 * ctx_switch.asm doesn't touch fs_base, and which tracks it via arch_prctl).
 * On arm64 that write would clobber the still-running OUTGOING task's live
 * TPIDR_EL0 an instant before ctx_switch.S snapshots it, corrupting the
 * outgoing task's saved base with the incoming task's (observed: login's TLS
 * base reverted to init's, so errno/free faulted). Doing nothing here leaves
 * ctx_switch.S as the single owner. */
static inline void
arch_set_fs_base(uint64_t addr)
{
    (void)addr;
}

/* SMAP-equivalent stubs. arm64 v1 runs with PAN disabled so plain
 * copy_to/from_user (uaccess.h memcpy path) reaches user pages through
 * TTBR0. TODO(security): enable PAN + LDTR/STTR uaccess with an exception
 * table, matching the x86 SMAP + __ex_table posture. */
extern int arch_smap_enabled;
static inline void arch_stac(void) {}
static inline void arch_clac(void) {}

/* -------------------------------------------------------------------------
 * Arch-portable helpers
 * ------------------------------------------------------------------------- */

static inline void arch_wmb(void) { __asm__ volatile("dsb st" ::: "memory"); }

static inline void arch_enable_irq(void)  { __asm__ volatile("msr daifclr, #2" ::: "memory"); }
static inline void arch_disable_irq(void) { __asm__ volatile("msr daifset, #2" ::: "memory"); }

static inline unsigned long
arch_irq_save(void)
{
    unsigned long flags;
    __asm__ volatile("mrs %0, daif\n\tmsr daifset, #2" : "=r"(flags) : : "memory");
    return flags;
}

static inline void
arch_irq_restore(unsigned long flags)
{
    __asm__ volatile("msr daif, %0" : : "r"(flags) : "memory");
}

/* Monotonic cycle counter: the generic timer's virtual count. */
static inline uint64_t
arch_get_cycles(void)
{
    uint64_t v;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static inline void arch_pause(void) { __asm__ volatile("yield"); }

static inline void arch_halt(void) { __asm__ volatile("wfi" ::: "memory"); }

/* Enable IRQs, wait for one, mask again. A pending IRQ wakes WFI even
 * before the enable window, so no lost-wakeup race like x86's sti;hlt. */
static inline void arch_wait_for_irq(void)
{
    __asm__ volatile("msr daifclr, #2\n\twfi\n\tmsr daifset, #2" ::: "memory");
}

static inline int arch_early_key_held(void) { return 0; }

#endif /* ARCH_H */
