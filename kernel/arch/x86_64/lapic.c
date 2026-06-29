/*
 * lapic.c — Local APIC driver for x86-64
 *
 * Maps the LAPIC MMIO page (typically 0xFEE00000) into kernel VA and provides
 * EOI, IPI, and ID accessors. BSP calls lapic_init(); APs call lapic_init_ap()
 * which reuses the BSP's MMIO mapping (same physical address, per-CPU register
 * file selected by hardware).
 */

#include "lapic.h"
#include "arch.h"
#include "vmm.h"
#include "kva.h"
#include "printk.h"
#include "hyperv.h"
#include "pit.h"

#include <stdint.h>

/* IA32_APIC_BASE MSR */
#define MSR_APIC_BASE       0x1B

/* LAPIC register offsets (byte offsets from base) */
#define LAPIC_ID            0x020
#define LAPIC_TPR           0x080
#define LAPIC_EOI           0x0B0
#define LAPIC_SVR           0x0F0
#define LAPIC_ICR_LOW       0x300
#define LAPIC_ICR_HIGH      0x310
#define LAPIC_TIMER_LVT     0x320
#define LAPIC_TIMER_ICR     0x380
#define LAPIC_TIMER_CCR     0x390
#define LAPIC_TIMER_DCR     0x3E0

/* SVR bits */
#define SVR_ENABLE          (1u << 8)
#define SVR_SPURIOUS_VEC    0xFF

/* ICR bits */
#define ICR_DELIVERY_STATUS (1u << 12)
#define ICR_SHORTHAND_SHIFT 18

static volatile uint32_t *s_lapic_base;   /* kernel VA of LAPIC MMIO page */
static int                s_active;       /* 1 after successful init       */

/* --------------------------------------------------------------------------
 * MMIO helpers — all accesses are 32-bit aligned register reads/writes.
 * -------------------------------------------------------------------------- */

static inline uint32_t
lapic_read(uint32_t offset)
{
    return s_lapic_base[offset / 4];
}

static inline void
lapic_write(uint32_t offset, uint32_t val)
{
    s_lapic_base[offset / 4] = val;
}

/* --------------------------------------------------------------------------
 * MSR helpers
 * -------------------------------------------------------------------------- */

static inline uint64_t
rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

/* --------------------------------------------------------------------------
 * Internal: configure SVR + TPR (shared between BSP and AP init)
 * -------------------------------------------------------------------------- */

static void
lapic_configure(void)
{
    /* Enable LAPIC via SVR: set enable bit + spurious vector 0xFF */
    lapic_write(LAPIC_SVR, SVR_ENABLE | SVR_SPURIOUS_VEC);

    /* Clear task priority — accept all interrupts */
    lapic_write(LAPIC_TPR, 0);
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

/*
 * lapic_init — BSP initialization.
 *
 * Reads IA32_APIC_BASE MSR to find the LAPIC physical address, maps one
 * 4KB MMIO page into kernel VA (uncached), and configures SVR + TPR.
 */
void
lapic_init(void)
{
    uint64_t msr_val  = rdmsr(MSR_APIC_BASE);
    uint64_t phys     = msr_val & 0xFFFFF000ULL;  /* bits [35:12] */

    /* Allocate a kernel VA page, then remap it to the LAPIC MMIO address.
     * Pattern: kva gives us a PMM-backed page; we unmap that backing and
     * remap to the device physical address with uncacheable flags. */
    void *va = kva_alloc_pages(1);
    if (!va) {
        printk("[LAPIC] FAIL: kva_alloc_pages returned NULL\n");
        return;
    }
    vmm_unmap_page((uintptr_t)va);
    vmm_map_page((uintptr_t)va, phys,
                 VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS);

    s_lapic_base = (volatile uint32_t *)va;

    lapic_configure();

    s_active = 1;

    printk("[LAPIC] OK: id=%u base=0x%lx\n",
           (unsigned)lapic_id(), phys);
}

/*
 * lapic_init_ap — AP initialization.
 *
 * Reuses the BSP's MMIO mapping (the LAPIC physical address is the same for
 * all cores; hardware selects the per-CPU register file internally).
 * Configures SVR + TPR for this AP.
 */
void
lapic_init_ap(void)
{
    lapic_configure();
}

/*
 * lapic_id — return this CPU's LAPIC ID (bits [31:24] of the ID register).
 */
uint8_t
lapic_id(void)
{
    return (uint8_t)(lapic_read(LAPIC_ID) >> 24);
}

/*
 * lapic_eoi — signal end-of-interrupt to the local APIC.
 */
void
lapic_eoi(void)
{
    lapic_write(LAPIC_EOI, 0);
}

/*
 * lapic_send_ipi — send a fixed IPI to a specific APIC ID.
 *
 * Waits for the ICR delivery-status bit to clear before writing.
 */
void
lapic_send_ipi(uint8_t dest_apic_id, uint8_t vector)
{
    /* Wait for previous IPI to complete */
    while (lapic_read(LAPIC_ICR_LOW) & ICR_DELIVERY_STATUS)
        arch_pause();

    /* Set destination in ICR_HIGH bits [31:24] */
    lapic_write(LAPIC_ICR_HIGH, (uint32_t)dest_apic_id << 24);

    /* Fire: fixed delivery, edge, assert, physical destination */
    lapic_write(LAPIC_ICR_LOW, (uint32_t)vector);
}

/*
 * lapic_send_init — send an INIT IPI to the specified APIC ID.
 *
 * Used by smp_start_aps() to reset APs before SIPI. ICR_LOW = 0x4500:
 * delivery mode = INIT (101b in bits 10:8), level = assert, trigger = edge.
 */
void
lapic_send_init(uint8_t dest_apic_id)
{
    while (lapic_read(LAPIC_ICR_LOW) & ICR_DELIVERY_STATUS)
        arch_pause();
    lapic_write(LAPIC_ICR_HIGH, (uint32_t)dest_apic_id << 24);
    lapic_write(LAPIC_ICR_LOW, 0x00004500);
}

/*
 * lapic_send_sipi — send a Startup IPI (SIPI) to the specified APIC ID.
 *
 * vector is the page number of the real-mode entry point (e.g. 0x08 for
 * physical address 0x8000). ICR_LOW = 0x4600 | vector: delivery mode = SIPI
 * (110b in bits 10:8), level = assert, trigger = edge.
 */
void
lapic_send_sipi(uint8_t dest_apic_id, uint8_t vector)
{
    while (lapic_read(LAPIC_ICR_LOW) & ICR_DELIVERY_STATUS)
        arch_pause();
    lapic_write(LAPIC_ICR_HIGH, (uint32_t)dest_apic_id << 24);
    lapic_write(LAPIC_ICR_LOW, 0x00004600 | vector);
}

/*
 * lapic_send_ipi_all_excl_self — broadcast IPI to all CPUs except this one.
 *
 * Uses shorthand 11b (all-excluding-self) in ICR_LOW bits [19:18].
 */
void
lapic_send_ipi_all_excl_self(uint8_t vector)
{
    while (lapic_read(LAPIC_ICR_LOW) & ICR_DELIVERY_STATUS)
        arch_pause();

    /* Shorthand = 11 (all excluding self), no destination needed */
    lapic_write(LAPIC_ICR_LOW,
                (uint32_t)vector | (3u << ICR_SHORTHAND_SHIFT));
}

/*
 * lapic_active — return 1 if LAPIC has been initialized, 0 otherwise.
 */
int
lapic_active(void)
{
    return s_active;
}

/* --------------------------------------------------------------------------
 * LAPIC Timer — calibrated via PIT channel 2, configured for periodic mode.
 *
 * Vector 0x30 (avoids conflict with PIT on 0x20).
 * Calibration: start a PIT channel 2 one-shot for ~10ms, count down the
 * LAPIC timer from 0xFFFFFFFF, then compute ticks-per-10ms. Configure
 * periodic mode at that rate (~100Hz).
 *
 * Must be called on EACH CPU (BSP and every AP) after lapic_init/lapic_init_ap.
 * BSP: kernel_main, immediately before sched_start (IF=0 — the calibration
 * spin polls port 0x61 and needs no interrupts; vector 0x30 stays pending
 * until the first task enables interrupts).  APs: ap_entry, before setting
 * g_ap_online — which serializes the shared-PIT-channel-2 calibration
 * against the BSP's later call.  This timer is the ONLY sched_tick source
 * per CPU: the PIT (vector 0x20, BSP) does timekeeping + polling only.
 * -------------------------------------------------------------------------- */

/* Forward declaration — avoid circular header include */
extern void sched_tick(void);

/*
 * lapic_timer_init — calibrate and start the LAPIC timer in periodic mode.
 */
void
lapic_timer_init(void)
{
    if (!s_active)
        return;

    /* Divide configuration: divide by 16 (DCR value 0x03) */
    lapic_write(LAPIC_TIMER_DCR, 0x03);

    /* Mask timer during calibration: masked (bit 16), vector 0x30 */
    lapic_write(LAPIC_TIMER_LVT, 0x00010030);

    /* Measure how many LAPIC ticks elapse in a known ~10ms window.  The 8254
     * PIT is the reference on real hardware / QEMU, but Hyper-V Gen 2 VMs do
     * not emulate it at all (PIT is Gen 1 only) — calibrating against it there
     * yields garbage (elapsed≈21 → a multi-kHz runaway timer).  On Hyper-V we
     * time the window with the partition reference counter (100ns units). */
    uint32_t elapsed;
    uint64_t tsc_c0 = arch_get_cycles();   /* TSC over the same 10 ms window → calibrate */
    if (hyperv_present()) {
        lapic_write(LAPIC_TIMER_ICR, 0xFFFFFFFF);
        uint64_t t0 = hyperv_ref_time();
        while (hyperv_ref_time() - t0 < 100000ull)   /* 100000 * 100ns = 10ms */
            arch_pause();
        elapsed = 0xFFFFFFFF - lapic_read(LAPIC_TIMER_CCR);
    } else {
        /* PIT channel 2 one-shot for ~10ms (11932 ticks at 1.193182 MHz).
         * Port 0x61 bit 0 = gate, bit 1 = speaker (keep off).
         * Port 0x43 = 0xB0: channel 2, lo/hi, mode 0 (one-shot), binary.
         * Port 0x61 bit 5 = output of channel 2 (goes high when count expires). */
        outb(0x61, (inb(0x61) & 0xFD) | 0x01);   /* gate on, speaker off */
        outb(0x43, 0xB0);                          /* ch2 mode 0 */
        outb(0x42, 0x9C);                          /* 11932 low byte */
        outb(0x42, 0x2E);                          /* 11932 high byte */

        lapic_write(LAPIC_TIMER_ICR, 0xFFFFFFFF);  /* start countdown from max */

        while (!(inb(0x61) & 0x20))                /* spin until ch2 output high */
            arch_pause();

        elapsed = 0xFFFFFFFF - lapic_read(LAPIC_TIMER_CCR);
    }

    /* Calibrate the TSC-based monotonic clock against the same 10 ms window
     * (arch_tsc_calibrate gates on invariant TSC + sanity, so this is a no-op
     * on CPUs without an invariant TSC). */
    arch_tsc_calibrate(arch_get_cycles() - tsc_c0);

    /* Mask the timer while we reconfigure */
    lapic_write(LAPIC_TIMER_LVT, 0x00010030);

    /* Configure periodic mode (bit 17), vector 0x30, unmasked */
    lapic_write(LAPIC_TIMER_LVT, (1u << 17) | 0x30);
    lapic_write(LAPIC_TIMER_ICR, elapsed);
    if (hyperv_present())   /* Hyper-V-only: confirms the ref-counter calibration */
        printk("[LAPIC] OK: timer calibrated via HV ref counter (icr=%u)\n",
               (unsigned)elapsed);
}

/*
 * lapic_timer_handler — called from isr_dispatch on vector 0x30.
 *
 * Drives the scheduler tick. EOI is sent by the generic IRQ path in
 * isr_dispatch (EOI-before-handler pattern, safe for edge-triggered LAPIC
 * timer in periodic mode).
 */
void
lapic_timer_handler(void)
{
    sched_tick();
    /* On Hyper-V Gen 2 there is no 8254 PIT, so the LAPIC timer is also the
     * device-poll + timekeeping source.  Run that work on the BSP only (the
     * pollers are single-producer); the AP timers do preemption only.  On real
     * hardware / QEMU the PIT does this and hyperv_present() is false here. */
    if (hyperv_present() && lapic_id() == 0)
        timer_bsp_tick();
}
