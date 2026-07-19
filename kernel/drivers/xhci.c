/* xhci.c — xHCI USB host controller driver (Phase 22)
 *
 * Implements xHCI 1.2 controller initialization, device enumeration for
 * HID boot-protocol keyboards, and polling-based transfer handling.
 *
 * Init sequence:
 *   1. Locate xHCI controller via pcie_find_device(0x0C, 0x03, 0x30)
 *   2. Map BAR0 MMIO (16 pages = 64KB, uncached)
 *   3. Stop + reset controller
 *   4. Allocate and wire up DCBAA, Command Ring, Event Ring (ERST)
 *   5. Start controller (USBCMD.RS = 1)
 *   6. Enumerate ports: reset, Enable Slot, Address Device, Configure EP
 *   7. Schedule first interrupt IN transfer per keyboard slot
 *
 * Polling: xhci_poll() is called from the PIT ISR at 100 Hz.
 * No MSI/MSI-X — event ring is polled, not interrupt-driven.
 */
#include "xhci.h"
#include "arch.h"
#include "pcie.h"
#include "vmm.h"
#include "kva.h"
#include "pmm.h"
#include "printk.h"
#include "netdev.h"
#include "blkdev.h"
#include "spinlock.h"
#include <stdint.h>
#include <stddef.h>

/* Forward-declare the USB HID report handler.  usb_hid.h is defined in
 * Task 3; including it here would create a forward-dependency during phased
 * development.  The linker resolves this symbol when usb_hid.c is compiled
 * and linked in Task 4. */
void usb_hid_process_report(const uint8_t *report, uint32_t len);
void usb_mouse_process_report(const uint8_t *data, uint32_t len);

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

/* Number of BAR0 pages to map (256 pages = 1 MiB).
 * Covers CAP + OP + Runtime + Doorbell + extended capabilities. Real
 * hardware controllers may place extended caps and runtime registers
 * well beyond the first 64 KB; the previous 16-page (64 KB) limit
 * caused USBLEGSUP cap walks to fault on AMD. */
#define XHCI_BAR0_PAGES      256u

/* Maximum slots we support (hardware MaxSlots may be higher). */
#define XHCI_MAX_SLOTS       32u

/* Extended capability IDs (xHCI 1.0 §7) */
#define XHCI_EXT_CAP_LEGACY     1u   /* USB Legacy Support */
#define XHCI_EXT_CAP_PROTOCOL   2u   /* Supported Protocol */

/* USBLEGSUP register bits */
#define XHCI_LEGSUP_BIOS_OWNED  (1u << 16)
#define XHCI_LEGSUP_OS_OWNED    (1u << 24)

/* USBLEGCTLSTS bits — at offset 0x04 from USBLEGSUP cap base */
#define XHCI_LEGCTLSTS_DISABLE_SMI  0x000001E1u  /* SMI enables we disable */
#define XHCI_LEGCTLSTS_SMI_EVENTS   0xE0000000u  /* SMI event RW1C bits */

/* Maximum xHCI controllers we'll handle on a single machine.
 * Modern AMD/Intel platforms expose 1-4 xHCI host controllers. */
#define XHCI_MAX_CONTROLLERS    4u

/* Maximum physical ports we track for USB 2.0 / hotplug bookkeeping.
 * Each xHCI port number is 1-based, indexed 1..MaxPorts (≤255). */
#define XHCI_MAX_PORTS          64u

/* Endpoint index (doorbell value) for EP1 IN (HID keyboard).
 * xHCI DCI for EP1 IN = 2 * ep_number + direction(IN=1) = 2*1+1 = 3. */
#define XHCI_EP1_IN_DCI      3u

/* Input Context entry size (bytes per context slot).
 * Determined at init from HCCPARAMS1.CSZ (bit 2):
 *   0 = 32-byte contexts (xHCI 0.96/1.0 baseline)
 *   1 = 64-byte contexts (most actual implementations including qemu-xhci)
 * Stored in s_ctx_entry_size during xhci_init. */
static uint32_t s_ctx_entry_size = 32u;
#define XHCI_CTX_ENTRY_SIZE  s_ctx_entry_size

/* USB speed values in Slot Context speed field [PORTSC bits 13:10]. */
#define XHCI_SPEED_FS        1u   /* Full Speed  (12  Mbit/s) */
#define XHCI_SPEED_LS        2u   /* Low  Speed  (1.5 Mbit/s) */
#define XHCI_SPEED_HS        3u   /* High Speed  (480 Mbit/s) */
#define XHCI_SPEED_SS        4u   /* Super Speed (5   Gbit/s) */

/* EP types in Endpoint Context EPType field. */
#define XHCI_EP_TYPE_CTRL    4u
#define XHCI_EP_TYPE_INT_IN  7u
#define XHCI_EP_TYPE_BULK_OUT 2u
#define XHCI_EP_TYPE_BULK_IN  6u

/* Byte offsets of operational register fields (xHCI spec §5.4).
 * Used to avoid taking addresses of packed struct members. */
#define XHCI_OP_USBCMD_OFF   0x00u
#define XHCI_OP_USBSTS_OFF   0x04u

/* -------------------------------------------------------------------------
 * Static state
 * ---------------------------------------------------------------------- */

static volatile int              s_msc_busy       = 0;  /* MSC owns the event ring */
static int                       s_post_boot      = 0;

/* Per-controller state. The RP1 has TWO independent dwc3/xHCI controllers
 * (USB0 @ 0x1f00200000, USB1 @ 0x1f00300000), each driving one black + one
 * blue jack. To run both (keyboard on one, mouse on the other) every register
 * pointer, ring, DCBAA and per-slot table must be per-controller. Rather than
 * thread a handle through the whole 3000-line driver, all that state lives in
 * one struct; `s_cur` selects the active controller and the s_* macros below
 * redirect the unchanged driver body at it. xhci_init_at() and xhci_poll()
 * set s_cur; nothing else in the logic changes. */
#ifndef XHCI_MAX_HC
#define XHCI_MAX_HC 2u
#endif
struct xhci_ctrl {
    int                        active;
    uint8_t                   *bar0_va;
    /* SAFETY: cap/op are volatile MMIO pointers — no caching of reg access. */
    volatile xhci_cap_regs_t  *cap;
    volatile xhci_op_regs_t   *op;
    /* Command Ring */
    xhci_trb_t                *cmd_ring;
    uint64_t                   cmd_ring_phys;
    int                        cmd_cycle;
    uint32_t                   cmd_enqueue;
    /* Event Ring (volatile: cycle-bit polls must not be optimised away) */
    volatile xhci_trb_t       *evt_ring;
    uint64_t                   evt_ring_phys;
    uint32_t                   evt_dequeue;
    int                        evt_cycle;
    uint32_t                   max_ports;
    uint32_t                   max_slots;
    uint8_t                    port_is_usb2[XHCI_MAX_PORTS + 1];
    uint8_t                    port_is_usb3[XHCI_MAX_PORTS + 1];
    uint8_t                    pending_enum[XHCI_MAX_PORTS + 1];
    uint64_t                   dcbaa_phys;
    uint64_t                  *dcbaa;
    /* Per-slot HID state (index 0 unused; xHCI slots are 1-based) */
    int                        hid_slots[XHCI_MAX_SLOTS];
    uint8_t                    hid_slot_type[XHCI_MAX_SLOTS];
    uint8_t                    slot_port[XHCI_MAX_SLOTS];
    uint8_t                   *hid_buf[XHCI_MAX_SLOTS];
    uint64_t                   hid_buf_phys[XHCI_MAX_SLOTS];
    xhci_trb_t                *xfer_ring[XHCI_MAX_SLOTS];
    uint64_t                   xfer_ring_phys[XHCI_MAX_SLOTS];
    uint32_t                   xfer_enqueue[XHCI_MAX_SLOTS];
    int                        xfer_cycle[XHCI_MAX_SLOTS];
    /* Per-slot Output Device Context (xHCI §4.2). */
    uint8_t                   *dev_ctx[XHCI_MAX_SLOTS];
    uint64_t                   dev_ctx_phys[XHCI_MAX_SLOTS];
    /* Per-port enumeration diagnostics (/proc/usbnet). */
    uint8_t                    enum_stage[XHCI_MAX_PORTS + 1];
    uint8_t                    enum_cc[XHCI_MAX_PORTS + 1];
    uint32_t                   enum_usbsts[XHCI_MAX_PORTS + 1];
};
static struct xhci_ctrl  s_hc[XHCI_MAX_HC];
static struct xhci_ctrl *s_cur = &s_hc[0];
static uint32_t          s_hc_count = 0;   /* # of controllers brought up */

#define s_xhci_active     (s_cur->active)
#define s_bar0_va         (s_cur->bar0_va)
#define s_cap             (s_cur->cap)
#define s_op              (s_cur->op)
#define s_cmd_ring        (s_cur->cmd_ring)
#define s_cmd_ring_phys   (s_cur->cmd_ring_phys)
#define s_cmd_cycle       (s_cur->cmd_cycle)
#define s_cmd_enqueue     (s_cur->cmd_enqueue)
#define s_evt_ring        (s_cur->evt_ring)
#define s_evt_ring_phys   (s_cur->evt_ring_phys)
#define s_evt_dequeue     (s_cur->evt_dequeue)
#define s_evt_cycle       (s_cur->evt_cycle)
#define s_max_ports       (s_cur->max_ports)
#define s_max_slots       (s_cur->max_slots)
#define s_port_is_usb2    (s_cur->port_is_usb2)
#define s_port_is_usb3    (s_cur->port_is_usb3)
#define s_pending_enum    (s_cur->pending_enum)
#define s_dcbaa_phys      (s_cur->dcbaa_phys)
#define s_dcbaa           (s_cur->dcbaa)
#define s_hid_slots       (s_cur->hid_slots)
#define s_hid_slot_type   (s_cur->hid_slot_type)
#define s_slot_port       (s_cur->slot_port)
#define s_hid_buf         (s_cur->hid_buf)
#define s_hid_buf_phys    (s_cur->hid_buf_phys)
#define s_xfer_ring       (s_cur->xfer_ring)
#define s_xfer_ring_phys  (s_cur->xfer_ring_phys)
#define s_xfer_enqueue    (s_cur->xfer_enqueue)
#define s_xfer_cycle      (s_cur->xfer_cycle)
#define s_dev_ctx         (s_cur->dev_ctx)
#define s_dev_ctx_phys    (s_cur->dev_ctx_phys)
#define s_enum_stage      (s_cur->enum_stage)
#define s_enum_cc         (s_cur->enum_cc)
#define s_enum_usbsts     (s_cur->enum_usbsts)

/* -------------------------------------------------------------------------
 * MMIO accessor helpers
 *
 * The op register struct is __attribute__((packed)).  GCC treats
 * -Waddress-of-packed-member as an error, so we must not take the address
 * of any packed struct member.  Instead, compute the byte offset explicitly
 * and cast the base pointer — the fields are at their spec-defined offsets
 * and all are naturally aligned within the 4KB MMIO page.
 * ---------------------------------------------------------------------- */

static inline uint32_t
op_read32(uint32_t byte_off)
{
    /* SAFETY: s_op is a kernel VA mapping xHCI operational MMIO; byte_off is
     * a compile-time constant (XHCI_OP_*_OFF) within the mapped 64KB region.
     * Casting via uint8_t * and reading through volatile uint32_t * ensures
     * a 4-byte MMIO load without touching a packed struct field directly. */
    volatile uint32_t *p =
        (volatile uint32_t *)((volatile uint8_t *)s_op + byte_off);
    return *p;
}

static inline void
op_write32(uint32_t byte_off, uint32_t val)
{
    /* SAFETY: same rationale as op_read32. */
    volatile uint32_t *p =
        (volatile uint32_t *)((volatile uint8_t *)s_op + byte_off);
    *p = val;
}

/* -------------------------------------------------------------------------
 * Spin helpers
 * ---------------------------------------------------------------------- */

/* xhci_busy_wait_ms — block ms milliseconds.
 *
 * IMPORTANT: xhci_init runs in early boot with interrupts disabled, so
 * the PIT tick counter (arch_get_ticks) is frozen and CANNOT be used
 * for waiting. We instead use rdtsc() which always advances.
 *
 * We don't know the CPU frequency at boot — calibrate it once on first
 * call by reading TSC, doing a fixed work loop, reading TSC again. The
 * work loop is sized to take ~1ms on a typical 1-5GHz CPU. After
 * calibration, we cache the cycles-per-ms value.
 *
 * For safety the cached value is biased low (we wait at LEAST ms; the
 * actual wait may be 2-3x longer on a slow CPU, which is fine). */
static uint64_t s_cycles_per_ms = 0;

static inline uint64_t
xhci_rdtsc(void)
{
#if defined(__aarch64__)
    uint64_t v;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(v));   /* physical counter */
    return v;
#else
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#endif
}

/* Counter ticks per millisecond. arm64 has a real timebase (cntfrq_el0);
 * x86 assumes >=1 GHz TSC as a safe floor (may wait longer, never shorter). */
static inline uint64_t
xhci_ticks_per_ms(void)
{
#if defined(__aarch64__)
    uint64_t f;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(f));
    return f / 1000u;
#else
    return 1000000ULL;
#endif
}

/* CPU relax hint inside a spin loop. */
static inline void
xhci_relax(void)
{
#if defined(__aarch64__)
    __asm__ volatile("yield");
#else
    xhci_relax();
#endif
}

static void
xhci_busy_wait_ms(uint32_t ms)
{
    if (s_cycles_per_ms == 0) {
        /* Calibrate. Without a known timebase, we calibrate against a
         * fixed-cycle loop and ASSUME at least 1 GHz; on a 4 GHz CPU
         * the actual wait will be 4x what we ask for, which is safe.
         * We use 1,000,000 cycles per ms as the floor (= 1 GHz). */
        s_cycles_per_ms = xhci_ticks_per_ms();
    }
    uint64_t start = xhci_rdtsc();
    uint64_t deadline = start + (uint64_t)ms * s_cycles_per_ms;
    while (xhci_rdtsc() < deadline)
        xhci_relax();
}

/* op_spin_until_set — busy-wait until (op_reg_at_off & mask) != 0.
 * Returns 0 on success, -1 on timeout (ms_timeout milliseconds).
 * Uses rdtsc-based timing so it works in early boot before PIT IRQs. */
static int
op_spin_until_set_ms(uint32_t off, uint32_t mask, uint32_t ms_timeout)
{
    if (s_cycles_per_ms == 0) s_cycles_per_ms = xhci_ticks_per_ms();
    uint64_t deadline = xhci_rdtsc() + (uint64_t)ms_timeout * s_cycles_per_ms;
    while (xhci_rdtsc() < deadline) {
        if (op_read32(off) & mask)
            return 0;
        xhci_relax();
    }
    return -1;
}

/* op_spin_until_clear — busy-wait until (op_reg_at_off & mask) == 0. */
static int
op_spin_until_clear_ms(uint32_t off, uint32_t mask, uint32_t ms_timeout)
{
    if (s_cycles_per_ms == 0) s_cycles_per_ms = xhci_ticks_per_ms();
    uint64_t deadline = xhci_rdtsc() + (uint64_t)ms_timeout * s_cycles_per_ms;
    while (xhci_rdtsc() < deadline) {
        if (!(op_read32(off) & mask))
            return 0;
        xhci_relax();
    }
    return -1;
}

/* Legacy alias kept for the start-controller path that still uses
 * the symbol name op_spin_until_clear. */
static int
op_spin_until_clear(uint32_t off, uint32_t mask)
{
    return op_spin_until_clear_ms(off, mask, 1000u);
}

/* -------------------------------------------------------------------------
 * Page allocator helper
 * ---------------------------------------------------------------------- */

/* When set, all xHCI DMA memory is allocated Normal-NC (non-coherent) instead of
 * cacheable. Needed for controllers behind a non-coherent bus (the RP1 dwc3 on
 * Pi 5); x86 leaves it 0 (coherent). Set via xhci_set_dma_noncoherent(). */
static int s_xhci_dma_nc = 0;
void xhci_set_dma_noncoherent(int nc) { s_xhci_dma_nc = nc; }

/* alloc_page — allocate one 4KB zeroed page, return VA; set *phys_out.
 * Follows the nvme.c alloc_queue_page() pattern exactly. */
static void *
alloc_page(uint64_t *phys_out)
{
    /* Non-coherent path (RP1): Normal-NC <4GB page — the controller's DMA sees
     * the writes without cache maintenance, and the RP1 inbound window is
     * identity so kva_page_phys is the bus address directly. */
    void *va = s_xhci_dma_nc ? kva_alloc_pages_low_nc(1) : kva_alloc_pages(1);
    /* SAFETY: kva_alloc_pages returns a kernel VA for a PMM-allocated page;
     * zeroing via __builtin_memset is safe. */
    __builtin_memset(va, 0, 4096);
    *phys_out = kva_page_phys(va);
    return va;
}

/* -------------------------------------------------------------------------
 * Extended Capabilities walker
 *
 * The xHCI Extended Capabilities are a linked list anchored at HCCPARAMS1
 * bits [31:16] (xECP). Each cap is a 32-bit dword: [7:0] cap ID, [15:8]
 * next-cap offset (DWORDs from CURRENT cap; 0 = end), [31:16] cap-specific.
 *
 * Returns the byte offset (relative to s_bar0_va) of a cap with the given
 * cap_id, or 0 if not found / no extended caps. Walks at most 64 caps to
 * defend against malformed link lists.
 * ---------------------------------------------------------------------- */
static uint32_t
xhci_find_ext_cap(uint32_t cap_id)
{
    uint32_t hccparams1 = s_cap->hccparams1;
    uint32_t xecp_dword = (hccparams1 >> 16) & 0xFFFFu;
    if (xecp_dword == 0) return 0;

    uint32_t offset = xecp_dword << 2;  /* dwords -> bytes */
    int safety = 64;
    while (safety-- > 0) {
        if (offset == 0) return 0;
        if (offset >= XHCI_BAR0_PAGES * 4096u) return 0;  /* out of mapped */
        volatile uint32_t *p = (volatile uint32_t *)(s_bar0_va + offset);
        uint32_t val = *p;
        uint8_t  id   = (uint8_t)(val & 0xFFu);
        uint8_t  next = (uint8_t)((val >> 8) & 0xFFu);
        if (id == cap_id)
            return offset;
        if (next == 0) return 0;
        offset += (uint32_t)next << 2;
    }
    return 0;
}

/* xhci_bios_handoff — claim controller from BIOS via USBLEGSUP.
 *
 * On real hardware the BIOS owns the xHCI controller via SMI. We must
 * walk the extended capabilities to find USBLEGSUP (cap ID 1), set the
 * OS Owned Semaphore bit, wait for the BIOS Owned Semaphore to clear
 * (BIOS may take up to 5 seconds to release), then disable all SMI
 * generation in USBLEGCTLSTS (offset +0x04 from the cap base).
 *
 * Without this, BIOS SMM keeps firing on every controller event and
 * silently overrides our register writes — symptom: keyboards work in
 * BIOS/GRUB but die the moment Aegis takes over xHCI. QEMU has no
 * legacy cap so this is a no-op there.
 *
 * Returns 0 on success or if no LEGSUP cap exists. */
static int
xhci_bios_handoff(void)
{
    uint32_t legsup_off = xhci_find_ext_cap(XHCI_EXT_CAP_LEGACY);
    if (legsup_off == 0) {
        printk("[XHCI] no USBLEGSUP cap (QEMU or already handed-off)\n");
        return 0;
    }
    volatile uint32_t *legsup =
        (volatile uint32_t *)(s_bar0_va + legsup_off);
    volatile uint32_t *legctlsts =
        (volatile uint32_t *)(s_bar0_va + legsup_off + 4u);

    uint32_t val = *legsup;
    printk("[XHCI] USBLEGSUP at 0x%x = 0x%x\n",
           (unsigned)legsup_off, (unsigned)val);

    if (val & XHCI_LEGSUP_BIOS_OWNED) {
        /* Set OS Owned bit, wait for BIOS Owned to clear (up to 1s).
         * Use rdtsc-based timing — runs in early boot, no PIT IRQs. */
        *legsup = val | XHCI_LEGSUP_OS_OWNED;
        if (s_cycles_per_ms == 0) s_cycles_per_ms = xhci_ticks_per_ms();
        uint64_t deadline = xhci_rdtsc() + 1000ULL * s_cycles_per_ms;
        while (xhci_rdtsc() < deadline) {
            if (!((*legsup) & XHCI_LEGSUP_BIOS_OWNED))
                break;
            xhci_relax();
        }
        if ((*legsup) & XHCI_LEGSUP_BIOS_OWNED) {
            /* BIOS never released — force ownership (workaround for
             * broken BIOSes per Linux quirk_usb_handoff_xhci). */
            printk("[XHCI] WARN: BIOS never released, forcing ownership\n");
            *legsup = (*legsup) & ~XHCI_LEGSUP_BIOS_OWNED;
        } else {
            printk("[XHCI] BIOS released ownership cleanly\n");
        }
    }

    /* Disable all SMI generation. Mask off SMI enable bits, write 1 to
     * SMI event bits to clear them. The "write back as-is + clear" idiom
     * matches Linux's quirk_usb_handoff_xhci. */
    {
        uint32_t v = *legctlsts;
        v &= ~XHCI_LEGCTLSTS_DISABLE_SMI;
        v |=  XHCI_LEGCTLSTS_SMI_EVENTS;  /* RW1C — clear pending */
        *legctlsts = v;
    }
    return 0;
}

/* xhci_walk_supported_protocols — populate s_port_is_usb2 / s_port_is_usb3
 * by walking every Supported Protocol extended cap (cap ID 2). Each cap
 * dword2 holds: PortOffset[7:0] (1-based) and PortCount[15:8]. dword0
 * holds the major revision in bits [31:24] (0x02 = USB 2.0, 0x03 = USB 3.x).
 *
 * On QEMU's qemu-xhci this populates ports 1-4 as USB 3 and 5-8 as USB 2.
 * On real AMD it differentiates the SS-only ports from the HS pair so the
 * port enumeration loop can skip dead SS ports correctly.
 *
 * Walks the linked list manually since xhci_find_ext_cap returns only the
 * first match for a given ID, and there can be multiple SUPP_PROTOCOL caps. */
static void
xhci_walk_supported_protocols(void)
{
    uint32_t hccparams1 = s_cap->hccparams1;
    uint32_t xecp_dword = (hccparams1 >> 16) & 0xFFFFu;
    if (xecp_dword == 0) return;

    uint32_t offset = xecp_dword << 2;
    int safety = 64;
    while (offset != 0 && safety-- > 0) {
        if (offset >= XHCI_BAR0_PAGES * 4096u) break;
        volatile uint32_t *p = (volatile uint32_t *)(s_bar0_va + offset);
        uint32_t dw0 = p[0];
        uint8_t  id   = (uint8_t)(dw0 & 0xFFu);
        uint8_t  next = (uint8_t)((dw0 >> 8) & 0xFFu);

        if (id == XHCI_EXT_CAP_PROTOCOL) {
            uint32_t dw2 = p[2];
            uint8_t  major  = (uint8_t)((dw0 >> 24) & 0xFFu);
            uint8_t  port_offset = (uint8_t)(dw2 & 0xFFu);   /* 1-based */
            uint8_t  port_count  = (uint8_t)((dw2 >> 8) & 0xFFu);
            printk("[XHCI] supp proto: major=0x%x ports %u..%u\n",
                   (unsigned)major, (unsigned)port_offset,
                   (unsigned)(port_offset + port_count - 1));
            uint32_t i;
            for (i = 0; i < port_count; i++) {
                uint32_t pn = port_offset + i;
                if (pn >= 1 && pn <= XHCI_MAX_PORTS) {
                    if (major <= 0x02) s_port_is_usb2[pn] = 1;
                    else                s_port_is_usb3[pn] = 1;
                }
            }
        }

        if (next == 0) break;
        offset += (uint32_t)next << 2;
    }
}

/* -------------------------------------------------------------------------
 * Command Ring helpers
 * ---------------------------------------------------------------------- */

/* enqueue_cmd — place a TRB on the command ring, advance the tail.
 * Stamps the producer cycle bit into control[0].  At position
 * XHCI_CMD_RING_SIZE-1 we place a Link TRB and flip the cycle bit. */
static void
enqueue_cmd(uint64_t param, uint32_t status, uint32_t type_and_flags)
{
    xhci_trb_t *trb = &s_cmd_ring[s_cmd_enqueue];
    trb->param   = param;
    trb->status  = status;
    trb->control = type_and_flags | (uint32_t)s_cmd_cycle;

    s_cmd_enqueue++;
    if (s_cmd_enqueue == XHCI_CMD_RING_SIZE - 1u) {
        /* Rewrite Link TRB with current cycle bit, then toggle */
        xhci_trb_t *link = &s_cmd_ring[s_cmd_enqueue];
        link->param   = s_cmd_ring_phys;
        link->status  = 0;
        link->control = (uint32_t)(XHCI_TRB_LINK << 10) |
                        (1u << 1) |              /* Toggle Cycle bit */
                        (uint32_t)s_cmd_cycle;
        s_cmd_cycle  ^= 1;
        s_cmd_enqueue = 0;
    }
}

/* ring_cmd_doorbell — notify controller of new command ring entries. */
static void
ring_cmd_doorbell(void)
{
    /* SAFETY: s_bar0_va + cap->dboff is the doorbell array start;
     * doorbell 0 is the host-controller command doorbell. */
    volatile uint32_t *db =
        (volatile uint32_t *)(s_bar0_va + s_cap->dboff);
    /* sfence: all TRB writes must be globally visible before doorbell. */
    arch_wmb();
    db[0] = 0;
}

/* update_erdp — write current event dequeue pointer to interrupter 0.
 * ERDP at runtime_base + 0x20 (interrupter 0) + 0x18 (ERDP). Must hold
 * a PHYSICAL address; bit 3 (EHB - Event Handler Busy) must be written
 * as 1 each update to clear it (RW1C), or the controller's event
 * interrupt assertion eventually stalls. */
static void
update_erdp(void)
{
    uint8_t *rts = s_bar0_va + s_cap->rtsoff;
    volatile uint64_t *erdp =
        (volatile uint64_t *)(rts + 0x20u + 0x18u);
    /* ERDP must be the BYTE-ACCURATE physical address of the next event TRB.
     * kva_page_phys (→ vmm_phys_of → ARCH_PTE_ADDR) returns the PAGE BASE only,
     * dropping the intra-page offset — so the old code pinned ERDP at the ring
     * base regardless of s_evt_dequeue. The controller then never saw software
     * advance, believed the ring was full once ~64 events accumulated (across
     * the boot's resets + commands + descriptor reads), and stopped posting
     * completions — making a later device's Address Device time out. Compute
     * the exact PA from the stored ring base + dequeue index instead. */
    uint64_t pa = s_evt_ring_phys + (uint64_t)s_evt_dequeue * sizeof(xhci_trb_t);
    *erdp = pa | (1ULL << 3);  /* PA | EHB clear */
}

/* poll_cmd_completion — wait for a CMD_COMPLETION event on the event ring.
 * Skips any other event types (Port Status Change, Transfer events) that
 * may have been posted before the command completion arrives.
 * Returns the slot_id from bits [31:24] of the event control field on
 * success (TRB_COMPLETION_SUCCESS, cc=1), or 0 on timeout/error. */
static uint8_t s_last_cmd_cc;  /* completion code of the last command (0xFF=timeout) — /proc/usbnet */
static uint8_t s_last_ctrl_cc; /* completion code of the last control transfer (0xFF=timeout) */
static uint8_t
poll_cmd_completion(void)
{
    /* Wall-clock 1s timeout (TSC-based, CPU-speed-independent). The old fixed
     * 2,000,000-iteration count was only ~10-30ms on a fast CPU — too short and
     * jittery for a real SuperSpeed Address Device, which intermittently took
     * longer and "timed out" (cc=timeout) run-to-run. Matches the control-
     * transfer path's timeout discipline. */
    if (s_cycles_per_ms == 0) s_cycles_per_ms = xhci_ticks_per_ms();
    uint64_t deadline = xhci_rdtsc() + 1000ULL * s_cycles_per_ms;
    while (xhci_rdtsc() < deadline) {
        volatile xhci_trb_t *trb = &s_evt_ring[s_evt_dequeue];
        /* SAFETY: trb is a volatile pointer into a kva-mapped page; the
         * volatile qualifier ensures each cycle-bit read goes to memory. */
        uint32_t ctrl = trb->control;
        if ((ctrl & 1u) != (uint32_t)s_evt_cycle) {
            xhci_relax();
            continue;   /* no new event yet */
        }

        uint32_t trb_type = (ctrl >> 10) & 0x3Fu;
        uint8_t  slot_id  = (uint8_t)((ctrl >> 24) & 0xFFu);
        uint8_t  cc       = (uint8_t)((trb->status >> 24) & 0xFFu);

        s_evt_dequeue++;
        if (s_evt_dequeue >= XHCI_EVT_RING_SIZE) {
            s_evt_dequeue = 0;
            s_evt_cycle  ^= 1;
        }
        update_erdp();

        if (trb_type == XHCI_TRB_CMD_COMPLETION) {
            s_last_cmd_cc = cc;
            if (cc == 1u)
                return slot_id;
            printk("[XHCI] cmd_completion fail: cc=%u slot=%u\n",
                   (unsigned)cc, (unsigned)slot_id);
            return 0;
        }
        /* Other event types (port status change, etc.) — skip and keep
         * looking for the CMD_COMPLETION we issued. */
    }
    s_last_cmd_cc = 0xFFu;   /* timeout sentinel */
    printk("[XHCI] cmd_completion TIMEOUT\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Device enumeration helpers
 * ---------------------------------------------------------------------- */

/* issue_enable_slot — send Enable Slot command; return assigned slot_id
 * (1-based) or 0 on failure. */
static uint8_t
issue_enable_slot(void)
{
    enqueue_cmd(0, 0, (uint32_t)(XHCI_TRB_ENABLE_SLOT << 10));
    ring_cmd_doorbell();
    return poll_cmd_completion();
}

/* issue_disable_slot — send Disable Slot command for a slot.
 * Tells the controller to release internal slot resources. Should be
 * called when a device is disconnected, before software state cleanup. */
static void
issue_disable_slot(uint8_t slot_id)
{
    enqueue_cmd(0, 0,
                (uint32_t)(XHCI_TRB_DISABLE_SLOT << 10) |
                ((uint32_t)slot_id << 24));
    ring_cmd_doorbell();
    (void)poll_cmd_completion();
}

/* issue_address_device — build a minimal Input Context and issue Address
 * Device command for the given slot.
 *
 * Input Context layout (Input Control Ctx + Slot Ctx + EP0 Ctx):
 *   [0]  Input Control Context  (32B): Add A0(slot) + A1(EP0)
 *   [1]  Slot Context           (32B): Speed, ContextEntries=1, RootHubPort
 *   [2]  EP0 Context            (32B): CErr=3, EPType=Control, MaxPacketSize=8
 *
 * Returns 0 on success, -1 on failure. */
static int
issue_address_device(uint8_t slot_id, uint8_t port_num, uint8_t speed)
{
    uint64_t  ictx_phys;
    uint8_t  *ictx = (uint8_t *)alloc_page(&ictx_phys);

    /* Input Control Context: Drop=0, Add=0x3 (A0=slot + A1=EP0) */
    ((volatile uint32_t *)ictx)[0] = 0u;
    ((volatile uint32_t *)ictx)[1] = 0x3u;

    /* Slot Context (xHCI 1.0 §6.2.2):
     *   dword0: Route[19:0], Speed[23:20], MTT[25], Hub[26], ContextEntries[31:27]
     *   dword1: MaxExitLatency[15:0], RootHubPortNumber[23:16], NumberOfPorts[31:24]
     *   dword2: ParentHubSlotID[7:0], ParentPortNumber[15:8], TTThinkTime[17:16],
     *           InterrupterTarget[31:22]
     *   dword3: DeviceAddress[7:0], SlotState[31:27] (read-only)
     *
     * Previously wrote RootHubPortNumber to dword2[23:16] (wrong) instead
     * of dword1[23:16] — controller saw RootHubPortNumber=0 and treated
     * port_num as a Parent Hub address, returning cc=5 TRB Error. */
    {
        uint8_t *sc = ictx + XHCI_CTX_ENTRY_SIZE;
        ((volatile uint32_t *)sc)[0] =
            ((uint32_t)speed << 20) | (1u << 27);   /* speed + ContextEntries=1 */
        ((volatile uint32_t *)sc)[1] =
            (uint32_t)port_num << 16;               /* RootHubPortNumber */
    }

    /* EP0 Context at offset 2 * XHCI_CTX_ENTRY_SIZE.
     *
     * Endpoint Context layout (xHCI 1.0 §6.2.3):
     *   dword0: EPState[2:0] / Mult / MaxPStreams / LSA / Interval / MaxESITPayloadHi
     *   dword1: CErr[2:1], EPType[5:3], HID[7], MaxBurstSize[15:8], MaxPacketSize[31:16]
     *   dword2: DCS[0], reserved[3:1], TR Dequeue Pointer Lo[31:4]
     *   dword3: TR Dequeue Pointer Hi[31:0]
     *   dword4: AverageTRBLength[15:0], MaxESITPayloadLo[31:16]
     *
     * MaxPacketSize0 is speed-dependent per xHCI spec §4.3.4:
     *   LS=8, FS=8 (later updated), HS=64, SS=512.
     *
     * The previous version set ONLY dword1, leaving the TR Dequeue
     * Pointer at zero — Address Device "succeeded" structurally but
     * subsequent control transfers timed out because the controller
     * had no transfer ring to read commands from. */
    {
        uint16_t max_packet_size_0;
        uint64_t tr_phys;
        switch (speed) {
        case XHCI_SPEED_LS: max_packet_size_0 = 8;   break;
        case XHCI_SPEED_FS: max_packet_size_0 = 8;   break;
        case XHCI_SPEED_HS: max_packet_size_0 = 64;  break;
        case XHCI_SPEED_SS: max_packet_size_0 = 512; break;
        default:            max_packet_size_0 = 8;   break;
        }
        tr_phys = s_xfer_ring_phys[slot_id];

        uint8_t *ep0 = ictx + 2u * XHCI_CTX_ENTRY_SIZE;
        /* dword1: CErr=3, EPType=Control(4), MaxPacketSize */
        ((volatile uint32_t *)ep0)[1] =
            (3u << 1) | (XHCI_EP_TYPE_CTRL << 3) |
            ((uint32_t)max_packet_size_0 << 16);
        /* dword2: TR Dequeue Pointer Lo | DCS (= initial cycle = 1) */
        ((volatile uint32_t *)ep0)[2] =
            (uint32_t)(tr_phys & 0xFFFFFFF0u) |
            (uint32_t)s_xfer_cycle[slot_id];
        /* dword3: TR Dequeue Pointer Hi */
        ((volatile uint32_t *)ep0)[3] = (uint32_t)(tr_phys >> 32);
        /* dword4: Average TRB Length = 8 (control transfers are small) */
        ((volatile uint32_t *)ep0)[4] = 8u;
    }

    /* DCBAA[slot] must already point at a zeroed Output Device Context
     * (installed in enumerate_port before this call, xHCI §4.3.3 step 4).
     * The controller writes slot/endpoint state there; do NOT clear it. */

    enqueue_cmd(ictx_phys, 0,
                (uint32_t)(XHCI_TRB_ADDRESS_DEVICE << 10) |
                ((uint32_t)slot_id << 24));
    ring_cmd_doorbell();
    if (poll_cmd_completion() == 0)
        return -1;
    return 0;
}

/* issue_configure_ep — add EP1 IN to the slot's device context.
 *
 * Input Context layout:
 *   [0]  Input Control Context  (32B): Add A0(slot) + A3(EP1IN DCI=3)
 *   [1]  Slot Context           (32B): Speed, ContextEntries=3, RootHubPort
 *   [2]  EP0 Context            (32B): zeroed (not re-adding EP0)
 *   [3]  EP1 OUT Context        (32B): zeroed (not used)
 *   [4]  EP1 IN  Context        (32B): EPType=INT_IN, MaxPktSize=8, TR ptr
 *
 * The EP1 IN context is at xHCI DCI=3, which maps to Input Context index 3
 * (after Input Control + Slot = indices 0/1 in the driver-local naming).
 * In bytes: offset = (DCI + 1) * 32 = 4 * 32 = 128.
 *
 * Returns 0 on success, -1 on failure. */
static int
issue_configure_ep(uint8_t slot_id, uint8_t port_num, uint8_t speed)
{
    uint64_t  ictx_phys;
    uint8_t  *ictx = (uint8_t *)alloc_page(&ictx_phys);
    uint64_t  xfer_phys = s_xfer_ring_phys[slot_id];

    /* Input Control Context: Add A0(slot bit0) + A3(EP1IN DCI=3, bit3) = 0x9 */
    ((volatile uint32_t *)ictx)[0] = 0u;
    ((volatile uint32_t *)ictx)[1] = 0x9u;

    /* Slot Context: copy the CURRENT device slot context (set up by Address
     * Device: device address, slot state, speed, port) and only bump Context
     * Entries to 3 (highest DCI in use = EP1 IN). Building it from scratch left
     * the address/state fields zero, which the strict Synopsys dwc3 (RP1)
     * rejects with cc=17 (lenient x86 xHCIs accepted it). */
    {
        uint8_t *sc = ictx + XHCI_CTX_ENTRY_SIZE;
        (void)speed; (void)port_num;
        __builtin_memcpy((void *)sc, (const void *)s_dev_ctx[slot_id],
                         XHCI_CTX_ENTRY_SIZE);
        uint32_t d0 = ((volatile uint32_t *)sc)[0];
        d0 = (d0 & ~(0x1Fu << 27)) | (3u << 27);   /* Context Entries = 3 */
        ((volatile uint32_t *)sc)[0] = d0;
    }

    /* EP1 IN Context at byte offset (DCI+1) * ctx_size = 4 * ctx_size.
     *
     * Interval field encoding (xHCI 1.0 §6.2.3.6):
     *   LS/FS interrupt: bInterval direct (1-255 ms)
     *   HS interrupt:    2^(bInterval-1) × 125us
     * For our LS K120 (bInterval=10), Interval=10 (0xA) = 10ms polling.
     *
     * MaxPacketSize is set to 64 even though boot keyboards declare 8,
     * so the controller doesn't fire cc=3 (Babble) if the device sends
     * a slightly oversized packet. K120 in practice sends 8 but the
     * controller validates against the EP context value, not the
     * descriptor value. */
    {
        uint8_t *ep1in = ictx + 4u * XHCI_CTX_ENTRY_SIZE;
        /* Low-Speed endpoints max out at 8-byte packets; the strict Synopsys
         * dwc3 (RP1) rejects the x86 anti-Babble MaxPacketSize=64 for a LS
         * device with cc=17. Size it to the port speed (boot keyboards send 8). */
        uint32_t mps = (speed == XHCI_SPEED_LS) ? 8u : 64u;
        /* dword0: Interval[23:16]. xHCI FS/LS interrupt period = 2^Interval ×
         * 125µs, so 6 = 8ms (~125 Hz) — the standard USB mouse/keyboard poll
         * rate. (The old 0xA was mislabeled "10ms" but is actually 2^10×125µs =
         * 128ms ≈ 8 Hz, which made the pointer visibly laggy.) */
        ((volatile uint32_t *)ep1in)[0] = (0x6u << 16);
        /* dword1: CErr=3, EPType=INT_IN(7), MaxPacketSize */
        ((volatile uint32_t *)ep1in)[1] =
            (3u << 1) | (XHCI_EP_TYPE_INT_IN << 3) | (mps << 16);
        /* dword2/3: TR Dequeue Pointer [63:4] | DCS (dequeue cycle state).
         * The interrupt EP shares EP0's transfer ring, so point its dequeue at
         * the CURRENT enqueue slot — where xhci_schedule_interrupt_in will place
         * the first interrupt TRB — NOT the ring base (offset 0), which still
         * holds a stale, already-consumed control TRB from enumeration. The
         * strict RP1 dwc3 executes whatever the dequeue points at: aimed at the
         * base it fetched that stale Setup-Stage TRB and never ran the interrupt
         * transfer, so no completion event was ever generated and no HID report
         * reached the CPU. (Lenient x86/QEMU xHCIs re-read and masked this.)
         * Caller guarantees no EP0 traffic runs between here and the first
         * xhci_schedule_interrupt_in, so this snapshot stays valid. */
        uint64_t int_deq = xfer_phys +
            (uint64_t)s_xfer_enqueue[slot_id] * sizeof(xhci_trb_t);
        ((volatile uint32_t *)ep1in)[2] =
            (uint32_t)(int_deq & 0xFFFFFFF0u) |
            (uint32_t)s_xfer_cycle[slot_id];
        ((volatile uint32_t *)ep1in)[3] = (uint32_t)(int_deq >> 32);
        /* dword4: Max ESIT Payload [31:16] | Average TRB Length [15:0].
         * The Synopsys dwc3 (RP1) validates Max ESIT Payload and rejects a
         * zero with cc=17 (Parameter Error); = MaxPacketSize * (burst+1) *
         * (mult+1) = MaxPacketSize. (Lenient x86 xHCIs accept 0, which is why
         * this was invisible until real Pi 5 hardware.) */
        ((volatile uint32_t *)ep1in)[4] = (mps << 16) | 8u;
    }

    enqueue_cmd(ictx_phys, 0,
                (uint32_t)(XHCI_TRB_CONFIGURE_EP << 10) |
                ((uint32_t)slot_id << 24));
    ring_cmd_doorbell();
    if (poll_cmd_completion() == 0)
        return -1;
    return 0;
}

/* -------------------------------------------------------------------------
 * Control transfer helpers for device enumeration
 * ---------------------------------------------------------------------- */

/* issue_control_transfer — send a SETUP + DATA(IN) + STATUS(OUT) sequence on
 * EP0 (DCI=1) for the given slot.  The 8-byte response lands in
 * s_hid_buf[slot_id].  Returns bytes transferred or -1 on error.
 *
 * setup_pkt: the 8-byte USB setup packet encoded as a uint64_t:
 *   bits [7:0]   = bmRequestType
 *   bits [15:8]  = bRequest
 *   bits [31:16] = wValue
 *   bits [47:32] = wIndex
 *   bits [63:48] = wLength
 *
 * For a no-data transfer (wLength==0), pass only SETUP + STATUS (no DATA
 * stage); the STATUS direction is IN for host-to-device transfers and OUT
 * for device-to-host transfers (opposite of data direction). */
static int
issue_control_transfer(uint8_t slot_id, uint64_t setup_pkt, int data_dir)
{
    /* data_dir: 0 = no data stage, 1 = IN (device->host), 2 = OUT (host->device).
     * The data buffer is always s_hid_buf[slot_id]; OUT callers fill it first. */
    xhci_trb_t *ring  = s_xfer_ring[slot_id];
    uint32_t    cycle = (uint32_t)s_xfer_cycle[slot_id];
    uint32_t    ei    = s_xfer_enqueue[slot_id];
    uint16_t    wlen  = (uint16_t)(setup_pkt >> 48);
    volatile uint32_t *db;
    volatile xhci_trb_t *evt;
    uint64_t deadline;

    if (!ring || !s_hid_buf[slot_id])
        return -1;

    /* --- Setup TRB: type=2, IDT=1(bit6), TRT=3(IN, bits17:16), len=8 --- */
    {
        xhci_trb_t *trb = &ring[ei];
        trb->param   = setup_pkt;
        trb->status  = 8u;                                /* setup packet length */
        trb->control = (uint32_t)(XHCI_TRB_SETUP << 10)  /* type */
                     | (1u << 6)                           /* IDT (Immediate Data) */
                     | (data_dir == 1 ? (3u << 16)         /* TRT: 3=IN data */
                        : data_dir == 2 ? (2u << 16)       /* TRT: 2=OUT data */
                        : 0u)                              /* TRT: 0=No data */
                     | cycle;
        ei++;
        if (ei >= XHCI_TRANSFER_RING_SIZE - 1u) {
            /* Link TRB keeps the CURRENT lap's cycle (matches idx 0..62); its
             * Toggle Cycle bit flips the consumer cycle on traversal. Flip our
             * producer cycle AFTER stamping the link — see msc_bulk_one. */
            ring[XHCI_TRANSFER_RING_SIZE - 1].control =
                (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | cycle;
            s_xfer_cycle[slot_id] ^= 1;
            ei = 0;
            cycle = (uint32_t)s_xfer_cycle[slot_id];
        }
    }

    /* --- Data TRB (only if there is a data stage) --- */
    if (data_dir != 0 && wlen > 0) {
        xhci_trb_t *trb = &ring[ei];
        trb->param   = s_hid_buf_phys[slot_id];
        trb->status  = (uint32_t)wlen;
        trb->control = (uint32_t)(XHCI_TRB_DATA << 10)
                     | (data_dir == 1 ? (1u << 16) : 0u)   /* DIR: 1=IN, 0=OUT */
                     | cycle;
        ei++;
        if (ei >= XHCI_TRANSFER_RING_SIZE - 1u) {
            /* Link TRB keeps the CURRENT lap's cycle (matches idx 0..62); its
             * Toggle Cycle bit flips the consumer cycle on traversal. Flip our
             * producer cycle AFTER stamping the link — see msc_bulk_one. */
            ring[XHCI_TRANSFER_RING_SIZE - 1].control =
                (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | cycle;
            s_xfer_cycle[slot_id] ^= 1;
            ei = 0;
            cycle = (uint32_t)s_xfer_cycle[slot_id];
        }
    }

    /* --- Status TRB --- */
    {
        xhci_trb_t *trb = &ring[ei];
        trb->param   = 0;
        trb->status  = 0;
        /* Status direction is opposite of data direction:
         *   IN data  → OUT status (DIR=0)
         *   No data (host-to-device setup) → IN status (DIR=1) */
        trb->control = (uint32_t)(XHCI_TRB_STATUS << 10)
                     | (1u << 5)                           /* IOC */
                     | (data_dir == 1 ? 0u : (1u << 16))   /* IN data->OUT status; else IN */
                     | cycle;
        ei++;
        if (ei >= XHCI_TRANSFER_RING_SIZE - 1u) {
            /* Link TRB keeps the CURRENT lap's cycle (matches idx 0..62); its
             * Toggle Cycle bit flips the consumer cycle on traversal. Flip our
             * producer cycle AFTER stamping the link — see msc_bulk_one. */
            ring[XHCI_TRANSFER_RING_SIZE - 1].control =
                (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | cycle;
            s_xfer_cycle[slot_id] ^= 1;
            ei = 0;
            cycle = (uint32_t)s_xfer_cycle[slot_id];
        }
    }

    s_xfer_enqueue[slot_id] = ei;

    /* Ring doorbell for EP0 (DCI=1) */
    db = (volatile uint32_t *)(s_bar0_va + s_cap->dboff);
    arch_wmb();
    db[slot_id] = 1u;   /* DCI=1 for EP0 */

    /* DIAG: post-doorbell controller + event-ring pointer state */
    printk("[XHCI] ctrl post-db: usbsts=0x%x evt_deq=%u evt_cyc=%u wlen=%u\n",
           (unsigned)op_read32(XHCI_OP_USBSTS_OFF),
           (unsigned)s_evt_dequeue, (unsigned)s_evt_cycle, (unsigned)wlen);

    /* Poll for Transfer Event completion. Skip non-transfer events
     * (port status changes, leftover CMD_COMPLETIONs from earlier
     * commands, etc.) instead of bailing — same fix as
     * poll_cmd_completion's PSC skip. */
    /* Wait up to 1s (TSC-based, CPU-speed-independent). A passed-through
     * real device answers via async usb-host (several ms); an emulated
     * device answers near-instantly. A tight iteration count is NOT enough
     * for real silicon — it expires before the libusb round-trip lands. */
    deadline = xhci_rdtsc() + 1000ULL * s_cycles_per_ms;
    while (xhci_rdtsc() < deadline) {
        evt = &s_evt_ring[s_evt_dequeue];
        if ((evt->control & 1u) != (uint32_t)s_evt_cycle) {
            xhci_relax();
            continue;
        }

        {
            uint32_t ctrl     = evt->control;
            uint32_t etype    = (ctrl >> 10) & 0x3Fu;
            uint8_t  cc       = (uint8_t)((evt->status >> 24) & 0xFFu);
            uint32_t residual = evt->status & 0xFFFFFFu;

            s_evt_dequeue++;
            if (s_evt_dequeue >= XHCI_EVT_RING_SIZE) {
                s_evt_dequeue = 0;
                s_evt_cycle  ^= 1;
            }
            update_erdp();

            if (etype == XHCI_TRB_TRANSFER_EVENT) {
                s_last_ctrl_cc = cc;
                if (cc == 1u || cc == 13u) {
                    /* cc=1: Success, cc=13: Short Packet (normal) */
                    return (int)((uint32_t)wlen - residual);
                }
                printk("[XHCI] ctrl_xfer transfer event cc=%u\n",
                       (unsigned)cc);
                return -1;
            }
            /* Other event types (PSC, leftover CMD_COMPLETION) — skip */
            printk("[XHCI] ctrl_xfer skip etype=%u\n", (unsigned)etype);
        }
    }
    printk("[XHCI] ctrl_xfer TIMEOUT usbsts=0x%x evt_deq=%u evt_cyc=%u\n",
           (unsigned)op_read32(XHCI_OP_USBSTS_OFF),
           (unsigned)s_evt_dequeue, (unsigned)s_evt_cycle);
    /* DIAG: scan whole event ring for what the controller actually posted */
    {
        uint32_t k;
        for (k = 0; k < XHCI_EVT_RING_SIZE; k++) {
            if (s_evt_ring[k].control != 0u || s_evt_ring[k].status != 0u)
                printk("[XHCI]   evt[%u] type=%u cc=%u cyc=%u ctrl=0x%x sts=0x%x\n",
                       (unsigned)k,
                       (unsigned)((s_evt_ring[k].control >> 10) & 0x3Fu),
                       (unsigned)((s_evt_ring[k].status >> 24) & 0xFFu),
                       (unsigned)(s_evt_ring[k].control & 1u),
                       (unsigned)s_evt_ring[k].control,
                       (unsigned)s_evt_ring[k].status);
        }
    }
    /* DIAG: output device context (EP0 state/dequeue) + the TRBs we enqueued */
    if (s_dev_ctx[slot_id]) {
        volatile uint32_t *sc  = (volatile uint32_t *)s_dev_ctx[slot_id];
        volatile uint32_t *ep0 = (volatile uint32_t *)
            (s_dev_ctx[slot_id] + XHCI_CTX_ENTRY_SIZE);
        printk("[XHCI]   octx slot d0=0x%x d3=0x%x(state=%u) | ep0 d0=0x%x(state=%u) d1=0x%x deq=0x%x:%x\n",
               (unsigned)sc[0], (unsigned)sc[3], (unsigned)(sc[3] >> 27),
               (unsigned)ep0[0], (unsigned)(ep0[0] & 7u),
               (unsigned)ep0[1], (unsigned)ep0[3], (unsigned)ep0[2]);
    }
    printk("[XHCI]   usbcmd=0x%x ring_pa=0x%x tr[0]c=0x%x s=0x%x p=0x%x tr[1]c=0x%x tr[2]c=0x%x\n",
           (unsigned)op_read32(XHCI_OP_USBCMD_OFF),
           (unsigned)s_xfer_ring_phys[slot_id],
           (unsigned)ring[0].control, (unsigned)ring[0].status,
           (unsigned)ring[0].param,
           (unsigned)ring[1].control, (unsigned)ring[2].control);
    s_last_ctrl_cc = 0xFFu;   /* timeout */
    return -1;
}

/* detect_hid_protocol — issue GET_DESCRIPTOR(Configuration) and walk the
 * returned descriptor chain for an Interface Descriptor (type=4) with
 * bInterfaceClass=3 (HID).  Returns bInterfaceProtocol:
 *   1 = keyboard, 2 = mouse, 0 = unknown/not HID. */
static uint8_t
detect_hid_protocol(uint8_t slot_id)
{
    /* GET_DESCRIPTOR: bmRequestType=0x80 (Device-to-Host, Standard, Device),
     * bRequest=6 (GET_DESCRIPTOR), wValue=0x0200 (Configuration, index 0),
     * wIndex=0, wLength=64 */
    uint64_t setup = (uint64_t)0x80u          /* bmRequestType */
                   | ((uint64_t)0x06u << 8)   /* bRequest */
                   | ((uint64_t)0x0200u << 16) /* wValue: Config desc, idx 0 */
                   | ((uint64_t)0u << 32)      /* wIndex */
                   | ((uint64_t)64u << 48);    /* wLength */
    int got;
    uint8_t *buf;
    int off;

    got = issue_control_transfer(slot_id, setup, 1);
    printk("[XHCI] slot %u GET_DESCRIPTOR(Config) got=0x%x\n",
           (unsigned)slot_id, (unsigned)got);
    if (got < 4)
        return 0;

    buf = s_hid_buf[slot_id];
    /* Dump 36 bytes of config descriptor — enough to see config + iface 0
     * + HID descriptor + EP1 IN endpoint descriptor for the boot kbd. */
    printk("[XHCI] cfg desc 0-15: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
           (unsigned)buf[0],  (unsigned)buf[1],  (unsigned)buf[2],  (unsigned)buf[3],
           (unsigned)buf[4],  (unsigned)buf[5],  (unsigned)buf[6],  (unsigned)buf[7],
           (unsigned)buf[8],  (unsigned)buf[9],  (unsigned)buf[10], (unsigned)buf[11],
           (unsigned)buf[12], (unsigned)buf[13], (unsigned)buf[14], (unsigned)buf[15]);
    printk("[XHCI] cfg desc 16-31: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
           (unsigned)buf[16], (unsigned)buf[17], (unsigned)buf[18], (unsigned)buf[19],
           (unsigned)buf[20], (unsigned)buf[21], (unsigned)buf[22], (unsigned)buf[23],
           (unsigned)buf[24], (unsigned)buf[25], (unsigned)buf[26], (unsigned)buf[27],
           (unsigned)buf[28], (unsigned)buf[29], (unsigned)buf[30], (unsigned)buf[31]);

    /* Walk the descriptor chain */
    off = 0;
    while (off + 2 <= got) {
        uint8_t blen  = buf[off];
        uint8_t btype = buf[off + 1];

        if (blen < 2 || off + blen > got)
            break;

        /* Interface Descriptor: bDescriptorType=4, bLength>=9 */
        if (btype == 4u && blen >= 9u) {
            uint8_t bclass = buf[off + 5];   /* bInterfaceClass */
            uint8_t bproto = buf[off + 7];   /* bInterfaceProtocol */
            if (bclass == 3u)                /* HID class */
                return bproto;               /* 1=kbd, 2=mouse */
        }
        off += blen;
    }
    return 0;
}

/* ---- USB Ethernet (ASIX AX88179 / AX88179A) -------------------------- */

/* Single USB ethernet device state. The AX88179 presents a vendor-specific
 * configuration (class 0xFF) with bulk IN/OUT endpoints; probe_usb_ethernet
 * records what it discovers so the bulk + driver paths can use it. */
typedef struct {
    int      present;
    int      configured;      /* bulk endpoints set up + netdev registered */
    uint8_t  slot_id;
    uint8_t  port_num;
    uint8_t  speed;
    uint8_t  bulk_in_addr;    /* 0x8N */
    uint8_t  bulk_out_addr;   /* 0x0N */
    uint8_t  bulk_in_dci;     /* 2*N+1 */
    uint8_t  bulk_out_dci;    /* 2*N   */
    uint16_t bulk_in_mps;     /* wMaxPacketSize (1024 @ SuperSpeed) */
    uint16_t bulk_out_mps;
    uint8_t  bulk_in_burst;   /* SS EP Companion bMaxBurst (0-based) — REQUIRED for SS bulk */
    uint8_t  bulk_out_burst;
    uint8_t  mac[6];

    /* Interrupt IN endpoint (link-status notifications). The AX88179A's PHY is
     * an integrated firmware-managed GPHY whose MDIO (AX_ACCESS_PHY) NAKs forever
     * on UA2 silicon, so — exactly like mainline Linux ax88179_status — we learn
     * link up/down from this endpoint's 8-byte report (intdata1 bit 16) instead. */
    uint8_t  int_addr;        /* 0x8N, 0 if none */
    uint8_t  int_dci;         /* 2*N+1 */
    uint16_t int_mps;
    xhci_trb_t *int_ring;  uint64_t int_ring_phys;  uint32_t int_enq;  uint32_t int_cycle;
    uint8_t  *int_buf;     uint64_t int_buf_phys;
    uint8_t   int_armed;      /* interrupt IN endpoint configured + armed */
    uint8_t   link_up_intr;   /* last link state from the interrupt endpoint */
    uint8_t   link_change_pending; /* INT EP saw link-up; run link_reset in poll */
    uint16_t  det_speed;      /* MDIO-free detected link speed (0/100/1000 Mb/s) */
    uint16_t  med_gig_rb;     /* MEDIUM readback after a gigabit probe write */
    uint16_t  med_100_rb;     /* MEDIUM readback after a 100M probe write */
    uint32_t  int_count;      /* interrupt-IN completions seen */
    uint32_t  intdata1;       /* last interrupt report dword 0 (link bit = 1<<16) */
    uint32_t  intdata2;       /* last interrupt report dword 1 */

    /* Bulk transfer rings (one each), per-ring enqueue + producer cycle. */
    xhci_trb_t *in_ring;   uint64_t in_ring_phys;   uint32_t in_enq;   uint32_t in_cycle;
    xhci_trb_t *out_ring;  uint64_t out_ring_phys;  uint32_t out_enq;  uint32_t out_cycle;

    /* DMA buffers (<4GB). rx is re-armed continuously; tx is single-frame. */
    uint8_t  *rx_buf;  uint64_t rx_buf_phys;  uint32_t rx_buf_len;
    uint8_t  *tx_buf;  uint64_t tx_buf_phys;
    int       tx_inflight;
    uint64_t  tx_deadline;   /* TSC; reclaim tx_inflight past this (lost completion) */

    /* Live diagnostics (surfaced via /proc/usbnet — see xhci_usbnet_diag). */
    uint8_t   link_up;
    uint8_t   link_reset_done;
    uint16_t  link_physr;
    uint16_t  link_bmsr;
    uint16_t  medium_rb;     /* MEDIUM_STATUS_MODE read-back (RECEIVE_EN=0x100) */
    uint16_t  rxctl_rb;      /* RX_CTL read-back (START=0x80) */
    uint8_t   plink_rb;      /* PHYSICAL_LINK_STATUS read-back (USB speed bits) */
    uint8_t   genstat_rb;    /* GENERAL_STATUS (AX_SECLD=0x04: set=UA2, clear=UA1) */
    uint16_t  bcd_device;    /* device bcdDevice (>=0x0200 = AX88179A) */
    uint8_t   phy_cc;        /* completion code of a failed MDIO read (4=txn,6=stall,0xFF=timeout) */
    uint32_t  rx_count;     /* bulk-IN URBs completed */
    uint32_t  rx_frames;    /* Ethernet frames delivered to the stack */
    uint32_t  rx_bytes;
    uint32_t  last_rx_len;
    uint32_t  tx_count;     /* bulk-OUT URBs submitted */
    uint32_t  tx_done;      /* bulk-OUT URBs completed (event received) */
    uint8_t   registered;   /* netdev registered */

    netdev_t  nd;
} usb_eth_dev_t;

static usb_eth_dev_t s_eth;

/* Guards the bulk-OUT (TX) ring + doorbell in usb_eth_send (process context)
 * against the PIT-ISR xhci_poll. irqsave disables interrupts during the short
 * critical section, so on single-core the ISR cannot interleave. */
static spinlock_t s_eth_tx_lock = SPINLOCK_INIT;

/* netdev RX-in-ISR flag: when set, arp_resolve takes its non-blocking path.
 * xhci_poll is NOT called from netdev_poll_all (which normally sets this), so
 * the USB RX-deliver path must set it itself or an un-cached reply would spin
 * the blocking ARP wait inside the timer ISR. Defined in net/netdev.c. */
extern volatile int g_in_netdev_poll;

/* Last non-HID USB device probed (claimed or not) — for /proc/usbnet so an
 * unsupported adapter can be identified by VID/PID. */
static uint8_t  s_probe_saw;
static uint16_t s_probe_vid;
static uint16_t s_probe_pid;

/* xHCI host-controller discovery diagnostics (see /proc/usbnet). Populated by
 * xhci_init; read live (port state) by xhci_host_diag. */
#define XHCI_HDIAG_MAX 8
static struct {
    uint8_t  bus, dev, fn;
    uint16_t vendor, device;
    int8_t   result;   /* 1=adopted, 0=empty, -1=fail */
} s_hdiag[XHCI_HDIAG_MAX];
static uint8_t s_hdiag_count;
static uint8_t s_hdiag_total;
static int8_t  s_hdiag_adopted = -1;

/* Per-root-port enumeration progress (how far enumerate_port got) — for
 * /proc/usbnet, so a serial-less laptop can see exactly where a device stalls. */
#define XHCI_ENUM_NONE      0u  /* not enumerated / no connect */
#define XHCI_ENUM_RESET_TO  1u  /* port reset timed out */
#define XHCI_ENUM_SLOT_FAIL 2u  /* Enable Slot failed */
#define XHCI_ENUM_ADDR_FAIL 3u  /* Address Device failed */
#define XHCI_ENUM_CFG_FAIL  4u  /* Configure Endpoint failed (HID) */
#define XHCI_ENUM_HID_OK    5u  /* HID device ready */
#define XHCI_ENUM_PROBED    6u  /* non-HID → handed to usb-ethernet probe */
/* s_enum_stage / s_enum_cc / s_enum_usbsts are now per-controller fields in
 * struct xhci_ctrl (see the s_* macros near the top). */

void
xhci_host_diag(xhci_host_diag_t *out)
{
    uint32_t i;
    if (!out) return;
    out->total_controllers = s_hdiag_total;
    out->adopted_index     = s_hdiag_adopted;
    out->count             = s_hdiag_count;
    for (i = 0; i < s_hdiag_count && i < 8u; i++) {
        out->ctrl[i].bus    = s_hdiag[i].bus;
        out->ctrl[i].dev    = s_hdiag[i].dev;
        out->ctrl[i].fn     = s_hdiag[i].fn;
        out->ctrl[i].vendor = s_hdiag[i].vendor;
        out->ctrl[i].device = s_hdiag[i].device;
        out->ctrl[i].result = s_hdiag[i].result;
    }
    out->adopted_max_ports = 0;
    for (i = 0; i <= (uint32_t)XHCI_DIAG_MAX_PORTS; i++) {
        out->port[i] = 0;
        out->enum_stage[i] = (i <= XHCI_MAX_PORTS) ? s_enum_stage[i] : 0u;
        out->enum_cc[i]    = (i <= XHCI_MAX_PORTS) ? s_enum_cc[i]    : 0u;
        out->is_usb3[i]    = (i <= XHCI_MAX_PORTS) ? s_port_is_usb3[i] : 0u;
        out->enum_usbsts[i]= (i <= XHCI_MAX_PORTS) ? s_enum_usbsts[i] : 0u;
    }
    /* Live-read the adopted controller's PORTSC array (read-only, no RW1C). */
    if (s_op && s_hdiag_adopted >= 0) {
        uint8_t *op_base = (uint8_t *)s_op;
        uint32_t mp = s_max_ports;
        if (mp > (uint32_t)XHCI_DIAG_MAX_PORTS) mp = (uint32_t)XHCI_DIAG_MAX_PORTS;
        out->adopted_max_ports = (uint8_t)mp;
        for (i = 1; i <= mp; i++) {
            volatile uint32_t *psc =
                (volatile uint32_t *)(op_base + 0x400u + (i - 1u) * 16u);
            out->port[i] = *psc;
        }
    }
}

/* ---- ASIX vendor register helpers (see docs/ax88179-driver-spec.md) ---- */

/* ax_write_mac — AX_ACCESS_MAC (0x01) write: `len` LE bytes of `val` to `reg`.
 * SETUP = 40 01 <reg> 00 <len> 00 <len> 00, then OUT `len` bytes. */
static void
ax_write_mac(uint8_t slot, uint8_t reg, uint8_t len, uint32_t val)
{
    uint8_t *buf = s_hid_buf[slot];
    uint64_t setup;
    int i;
    for (i = 0; i < len; i++)
        buf[i] = (uint8_t)(val >> (8 * i));
    setup = (uint64_t)0x40u | ((uint64_t)0x01u << 8)
          | ((uint64_t)reg << 16) | ((uint64_t)len << 32) | ((uint64_t)len << 48);
    issue_control_transfer(slot, setup, 2);
}

/* ax_write_mac_buf — AX_ACCESS_MAC write of `len` bytes from a byte array. */
static void
ax_write_mac_buf(uint8_t slot, uint8_t reg, uint8_t len, const uint8_t *data)
{
    uint8_t *buf = s_hid_buf[slot];
    uint64_t setup;
    int i;
    for (i = 0; i < len; i++)
        buf[i] = data[i];
    setup = (uint64_t)0x40u | ((uint64_t)0x01u << 8)
          | ((uint64_t)reg << 16) | ((uint64_t)len << 32) | ((uint64_t)len << 48);
    issue_control_transfer(slot, setup, 2);
}

/* ax_read_mac — AX_ACCESS_MAC read: `len` LE bytes from `reg` into a uint32. */
static uint32_t
ax_read_mac(uint8_t slot, uint8_t reg, uint8_t len)
{
    uint8_t *buf = s_hid_buf[slot];
    uint64_t setup;
    uint32_t v = 0;
    int i;
    setup = (uint64_t)0xC0u | ((uint64_t)0x01u << 8)
          | ((uint64_t)reg << 16) | ((uint64_t)len << 32) | ((uint64_t)len << 48);
    if (issue_control_transfer(slot, setup, 1) < 0)
        return 0;
    for (i = 0; i < len; i++)
        v |= (uint32_t)buf[i] << (8 * i);
    return v;
}

/* ax_phy_read/write — AX_ACCESS_PHY (0x02), phy_id 0x03, 16-bit register.
 * ax_phy_read is unused now that link/speed come from the interrupt EP +
 * MEDIUM stick-test (MDIO is dead on this UA2 silicon); kept for diagnostics
 * and non-UA2 adapters. */
static uint16_t __attribute__((unused))
ax_phy_read(uint8_t slot, uint8_t reg)
{
    uint8_t *buf = s_hid_buf[slot];
    uint64_t setup = (uint64_t)0xC0u | ((uint64_t)0x02u << 8)
          | ((uint64_t)0x03u << 16) | ((uint64_t)reg << 32) | ((uint64_t)2u << 48);
    int attempt;
    /* Retry: a PHY access makes the adapter run a slow internal MDIO cycle and
     * NAK meanwhile; an over-eager completion could bail before the data lands. */
    for (attempt = 0; attempt < 4; attempt++) {
        if (issue_control_transfer(slot, setup, 1) >= 0)
            return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
        s_eth.phy_cc = s_last_ctrl_cc;   /* record WHY MDIO failed (STALL/txn/timeout) */
        xhci_busy_wait_ms(3);
    }
    return 0xDEADu;   /* sentinel: AX_ACCESS_PHY control transfer FAILED */
}

static void
ax_phy_write(uint8_t slot, uint8_t reg, uint16_t val)
{
    uint8_t *buf = s_hid_buf[slot];
    uint64_t setup;
    buf[0] = (uint8_t)val;
    buf[1] = (uint8_t)(val >> 8);
    setup = (uint64_t)0x40u | ((uint64_t)0x02u << 8)
          | ((uint64_t)0x03u << 16) | ((uint64_t)reg << 32) | ((uint64_t)2u << 48);
    issue_control_transfer(slot, setup, 2);
}

/* ax_phy_read2 — like ax_phy_read but with an explicit PHY address (for scan). */
static uint16_t __attribute__((unused))
ax_phy_read2(uint8_t slot, uint8_t phy_id, uint8_t reg)
{
    uint8_t *buf = s_hid_buf[slot];
    uint64_t setup = (uint64_t)0xC0u | ((uint64_t)0x02u << 8)
          | ((uint64_t)phy_id << 16) | ((uint64_t)reg << 32) | ((uint64_t)2u << 48);
    if (issue_control_transfer(slot, setup, 1) < 0)
        return 0xFFFFu;
    return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
}

/* ax88179_reset — the mainline ax88179_reset() write sequence (spec §3B).
 * Brings the MAC to RX-enabled; the embedded PHY autonegotiates. Runs in boot
 * enumeration context, so the 500/200ms PHY settle delays are one-time. */
static void
ax88179_reset(uint8_t slot)
{
    static const uint8_t bulkin_ss[5] = {0x07, 0x4f, 0x00, 0x12, 0xff};

    ax_write_mac(slot, 0x26, 2, 0x0000);          /* PHYPWR_RSTCTL: power down   */
    ax_write_mac(slot, 0x26, 2, 0x0020);          /* PHYPWR_RSTCTL: IPRL release */
    xhci_busy_wait_ms(500);
    ax_write_mac(slot, 0x33, 1, 0x03);            /* CLK_SELECT: ACS|BCS         */
    xhci_busy_wait_ms(200);

    /* AX88179A (bcdDevice >= 0x0200) boots in a NATIVE firmware mode whose
     * vendor-command plane differs: AX_ACCESS_PHY (MDIO) is rejected and the RX
     * header layout is larger/incompatible with our §6 parser. Force it into
     * 178A/179 legacy-compat mode (exactly as FreeBSD axge_chip_init does for
     * 179A). Dedicated vendor cmd: bmRequestType=0x40, bRequest=0x08(FW_MODE),
     * wValue=0x0000(178A179), wIndex=0x0001, 1 data byte = 0x00. */
    if (s_eth.bcd_device >= 0x0200u) {
        s_hid_buf[slot][0] = 0x00;
        uint64_t fw = (uint64_t)0x40u | ((uint64_t)0x08u << 8)
              | ((uint64_t)0x0000u << 16) | ((uint64_t)0x0001u << 32)
              | ((uint64_t)0x0001u << 48);
        (void)issue_control_transfer(slot, fw, 2);
        xhci_busy_wait_ms(50);
    }

    ax_write_mac_buf(slot, 0x2e, 5, bulkin_ss);   /* RX_BULKIN_QCTRL idx0        */
    ax_write_mac(slot, 0x55, 1, 0x34);            /* PAUSE_WATERLVL_LOW          */
    ax_write_mac(slot, 0x54, 1, 0x52);            /* PAUSE_WATERLVL_HIGH         */
    ax_write_mac(slot, 0x34, 1, 0x67);            /* RXCOE_CTL                   */
    ax_write_mac(slot, 0x35, 1, 0x67);            /* TXCOE_CTL                   */
    /* RX_CTL: DROPCRCERR(0x100)|IPE(0x200)|START(0x80)|AP(0x20)|AMALL(0x02)|AB(0x08)
     * = 0x03AA. The old 0x039A had AM(0x10) instead of AP(0x20): without AP the
     * MAC drops UNICAST frames addressed to us (DHCP OFFER/ACK, all replies) — a
     * key reason RX looked dead. AM is useless here (no multicast hash table). */
    ax_write_mac(slot, 0x0b, 2, 0x03AA);
    ax_write_mac(slot, 0x24, 1, 0x64);            /* MONITOR_MOD                 */
    /* MEDIUM = full gigabit-full-duplex, RX-enabled (the COMPLETE static config
     * so RX flows without a runtime link_reset; MDIO is dead on this UA2 chip
     * and link_reset from the ISR is unsafe). 0x013B =
     * RECEIVE_EN(0x100)|TXFLOW(0x20)|RXFLOW(0x10)|EN_125MHZ(0x08)|FD(0x02)|GIGA(0x01).
     * The earlier 0x0133 OMITTED EN_125MHZ — gigabit mode needs GIGA|EN_125MHZ,
     * so RX was never actually enabled at gigabit. RX_BULKIN_QCTRL was already
     * set to the gigabit-SS profile above. */
    ax_write_mac(slot, 0x22, 2, 0x013B);          /* MEDIUM_STATUS_MODE: gig-FD  */

    /* Power the embedded PHY/LED rail on "UA1" silicon — mainline does this in
     * ax88179_led_setting (ax88179_178a.c:1114-1119): read GENERAL_STATUS, and
     * if AX_SECLD(0x04) is CLEAR (UA1), enable GPIO1/2/3 (AX_GPIO_CTRL=0xE0).
     * WITHOUT this the PHY stays unpowered → MDIO reads return 0x0000 (MAC regs
     * still work) → no link → no RX. This is the step our driver was missing. */
    {
        uint8_t gs = (uint8_t)ax_read_mac(slot, 0x03, 1);   /* GENERAL_STATUS */
        s_eth.genstat_rb = gs;
        if (!(gs & 0x04u))                                   /* UA1 */
            ax_write_mac(slot, 0x25, 1, 0xE0u);              /* GPIO1/2/3 EN */
    }

    ax_phy_write(slot, 0x00, 0x1200);             /* BMCR: ANENABLE|ANRESTART    */
}

/* ax88179_link_reset — on link-up, program RX_BULKIN_QCTRL + MEDIUM_STATUS_MODE
 * for the negotiated speed/duplex (spec §3 link_reset). The AX88179 does NOT
 * deliver RX frames until this runs for the actual line rate. physr = GMII
 * PHYSR (0x11): speed in bits 0xC000 (gig/100/10), full-duplex in 0x2000.
 * Currently unused (speed is set statically in probe — MDIO/runtime link_reset
 * are dead on UA2); kept for non-UA2 adapters and future speed re-detect. */
static void
ax88179_link_reset(uint8_t slot, uint16_t physr)
{
    static const uint8_t bulkin_gig_ss[5] = {0x07, 0x4f, 0x00, 0x12, 0xff}; /* idx0 */
    static const uint8_t bulkin_gig_hs[5] = {0x07, 0x20, 0x03, 0x16, 0xff}; /* idx1 */
    static const uint8_t bulkin_100[5]    = {0x07, 0xae, 0x07, 0x18, 0xff}; /* idx2 */
    static const uint8_t bulkin_10[5]     = {0x07, 0xcc, 0x4c, 0x18, 0x08}; /* idx3 */

    uint16_t mode = 0x0130u;                       /* RECEIVE_EN|TXFLOW|RXFLOW */
    uint8_t  ss   = (ax_read_mac(slot, 0x02, 1) & 0x04u) ? 1u : 0u; /* USB SuperSpeed? */

    if ((physr & 0xC000u) == 0x8000u) {            /* 1000 Mb/s */
        mode |= 0x0009u;                           /* GIGAMODE | EN_125MHZ */
        ax_write_mac_buf(slot, 0x2e, 5, ss ? bulkin_gig_ss : bulkin_gig_hs);
    } else if ((physr & 0xC000u) == 0x4000u) {     /* 100 Mb/s */
        mode |= 0x0200u;                           /* PS */
        ax_write_mac_buf(slot, 0x2e, 5, bulkin_100);
    } else {                                       /* 10 Mb/s */
        ax_write_mac_buf(slot, 0x2e, 5, bulkin_10);
    }
    if (physr & 0x2000u) mode |= 0x0002u;          /* FULL_DUPLEX */
    ax_write_mac(slot, 0x22, 2, mode);             /* MEDIUM_STATUS_MODE */
    s_eth.link_reset_done = 1;
    s_eth.medium_rb = (uint16_t)ax_read_mac(slot, 0x22, 2);  /* read back */
}

/* ---- xHCI bulk endpoint plumbing for the ethernet device --------------- */

static void xhci_eth_submit_int(void);

/* xhci_eth_configure_bulk — allocate per-endpoint bulk rings + <4GB DMA buffers
 * and issue Configure Endpoint adding bulk-IN and bulk-OUT to the device
 * context (alongside the existing EP0/EP1). Returns 0 on success. */
static int
xhci_eth_configure_bulk(void)
{
    uint64_t ictx_phys;
    uint8_t *ictx;
    uint8_t  slot = s_eth.slot_id;

    s_eth.in_ring  = (xhci_trb_t *)alloc_page(&s_eth.in_ring_phys);
    s_eth.out_ring = (xhci_trb_t *)alloc_page(&s_eth.out_ring_phys);
    if (!s_eth.in_ring || !s_eth.out_ring)
        return -1;
    s_eth.in_enq = 0;  s_eth.in_cycle = 1;
    s_eth.out_enq = 0; s_eth.out_cycle = 1;
    s_eth.in_ring[XHCI_TRANSFER_RING_SIZE - 1].param   = s_eth.in_ring_phys;
    s_eth.in_ring[XHCI_TRANSFER_RING_SIZE - 1].control =
        (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | 1u;
    s_eth.out_ring[XHCI_TRANSFER_RING_SIZE - 1].param   = s_eth.out_ring_phys;
    s_eth.out_ring[XHCI_TRANSFER_RING_SIZE - 1].control =
        (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | 1u;

    /* RX buffer: a SINGLE 4 KB page (one Normal TRB). The chip CAN batch a
     * bulk-IN up to RX_BULKIN_QCTRL.size KB (gig=20K/100M=26K), but a multi-page
     * buffer is unsafe here: kva_alloc_pages_low returns virtually-contiguous but
     * physically-SCATTERED pages, and a single TRB describes one contiguous
     * physical run — a >4KB single-TRB buffer would DMA past the first page into
     * unrelated memory (and can cross a 64KB boundary, illegal per xHCI). One
     * page is contiguous + 64KB-safe and holds any single frame / small batch
     * (enough to prove RX + do DHCP). Full-size bursts need per-page CHAINED
     * TRBs — a follow-up once RX is confirmed. */
    s_eth.rx_buf = (uint8_t *)kva_alloc_pages_low(1);
    s_eth.tx_buf = (uint8_t *)kva_alloc_pages_low(1);
    if (!s_eth.rx_buf || !s_eth.tx_buf)
        return -1;
    s_eth.rx_buf_phys = kva_page_phys(s_eth.rx_buf);
    s_eth.tx_buf_phys = kva_page_phys(s_eth.tx_buf);
    s_eth.rx_buf_len  = 4096;

    /* Interrupt IN endpoint ring + 8-byte report buffer (link-status). */
    if (s_eth.int_dci) {
        s_eth.int_ring = (xhci_trb_t *)alloc_page(&s_eth.int_ring_phys);
        s_eth.int_buf  = (uint8_t *)kva_alloc_pages_low(1);
        if (!s_eth.int_ring || !s_eth.int_buf) {
            s_eth.int_dci = 0;          /* fall back to no INT EP, not fatal */
        } else {
            s_eth.int_buf_phys = kva_page_phys(s_eth.int_buf);
            s_eth.int_enq = 0; s_eth.int_cycle = 1;
            s_eth.int_ring[XHCI_TRANSFER_RING_SIZE - 1].param   = s_eth.int_ring_phys;
            s_eth.int_ring[XHCI_TRANSFER_RING_SIZE - 1].control =
                (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | 1u;
        }
    }

    /* Input Context: add slot + bulk-IN + bulk-OUT (+ interrupt IN if present);
     * never drop EP0/EP1. ContextEntries = highest DCI in use. */
    {
        uint32_t add = 1u | (1u << s_eth.bulk_in_dci) | (1u << s_eth.bulk_out_dci);
        uint8_t  hi  = s_eth.bulk_out_dci;
        if (s_eth.bulk_in_dci > hi) hi = s_eth.bulk_in_dci;
        if (s_eth.int_dci) {
            add |= (1u << s_eth.int_dci);
            if (s_eth.int_dci > hi) hi = s_eth.int_dci;
        }
        ictx = (uint8_t *)alloc_page(&ictx_phys);
        ((volatile uint32_t *)ictx)[0] = 0u;
        ((volatile uint32_t *)ictx)[1] = add;

        /* Slot Context: ContextEntries = highest DCI, speed, root port. */
        {
            uint8_t *sc = ictx + XHCI_CTX_ENTRY_SIZE;
            ((volatile uint32_t *)sc)[0] =
                ((uint32_t)s_eth.speed << 20) | ((uint32_t)hi << 27);
            ((volatile uint32_t *)sc)[1] = (uint32_t)s_eth.port_num << 16;
        }
    }
    /* SuperSpeed bulk MPS is fixed at 1024 (USB3 §9.6.6); force it for SS so a
     * mis-read descriptor can't mis-size bursts. Max Burst Size (dword1[15:8]) =
     * the SS Companion bMaxBurst — REQUIRED for SS bulk or the transfer never
     * progresses (the bug: it was left 0). */
    {
        uint16_t in_mps  = (s_eth.speed == 4u) ? 1024u : s_eth.bulk_in_mps;
        uint16_t out_mps = (s_eth.speed == 4u) ? 1024u : s_eth.bulk_out_mps;
        /* Bulk-IN EP context. */
        {
            uint8_t *ep = ictx + (uint32_t)(s_eth.bulk_in_dci + 1u) * XHCI_CTX_ENTRY_SIZE;
            ((volatile uint32_t *)ep)[1] =
                (3u << 1) | (XHCI_EP_TYPE_BULK_IN << 3)
                | ((uint32_t)s_eth.bulk_in_burst << 8)
                | ((uint32_t)in_mps << 16);
            ((volatile uint32_t *)ep)[2] =
                (uint32_t)(s_eth.in_ring_phys & 0xFFFFFFF0u) | 1u;
            ((volatile uint32_t *)ep)[3] = (uint32_t)(s_eth.in_ring_phys >> 32);
            ((volatile uint32_t *)ep)[4] = 1024u;
        }
        /* Bulk-OUT EP context. */
        {
            uint8_t *ep = ictx + (uint32_t)(s_eth.bulk_out_dci + 1u) * XHCI_CTX_ENTRY_SIZE;
            ((volatile uint32_t *)ep)[1] =
                (3u << 1) | (XHCI_EP_TYPE_BULK_OUT << 3)
                | ((uint32_t)s_eth.bulk_out_burst << 8)
                | ((uint32_t)out_mps << 16);
            ((volatile uint32_t *)ep)[2] =
                (uint32_t)(s_eth.out_ring_phys & 0xFFFFFFF0u) | 1u;
            ((volatile uint32_t *)ep)[3] = (uint32_t)(s_eth.out_ring_phys >> 32);
            ((volatile uint32_t *)ep)[4] = 1024u;
        }
    }
    /* Interrupt-IN EP context (link status). Interval field [23:16]: the AX88179
     * INT EP descriptor's bInterval is a frame exponent; 8 (=2^8 microframes) is
     * conservative and link events are rare — exact period is not load-bearing. */
    if (s_eth.int_dci) {
        uint8_t *ep = ictx + (uint32_t)(s_eth.int_dci + 1u) * XHCI_CTX_ENTRY_SIZE;
        ((volatile uint32_t *)ep)[0] = (8u << 16);
        ((volatile uint32_t *)ep)[1] =
            (3u << 1) | (XHCI_EP_TYPE_INT_IN << 3)
            | ((uint32_t)s_eth.int_mps << 16);
        ((volatile uint32_t *)ep)[2] =
            (uint32_t)(s_eth.int_ring_phys & 0xFFFFFFF0u) | 1u;
        ((volatile uint32_t *)ep)[3] = (uint32_t)(s_eth.int_ring_phys >> 32);
        ((volatile uint32_t *)ep)[4] = (uint32_t)s_eth.int_mps;
    }

    enqueue_cmd(ictx_phys, 0,
                (uint32_t)(XHCI_TRB_CONFIGURE_EP << 10) | ((uint32_t)slot << 24));
    ring_cmd_doorbell();
    if (poll_cmd_completion() == 0)
        return -1;

    /* Arm the first interrupt IN so link-status reports start flowing. */
    if (s_eth.int_dci) {
        xhci_eth_submit_int();
        s_eth.int_armed = 1;
    }
    return 0;
}

/* xhci_eth_submit_rx — queue one bulk-IN Normal TRB into the rx buffer + ring
 * the bulk-IN doorbell. Re-armed after each completion in xhci_poll. */
static void
xhci_eth_submit_rx(void)
{
    volatile uint32_t *db;
    xhci_trb_t *trb = &s_eth.in_ring[s_eth.in_enq];

    trb->param   = s_eth.rx_buf_phys;
    trb->status  = s_eth.rx_buf_len;
    /* IOC (1<<5) + ISP (1<<2, Interrupt-on Short Packet). ISP is REQUIRED: the
     * 4 KB buffer only fills on a full burst, but every ethernet frame is a short
     * packet — without ISP a short RX stops with no event → zero completions. */
    trb->control = (uint32_t)(XHCI_TRB_NORMAL << 10) | (1u << 5) | (1u << 2) | s_eth.in_cycle;
    s_eth.in_enq++;
    if (s_eth.in_enq >= XHCI_TRANSFER_RING_SIZE - 1u) {
        /* Link carries the current lap's cycle; flip producer cycle after. */
        s_eth.in_ring[XHCI_TRANSFER_RING_SIZE - 1].control =
            (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | s_eth.in_cycle;
        s_eth.in_cycle ^= 1u;
        s_eth.in_enq = 0;
    }
    db = (volatile uint32_t *)(s_bar0_va + s_cap->dboff);
    arch_wmb();
    db[s_eth.slot_id] = s_eth.bulk_in_dci;
}

/* xhci_eth_submit_int — queue one interrupt-IN Normal TRB into the int buffer +
 * ring the doorbell. Re-armed after each completion. Carries the 8-byte link
 * report (intdata1 bit 16 = AX_INT_PPLS_LINK). */
static void
xhci_eth_submit_int(void)
{
    volatile uint32_t *db;
    xhci_trb_t *trb = &s_eth.int_ring[s_eth.int_enq];

    trb->param   = s_eth.int_buf_phys;
    trb->status  = s_eth.int_mps;
    /* IOC + ISP: link reports are shorter than int_mps, so ISP is needed for the
     * short-packet completion (same rule as the bulk-IN RX path above). */
    trb->control = (uint32_t)(XHCI_TRB_NORMAL << 10) | (1u << 5) | (1u << 2) | s_eth.int_cycle;
    s_eth.int_enq++;
    if (s_eth.int_enq >= XHCI_TRANSFER_RING_SIZE - 1u) {
        /* Link carries the current lap's cycle; flip producer cycle after. */
        s_eth.int_ring[XHCI_TRANSFER_RING_SIZE - 1].control =
            (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | s_eth.int_cycle;
        s_eth.int_cycle ^= 1u;
        s_eth.int_enq = 0;
    }
    db = (volatile uint32_t *)(s_bar0_va + s_cap->dboff);
    arch_wmb();
    db[s_eth.slot_id] = s_eth.int_dci;
}

/* le32 — read a little-endian u32 from a byte buffer (x86 is LE; explicit for clarity). */
static inline uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* xhci_eth_rx_complete — parse one AX88179 bulk-IN URB (spec §6) and deliver each
 * contained Ethernet frame to the network stack. Called from xhci_poll (PIT ISR).
 * Layout: [pkt data, 8B-padded]... [per-packet 4B meta]... [rx_hdr (last 4B)].
 *   rx_hdr: pkt_cnt = lo16 (counts meta entries, incl. pkt_len==0 dummies),
 *           hdr_off = hi16 (byte offset of the meta array).
 *   meta h: pkt_len = (h>>16)&0x1fff (includes the 2B IPE front pad), and
 *           CRC_ERR=0x20000000 / DROP_ERR=0x80000000 flag bad frames. */
static void
xhci_eth_rx_complete(uint32_t len)
{
    uint8_t *buf = s_eth.rx_buf;
    s_eth.rx_count++;
    s_eth.rx_bytes += len;
    s_eth.last_rx_len = len;

    if (len < 4) return;
    uint32_t total   = len - 4u;
    uint32_t rx_hdr  = le32(buf + total);
    uint32_t pkt_cnt = rx_hdr & 0xFFFFu;
    uint32_t hdr_off = rx_hdr >> 16;
    if (pkt_cnt == 0u || (uint64_t)pkt_cnt * 4u + hdr_off > total)
        return;   /* malformed / truncated URB */

    uint8_t *pkt_hdr = buf + hdr_off;
    uint8_t *data    = buf;
    uint32_t remain  = hdr_off;
    uint32_t i;
    /* We're in the PIT ISR. Tell arp_resolve (reachable via a synchronous reply
     * inside netdev_rx_deliver) to use its non-blocking path. */
    int prev_inpoll = g_in_netdev_poll;
    g_in_netdev_poll = 1;
    for (i = 0; i < pkt_cnt; i++, pkt_hdr += 4) {
        uint32_t h       = le32(pkt_hdr);
        uint32_t pkt_len = (h >> 16) & 0x1FFFu;
        uint32_t padded  = (pkt_len + 7u) & ~7u;
        if (pkt_len == 0u) continue;                  /* dummy meta entry */
        if (padded > remain) break;                   /* would overrun */
        if ((h & 0xA0000000u) || pkt_len < 16u) {     /* CRC_ERR|DROP_ERR or runt */
            data += padded; remain -= padded; continue;
        }
        /* +2/-2: RX_CTL has IPE set, so each frame has a 2-byte front pad. */
        netdev_rx_deliver(&s_eth.nd, data + 2, (uint16_t)(pkt_len - 2u));
        s_eth.rx_frames++;
        data += padded; remain -= padded;
    }
    g_in_netdev_poll = prev_inpoll;
}

/* usb_eth_send — netdev TX (spec §7): prepend an 8-byte header (frame_len,
 * gso=0) and push one frame on the bulk-OUT ring. Called from process context
 * (the IP stack TX path); guarded against the ISR by s_eth_tx_lock (irqsave). */
static int
usb_eth_send(netdev_t *dev, const void *pkt, uint16_t len)
{
    (void)dev;
    if (!s_eth.configured || len == 0u || len > 1514u)
        return -1;

    irqflags_t fl = spin_lock_irqsave(&s_eth_tx_lock);
    if (s_eth.tx_inflight) {
        /* Previous TX still using tx_buf — unless its completion was lost (link
         * flap / EP halt), in which case reclaim it past the deadline so TX
         * doesn't wedge forever. */
        if (xhci_rdtsc() < s_eth.tx_deadline) {
            spin_unlock_irqrestore(&s_eth_tx_lock, fl);
            return -1;
        }
        s_eth.tx_inflight = 0;
    }
    if (s_cycles_per_ms == 0) s_cycles_per_ms = xhci_ticks_per_ms();
    s_eth.tx_deadline = xhci_rdtsc() + 1000ULL * s_cycles_per_ms;  /* 1s */

    uint8_t *tb = s_eth.tx_buf;
    uint32_t mps = s_eth.bulk_out_mps ? s_eth.bulk_out_mps : 1024u;
    uint32_t hdr1 = (uint32_t)len;
    uint32_t hdr2 = 0u;
    if (((uint32_t)len + 8u) % mps == 0u)
        hdr2 |= 0x80008000u;                 /* zero-length-packet avoidance pad flag */
    tb[0] = (uint8_t)hdr1; tb[1] = (uint8_t)(hdr1 >> 8);
    tb[2] = (uint8_t)(hdr1 >> 16); tb[3] = (uint8_t)(hdr1 >> 24);
    tb[4] = (uint8_t)hdr2; tb[5] = (uint8_t)(hdr2 >> 8);
    tb[6] = (uint8_t)(hdr2 >> 16); tb[7] = (uint8_t)(hdr2 >> 24);
    __builtin_memcpy(tb + 8, pkt, len);
    uint32_t total = 8u + (uint32_t)len;

    xhci_trb_t *trb = &s_eth.out_ring[s_eth.out_enq];
    trb->param   = s_eth.tx_buf_phys;
    trb->status  = total;
    trb->control = (uint32_t)(XHCI_TRB_NORMAL << 10) | (1u << 5) | s_eth.out_cycle;
    s_eth.out_enq++;
    if (s_eth.out_enq >= XHCI_TRANSFER_RING_SIZE - 1u) {
        /* Link carries the current lap's cycle; flip producer cycle after. */
        s_eth.out_ring[XHCI_TRANSFER_RING_SIZE - 1].control =
            (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | s_eth.out_cycle;
        s_eth.out_cycle ^= 1u;
        s_eth.out_enq = 0;
    }
    s_eth.tx_inflight = 1;
    s_eth.tx_count++;

    volatile uint32_t *db = (volatile uint32_t *)(s_bar0_va + s_cap->dboff);
    arch_wmb();
    db[s_eth.slot_id] = s_eth.bulk_out_dci;
    spin_unlock_irqrestore(&s_eth_tx_lock, fl);
    return 0;
}

/* usb_eth_poll — netdev poll hook. No-op: RX is driven by the bulk-IN completion
 * in xhci_poll (the USB controller poll), not by the net-stack poll. */
static void
usb_eth_poll(netdev_t *dev)
{
    (void)dev;
    /* On first link-up (interrupt EP), re-run link_reset for the negotiated
     * speed. The static probe-time MEDIUM write loses the gigabit bits
     * (GIGAMODE|EN_125MHZ) because it lands before the PHY negotiates, leaving the
     * MAC at 10/100 while the PHY is gigabit → no RX. MDIO is dead on this UA2
     * chip, so force gigabit-FD (host confirms 1000, int EP confirms link). Safe:
     * usb_eth_poll is the non-ISR poll path (control transfers OK here).
     * ponytail: forced gigabit; parse intdata1 speed bits if a non-gig link matters. */
    if (s_eth.present && s_eth.configured &&
        s_eth.link_up_intr && !s_eth.link_reset_done)
        ax88179_link_reset(s_eth.slot_id, 0xA000u);  /* 1000 Mb/s | full-duplex */

    /* ponytail: temporary bring-up heartbeat — dump the AX88179 data-path
     * counters to serial every ~256 polls so RX/TX/link progress is visible
     * without a userland shell. Remove once the data path is solid. */
    static uint32_t hb;
    if (s_eth.present && (++hb & 0xFF) == 0)
        printk("[USBETH] rx=%u txsub=%u txdone=%u int=%u linkI=%u intd1=%x | rxctl=%x med=%x burst=%u plink=%x\n",
               (unsigned)s_eth.rx_count, (unsigned)s_eth.tx_count,
               (unsigned)s_eth.tx_done, (unsigned)s_eth.int_count,
               (unsigned)s_eth.link_up_intr, (unsigned)s_eth.intdata1,
               (unsigned)s_eth.rxctl_rb, (unsigned)s_eth.medium_rb,
               (unsigned)s_eth.bulk_in_burst, (unsigned)s_eth.plink_rb);
}

/* xhci_usbnet_diag — snapshot the AX88179 state for /proc/usbnet (read context). */
void
xhci_usbnet_diag(xhci_usbnet_diag_t *out)
{
    int i;
    if (!out) return;
    out->present      = s_eth.present;
    out->configured   = s_eth.configured;
    for (i = 0; i < 6; i++) out->mac[i] = s_eth.mac[i];
    out->bulk_in_dci  = s_eth.bulk_in_dci;
    out->bulk_out_dci = s_eth.bulk_out_dci;
    out->bulk_in_mps  = s_eth.bulk_in_mps;
    out->bulk_out_mps = s_eth.bulk_out_mps;
    out->link_up         = s_eth.link_up;
    out->link_reset_done = s_eth.link_reset_done;
    out->physr           = s_eth.link_physr;
    out->bmsr            = s_eth.link_bmsr;
    out->medium_rb       = s_eth.medium_rb;
    out->rxctl_rb        = s_eth.rxctl_rb;
    out->plink_rb        = s_eth.plink_rb;
    out->genstat_rb      = s_eth.genstat_rb;
    out->bcd_device      = s_eth.bcd_device;
    out->phy_cc          = s_eth.phy_cc;
    out->int_dci         = s_eth.int_dci;
    out->int_armed       = s_eth.int_armed;
    out->link_up_intr    = s_eth.link_up_intr;
    out->int_count       = s_eth.int_count;
    out->intdata1        = s_eth.intdata1;
    out->intdata2        = s_eth.intdata2;
    out->det_speed       = s_eth.det_speed;
    out->med_gig_rb      = s_eth.med_gig_rb;
    out->med_100_rb      = s_eth.med_100_rb;
    out->bulk_in_addr    = s_eth.bulk_in_addr;
    out->bulk_out_addr   = s_eth.bulk_out_addr;
    out->int_addr        = s_eth.int_addr;
    out->bulk_in_burst   = s_eth.bulk_in_burst;
    out->rx_count     = s_eth.rx_count;
    out->rx_bytes     = s_eth.rx_bytes;
    out->last_rx_len  = s_eth.last_rx_len;
    out->rx_frames    = s_eth.rx_frames;
    out->tx_count     = s_eth.tx_count;
    out->registered   = s_eth.registered;
    for (i = 0; i < 8; i++) out->ifname[i] = s_eth.nd.name[i];
    out->ifname[7]    = '\0';
    out->saw_device   = s_probe_saw;
    out->last_vid     = s_probe_vid;
    out->last_pid     = s_probe_pid;
}

/* ---- USB Mass Storage (Bulk-Only Transport / SCSI) --------------------- */

typedef struct {
    int       present, configured, registered;
    uint8_t   slot_id, port_num, speed;
    uint8_t   bulk_in_addr, bulk_out_addr, bulk_in_dci, bulk_out_dci;
    uint16_t  bulk_in_mps, bulk_out_mps;
    uint8_t   bulk_in_burst, bulk_out_burst;
    xhci_trb_t *in_ring;  uint64_t in_ring_phys;  uint32_t in_enq, in_cycle;
    xhci_trb_t *out_ring; uint64_t out_ring_phys; uint32_t out_enq, out_cycle;
    uint8_t  *data; uint64_t data_phys;        /* one-page data bounce */
    uint8_t  *cbw;  uint64_t cbw_phys;          /* CBW @ +0, CSW @ +64 */
    uint32_t  tag;
    uint64_t  block_count; uint32_t block_size;
    spinlock_t lock;
    blkdev_t  blk;
} usb_msc_dev_t;
static usb_msc_dev_t s_msc;

/* One synchronous bulk transfer: a single Normal TRB on the given ring, ring
 * the EP doorbell, poll the event ring for the transfer event. Returns bytes
 * transferred (>=0) or -1. The post-boot blkdev path holds IRQs off so the
 * PIT-ISR xhci_poll cannot consume the same event ring concurrently. */
static int
msc_bulk_one(uint8_t dci, xhci_trb_t *ring,
             uint32_t *p_enq, uint32_t *p_cycle, uint64_t buf_phys, uint32_t len)
{
    uint32_t ei = *p_enq, cycle = *p_cycle;
    xhci_trb_t *trb = &ring[ei];
    trb->param   = buf_phys;
    trb->status  = len;
    trb->control = (uint32_t)(XHCI_TRB_NORMAL << 10) | (1u << 5) /*IOC*/ | cycle;
    ei++;
    if (ei >= XHCI_TRANSFER_RING_SIZE - 1u) {
        /* The Link TRB belongs to the lap just filled (idx 0..62), so it must
         * carry the CURRENT producer cycle — NOT the flipped one. Its Toggle
         * Cycle bit (1<<1) flips the endpoint's consumer cycle when it follows
         * the link into the next lap. Stamping the link with the flipped cycle
         * (the old bug) made the endpoint see a cycle mismatch at idx 63 and
         * halt as if the ring were empty — exactly at the first ring wrap. */
        ring[XHCI_TRANSFER_RING_SIZE - 1].control =
            (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | cycle;
        *p_cycle ^= 1; ei = 0;
    }
    *p_enq = ei;

    volatile uint32_t *db = (volatile uint32_t *)(s_bar0_va + s_cap->dboff);
    arch_wmb();
    db[s_msc.slot_id] = dci;

    uint64_t deadline = xhci_rdtsc() + 1000ULL * s_cycles_per_ms;
    while (xhci_rdtsc() < deadline) {
        volatile xhci_trb_t *evt = &s_evt_ring[s_evt_dequeue];
        if ((evt->control & 1u) != (uint32_t)s_evt_cycle) { xhci_relax(); continue; }
        uint32_t etype = (evt->control >> 10) & 0x3Fu;
        uint8_t  eslot = (uint8_t)((evt->control >> 24) & 0xFFu);
        uint8_t  cc    = (uint8_t)((evt->status >> 24) & 0xFFu);
        uint32_t resid = evt->status & 0xFFFFFFu;
        s_evt_dequeue++;
        if (s_evt_dequeue >= XHCI_EVT_RING_SIZE) { s_evt_dequeue = 0; s_evt_cycle ^= 1; }
        update_erdp();
        if (etype == XHCI_TRB_TRANSFER_EVENT && eslot == s_msc.slot_id)
            return (cc == 1u || cc == 13u) ? (int)(len - resid) : -1;
        /* skip events for other slots / non-transfer (PSC, CMD_COMPLETION) */
    }
    printk("[XHCI] msc bulk timeout dci=%u len=%u usbsts=0x%x\n",
           (unsigned)dci, (unsigned)len,
           (unsigned)op_read32(XHCI_OP_USBSTS_OFF));
    return -1;
}

/* Bulk-Only Transport transaction: CBW (out) → optional data → CSW (in). Data
 * lives in s_msc.data. Returns 0 on CSW "passed", -1 otherwise. */
static int
msc_bbb(const uint8_t *cdb, uint8_t cdb_len, uint32_t data_len, int dir_in)
{
    uint8_t *cbw = s_msc.cbw;
    uint32_t tag = ++s_msc.tag;
    for (int i = 0; i < 31; i++) cbw[i] = 0;
    cbw[0]=0x55; cbw[1]=0x53; cbw[2]=0x42; cbw[3]=0x43;           /* "USBC" */
    cbw[4]=(uint8_t)tag; cbw[5]=(uint8_t)(tag>>8); cbw[6]=(uint8_t)(tag>>16); cbw[7]=(uint8_t)(tag>>24);
    cbw[8]=(uint8_t)data_len; cbw[9]=(uint8_t)(data_len>>8); cbw[10]=(uint8_t)(data_len>>16); cbw[11]=(uint8_t)(data_len>>24);
    cbw[12]= dir_in ? 0x80u : 0x00u;                             /* bmCBWFlags */
    cbw[13]=0;                                                   /* LUN 0 */
    cbw[14]=cdb_len;
    for (uint8_t i = 0; i < cdb_len && i < 16u; i++) cbw[15+i] = cdb[i];

    if (msc_bulk_one(s_msc.bulk_out_dci, s_msc.out_ring, &s_msc.out_enq, &s_msc.out_cycle, s_msc.cbw_phys, 31) < 0)
        return -1;
    if (data_len > 0) {
        int rc = dir_in
            ? msc_bulk_one(s_msc.bulk_in_dci,  s_msc.in_ring,  &s_msc.in_enq,  &s_msc.in_cycle,  s_msc.data_phys, data_len)
            : msc_bulk_one(s_msc.bulk_out_dci, s_msc.out_ring, &s_msc.out_enq, &s_msc.out_cycle, s_msc.data_phys, data_len);
        if (rc < 0) return -1;
    }
    uint8_t *csw = s_msc.cbw + 64;
    if (msc_bulk_one(s_msc.bulk_in_dci, s_msc.in_ring, &s_msc.in_enq, &s_msc.in_cycle, s_msc.cbw_phys + 64, 13) < 0)
        return -1;
    if (csw[0]!=0x55 || csw[1]!=0x53 || csw[2]!=0x42 || csw[3]!=0x53) return -1;  /* "USBS" */
    return csw[12] == 0 ? 0 : -1;                                /* bCSWStatus */
}

static int
msc_configure_bulk(void)
{
    uint64_t ictx_phys; uint8_t *ictx; uint8_t slot = s_msc.slot_id;
    s_msc.in_ring  = (xhci_trb_t *)alloc_page(&s_msc.in_ring_phys);
    s_msc.out_ring = (xhci_trb_t *)alloc_page(&s_msc.out_ring_phys);
    if (!s_msc.in_ring || !s_msc.out_ring) return -1;
    s_msc.in_enq=0; s_msc.in_cycle=1; s_msc.out_enq=0; s_msc.out_cycle=1;
    s_msc.in_ring[XHCI_TRANSFER_RING_SIZE-1].param   = s_msc.in_ring_phys;
    s_msc.in_ring[XHCI_TRANSFER_RING_SIZE-1].control = (uint32_t)(XHCI_TRB_LINK<<10)|(1u<<1)|1u;
    s_msc.out_ring[XHCI_TRANSFER_RING_SIZE-1].param   = s_msc.out_ring_phys;
    s_msc.out_ring[XHCI_TRANSFER_RING_SIZE-1].control = (uint32_t)(XHCI_TRB_LINK<<10)|(1u<<1)|1u;
    s_msc.data = (uint8_t *)kva_alloc_pages_low(1);
    s_msc.cbw  = (uint8_t *)kva_alloc_pages_low(1);
    if (!s_msc.data || !s_msc.cbw) return -1;
    s_msc.data_phys = kva_page_phys(s_msc.data);
    s_msc.cbw_phys  = kva_page_phys(s_msc.cbw);

    uint32_t add = 1u | (1u<<s_msc.bulk_in_dci) | (1u<<s_msc.bulk_out_dci);
    uint8_t  hi  = s_msc.bulk_out_dci; if (s_msc.bulk_in_dci > hi) hi = s_msc.bulk_in_dci;
    ictx = (uint8_t *)alloc_page(&ictx_phys);
    ((volatile uint32_t *)ictx)[0]=0; ((volatile uint32_t *)ictx)[1]=add;
    { uint8_t *sc = ictx + XHCI_CTX_ENTRY_SIZE;
      ((volatile uint32_t *)sc)[0] = ((uint32_t)s_msc.speed<<20)|((uint32_t)hi<<27);
      ((volatile uint32_t *)sc)[1] = (uint32_t)s_msc.port_num<<16; }
    uint16_t in_mps  = (s_msc.speed==4u)?1024u:s_msc.bulk_in_mps;
    uint16_t out_mps = (s_msc.speed==4u)?1024u:s_msc.bulk_out_mps;
    { uint8_t *ep = ictx + (uint32_t)(s_msc.bulk_in_dci+1u)*XHCI_CTX_ENTRY_SIZE;
      ((volatile uint32_t *)ep)[1]=(3u<<1)|(XHCI_EP_TYPE_BULK_IN<<3)|((uint32_t)s_msc.bulk_in_burst<<8)|((uint32_t)in_mps<<16);
      ((volatile uint32_t *)ep)[2]=(uint32_t)(s_msc.in_ring_phys & 0xFFFFFFF0u)|1u;
      ((volatile uint32_t *)ep)[3]=(uint32_t)(s_msc.in_ring_phys>>32);
      ((volatile uint32_t *)ep)[4]=1024u; }
    { uint8_t *ep = ictx + (uint32_t)(s_msc.bulk_out_dci+1u)*XHCI_CTX_ENTRY_SIZE;
      ((volatile uint32_t *)ep)[1]=(3u<<1)|(XHCI_EP_TYPE_BULK_OUT<<3)|((uint32_t)s_msc.bulk_out_burst<<8)|((uint32_t)out_mps<<16);
      ((volatile uint32_t *)ep)[2]=(uint32_t)(s_msc.out_ring_phys & 0xFFFFFFF0u)|1u;
      ((volatile uint32_t *)ep)[3]=(uint32_t)(s_msc.out_ring_phys>>32);
      ((volatile uint32_t *)ep)[4]=1024u; }
    enqueue_cmd(ictx_phys, 0, (uint32_t)(XHCI_TRB_CONFIGURE_EP<<10)|((uint32_t)slot<<24));
    ring_cmd_doorbell();
    return poll_cmd_completion()==0 ? -1 : 0;
}

static int
msc_rw(uint64_t lba, uint32_t count, int is_write, uint8_t *ubuf)
{
    uint32_t max_chunk = 4096u / s_msc.block_size;
    if (max_chunk == 0) max_chunk = 1;
    int rc = 0;
    irqflags_t fl = spin_lock_irqsave(&s_msc.lock);   /* exclude xhci_poll */
    s_msc_busy = 1;
    while (count > 0 && rc == 0) {
        uint32_t chunk = count < max_chunk ? count : max_chunk;
        uint32_t bytes = chunk * s_msc.block_size;
        uint8_t cdb[10]; for (int i=0;i<10;i++) cdb[i]=0;
        cdb[0] = is_write ? 0x2Au : 0x28u;            /* WRITE(10) / READ(10) */
        cdb[2]=(uint8_t)(lba>>24); cdb[3]=(uint8_t)(lba>>16);
        cdb[4]=(uint8_t)(lba>>8);  cdb[5]=(uint8_t)lba;
        cdb[7]=(uint8_t)(chunk>>8); cdb[8]=(uint8_t)chunk;
        if (is_write) { for (uint32_t i=0;i<bytes;i++) s_msc.data[i]=ubuf[i]; }
        if (msc_bbb(cdb, 10, bytes, is_write?0:1) < 0) { rc = -1; break; }
        if (!is_write) { for (uint32_t i=0;i<bytes;i++) ubuf[i]=s_msc.data[i]; }
        ubuf += bytes; lba += chunk; count -= chunk;
    }
    s_msc_busy = 0;
    spin_unlock_irqrestore(&s_msc.lock, fl);
    return rc;
}

static int msc_blk_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{ (void)dev; return count==0 ? 0 : msc_rw(lba, count, 0, (uint8_t *)buf); }
static int msc_blk_write(blkdev_t *dev, uint64_t lba, uint32_t count, const void *buf)
{ (void)dev; return count==0 ? 0 : msc_rw(lba, count, 1, (uint8_t *)(uintptr_t)buf); }

/* detect_interface_class — first Interface Descriptor's bInterfaceClass. */
static uint8_t
detect_interface_class(uint8_t slot_id)
{
    uint64_t setup = (uint64_t)0x80u|((uint64_t)0x06u<<8)|((uint64_t)0x0200u<<16)|((uint64_t)64u<<48);
    uint8_t *buf = s_hid_buf[slot_id];
    int got = issue_control_transfer(slot_id, setup, 1);
    if (got < 4) return 0xFFu;
    int off = 0;
    while (off + 2 <= got) {
        uint8_t blen = buf[off], btype = buf[off+1];
        if (blen < 2 || off + blen > got) break;
        if (btype == 4u && blen >= 9u) return buf[off+5];
        off += blen;
    }
    return 0xFFu;
}

/* probe_usb_msc — claim a USB Bulk-Only mass-storage device, run SCSI bring-up
 * (TEST UNIT READY / INQUIRY / READ CAPACITY), register it as blkdev "usb0". */
static int
probe_usb_msc(uint8_t slot_id, uint8_t port_num, uint8_t speed)
{
    uint8_t *buf = s_hid_buf[slot_id];
    uint64_t setup;
    uint8_t cfg_val, bin=0, bout=0, bin_burst=0, bout_burst=0;
    uint16_t bin_mps=0, bout_mps=0;
    int total, off;

    setup = (uint64_t)0x80u|((uint64_t)0x06u<<8)|((uint64_t)0x0200u<<16)|((uint64_t)255u<<48);
    if (issue_control_transfer(slot_id, setup, 1) < 0) return 0;
    cfg_val = buf[5];
    total = (int)buf[2] | ((int)buf[3] << 8); if (total > 255) total = 255;
    off = 0;
    while (off + 2 <= total) {
        uint8_t blen = buf[off], btype = buf[off+1];
        if (blen < 2 || off + blen > total) break;
        if (btype == 5u && blen >= 7u) {
            uint8_t addr = buf[off+2], attr = buf[off+3];
            uint16_t mps = (uint16_t)buf[off+4] | ((uint16_t)buf[off+5] << 8);
            uint8_t burst = 0;
            if (off + (int)blen + 2 < total && buf[off+blen+1] == 0x30u) burst = buf[off+blen+2];
            if ((attr & 3u) == 2u) {
                if ((addr & 0x80u) && !bin)        { bin=addr;  bin_mps=mps;  bin_burst=burst; }
                else if (!(addr & 0x80u) && !bout) { bout=addr; bout_mps=mps; bout_burst=burst; }
            }
        }
        off += blen;
    }
    if (!bin || !bout) { printk("[XHCI] slot %u MSC — no bulk endpoints\n", (unsigned)slot_id); return 0; }

    setup = (uint64_t)0x00u|((uint64_t)0x09u<<8)|((uint64_t)cfg_val<<16);
    issue_control_transfer(slot_id, setup, 0);   /* SET_CONFIGURATION */

    s_msc.present=1; s_msc.slot_id=slot_id; s_msc.port_num=port_num; s_msc.speed=speed;
    s_msc.bulk_in_addr=bin; s_msc.bulk_out_addr=bout;
    s_msc.bulk_in_dci=(uint8_t)(2u*(bin&0x0Fu)+1u); s_msc.bulk_out_dci=(uint8_t)(2u*(bout&0x0Fu));
    s_msc.bulk_in_mps=bin_mps; s_msc.bulk_out_mps=bout_mps;
    s_msc.bulk_in_burst=bin_burst; s_msc.bulk_out_burst=bout_burst;
    s_msc.lock=(spinlock_t)SPINLOCK_INIT; s_msc.tag=0;

    if (msc_configure_bulk() != 0) { printk("[XHCI] MSC configure bulk failed\n"); return 0; }
    s_msc.configured = 1;

    uint8_t cdb[16];
    for (int t=0;t<4;t++){ for(int i=0;i<6;i++){ cdb[i]=0; } cdb[0]=0x00; if (msc_bbb(cdb,6,0,0)==0) break; }  /* TEST UNIT READY */
    for (int i=0;i<6;i++){ cdb[i]=0; }
    cdb[0]=0x12; cdb[4]=36; (void)msc_bbb(cdb,6,36,1);                       /* INQUIRY */
    for (int i=0;i<10;i++){ cdb[i]=0; }
    cdb[0]=0x25;                                                            /* READ CAPACITY(10) */
    if (msc_bbb(cdb, 10, 8, 1) < 0) { printk("[XHCI] MSC READ CAPACITY failed\n"); return 0; }
    uint8_t *cap = s_msc.data;
    uint32_t last_lba = ((uint32_t)cap[0]<<24)|((uint32_t)cap[1]<<16)|((uint32_t)cap[2]<<8)|cap[3];
    uint32_t bsz = ((uint32_t)cap[4]<<24)|((uint32_t)cap[5]<<16)|((uint32_t)cap[6]<<8)|cap[7];
    if (bsz == 0 || bsz > 4096) bsz = 512;
    s_msc.block_count = (uint64_t)last_lba + 1u;
    s_msc.block_size  = bsz;

    s_msc.blk.name[0]='u'; s_msc.blk.name[1]='s'; s_msc.blk.name[2]='b';
    s_msc.blk.name[3]='0'; s_msc.blk.name[4]='\0';
    s_msc.blk.block_count = s_msc.block_count;
    s_msc.blk.block_size  = bsz;
    s_msc.blk.lba_offset  = 0;
    s_msc.blk.read  = msc_blk_read;
    s_msc.blk.write = msc_blk_write;
    s_msc.blk.priv  = NULL;
    blkdev_register(&s_msc.blk);
    s_msc.registered = 1;

    /* Sustained read + write both work (verified: 300-sector read sweep and a
     * 120-sector write/readback round-trip, each crossing many transfer-ring
     * wraps). The earlier post-wrap stall was a transfer-ring Link TRB stamped
     * with the post-flip cycle bit (fixed in msc_bulk_one / issue_control_transfer):
     * the endpoint hit a cycle mismatch at the link and halted as if the ring
     * were empty. usb0 is registered and gpt_scan("usb0") runs, but usb0 is
     * intentionally NOT in the root-mount fallback — removable media must never
     * silently hijack boot; an Aegis-partitioned stick surfaces as usb0pN. */
    printk("[XHCI] usb-storage usb0 %u sectors (%u-byte blocks)\n",
           (unsigned)s_msc.block_count, (unsigned)bsz);
    return 1;
}

/* probe_usb_ethernet — called for a non-HID device. Claims an ASIX AX88179/
 * AX88179A (VID 0x0B95): reads its (single, vendor) configuration, locates the
 * primary bulk IN/OUT endpoints, selects the configuration, and records the
 * device in s_eth. Returns 1 if claimed, 0 otherwise.
 *
 * NOTE: the control-transfer return is the requested wLength (the residual is
 * read from the zero-length STATUS TRB), so it cannot be used as a byte count.
 * Descriptor walks are bounded by wTotalLength instead. */
static int
probe_usb_ethernet(uint8_t slot_id, uint8_t port_num, uint8_t speed)
{
    uint8_t *buf = s_hid_buf[slot_id];
    uint64_t setup;
    uint16_t vid, pid;
    uint8_t  cfg_val, bin = 0, bout = 0, bint = 0;
    uint16_t bin_mps = 0, bout_mps = 0, bint_mps = 0;
    uint8_t  bin_burst = 0, bout_burst = 0;
    int total, off;

    /* Device descriptor → idVendor/idProduct (offsets 8..11). */
    setup = (uint64_t)0x80u | ((uint64_t)0x06u << 8)
          | ((uint64_t)0x0100u << 16) | ((uint64_t)18u << 48);
    if (issue_control_transfer(slot_id, setup, 1) < 0)
        return 0;
    vid = (uint16_t)buf[8]  | ((uint16_t)buf[9]  << 8);
    pid = (uint16_t)buf[10] | ((uint16_t)buf[11] << 8);
    s_probe_saw = 1;
    s_probe_vid = vid;
    s_probe_pid = pid;
    if (vid != 0x0B95u) {
        printk("[XHCI] slot %u non-HID vid=%x pid=%x — no driver\n",
               (unsigned)slot_id, (unsigned)vid, (unsigned)pid);
        return 0;
    }
    /* bcdDevice (offsets 12-13): >= 0x0200 == AX88179A — needs the FW_MODE
     * legacy-mode force before MDIO/RX work (see ax88179_reset). */
    s_eth.bcd_device = (uint16_t)buf[12] | ((uint16_t)buf[13] << 8);

    /* Configuration descriptor (index 0); bound the walk by wTotalLength. */
    setup = (uint64_t)0x80u | ((uint64_t)0x06u << 8)
          | ((uint64_t)0x0200u << 16) | ((uint64_t)255u << 48);
    if (issue_control_transfer(slot_id, setup, 1) < 0)
        return 0;
    cfg_val = buf[5];
    total   = (int)buf[2] | ((int)buf[3] << 8);
    if (total > 255) total = 255;

    off = 0;
    while (off + 2 <= total) {
        uint8_t blen  = buf[off];
        uint8_t btype = buf[off + 1];
        if (blen < 2 || off + blen > total)
            break;
        if (btype == 5u && blen >= 7u) {                 /* Endpoint */
            uint8_t  addr = buf[off + 2];
            uint8_t  attr = buf[off + 3];
            uint16_t mps  = (uint16_t)buf[off + 4]
                          | ((uint16_t)buf[off + 5] << 8);
            /* SuperSpeed Endpoint Companion (bDescriptorType 0x30) immediately
             * follows each SS endpoint and carries bMaxBurst (offset 2). The SS
             * bulk EP context MUST be programmed with this burst or the bulk
             * transfer never progresses (zero completions). */
            uint8_t burst = 0;
            if (off + (int)blen + 2 < total && buf[off + blen + 1] == 0x30u)
                burst = buf[off + blen + 2];
            if ((attr & 3u) == 2u) {                     /* Bulk */
                if ((addr & 0x80u) && !bin)        { bin = addr;  bin_mps = mps;  bin_burst = burst; }
                else if (!(addr & 0x80u) && !bout) { bout = addr; bout_mps = mps; bout_burst = burst; }
            } else if ((attr & 3u) == 3u) {              /* Interrupt */
                if ((addr & 0x80u) && !bint) { bint = addr; bint_mps = mps; }
            }
        }
        off += blen;
    }
    if (!bin || !bout) {
        printk("[XHCI] slot %u ASIX vid=%x pid=%x — no bulk endpoints\n",
               (unsigned)slot_id, (unsigned)vid, (unsigned)pid);
        return 0;
    }

    /* SET_CONFIGURATION(cfg_val) — no data stage. */
    setup = (uint64_t)0x00u | ((uint64_t)0x09u << 8) | ((uint64_t)cfg_val << 16);
    issue_control_transfer(slot_id, setup, 0);

    /* Read the MAC from AX_NODE_ID (AX_ACCESS_MAC=0x01, reg 0x10, 6 bytes):
     * SETUP = C0 01 10 00 06 00 06 00. Validates the vendor command path. */
    setup = (uint64_t)0xC0u | ((uint64_t)0x01u << 8)
          | ((uint64_t)0x0010u << 16) | ((uint64_t)0x0006u << 32)
          | ((uint64_t)0x0006u << 48);
    if (issue_control_transfer(slot_id, setup, 1) >= 0) {
        int k;
        for (k = 0; k < 6; k++) s_eth.mac[k] = buf[k];
        printk("[XHCI] ax88179 MAC %x:%x:%x:%x:%x:%x\n",
               (unsigned)buf[0], (unsigned)buf[1], (unsigned)buf[2],
               (unsigned)buf[3], (unsigned)buf[4], (unsigned)buf[5]);
    }

    s_eth.present       = 1;
    s_eth.slot_id       = slot_id;
    s_eth.port_num      = port_num;
    s_eth.speed         = speed;
    s_eth.bulk_in_addr  = bin;
    s_eth.bulk_out_addr = bout;
    s_eth.bulk_in_dci   = (uint8_t)(2u * (bin & 0x0Fu) + 1u);
    s_eth.bulk_out_dci  = (uint8_t)(2u * (bout & 0x0Fu));
    s_eth.bulk_in_mps   = bin_mps;
    s_eth.bulk_out_mps  = bout_mps;
    s_eth.bulk_in_burst = bin_burst;
    s_eth.bulk_out_burst = bout_burst;
    s_eth.int_addr      = bint;
    s_eth.int_dci       = bint ? (uint8_t)(2u * (bint & 0x0Fu) + 1u) : 0u;
    /* int_mps is the device-asserted interrupt-EP wMaxPacketSize (up to 0xFFFF)
     * and is used verbatim as the interrupt-IN TRB transfer length over int_buf,
     * a fixed 4096-byte page. A malicious/spoofed device declaring a huge value
     * would DMA past the page (kernel heap overflow). A real interrupt EP is
     * <=1024; clamp to the buffer size. */
    if (bint_mps > 4096u) bint_mps = 4096u;
    s_eth.int_mps       = bint_mps;

    printk("[XHCI] slot %u ASIX AX88179 vid=%x pid=%x cfg=%u "
           "in=0x%x(dci%u mps%u) out=0x%x(dci%u mps%u)\n",
           (unsigned)slot_id, (unsigned)vid, (unsigned)pid, (unsigned)cfg_val,
           (unsigned)bin,  (unsigned)s_eth.bulk_in_dci,  (unsigned)bin_mps,
           (unsigned)bout, (unsigned)s_eth.bulk_out_dci, (unsigned)bout_mps);

    /* Run the ASIX MAC reset/init sequence, then read back key registers to
     * confirm the vendor writes landed and report PHY/link state.
     *
     * NOTE (diag-rev=18→19): do NOT re-issue SET_CONFIGURATION after this reset
     * as a FW_MODE "latch" (FreeBSD axge_reset does, but it runs it BEFORE any
     * xHCI Configure-EP). Re-issuing SET_CONFIGURATION once we've configured the
     * device's endpoints at the xHCI level wedges the vendor control plane: every
     * subsequent AX_ACCESS_MAC read came back 0x0000 (rx_ctl/medium/genstat all
     * zero → RX_CTL.START never set → no RX). The FW_MODE force inside
     * ax88179_reset is sufficient on its own; the interrupt endpoint (armed in
     * configure_bulk) is what actually delivers link state. */
    ax88179_reset(slot_id);

    /* Read back key MAC registers via AX_ACCESS_MAC (which works even though
     * AX_ACCESS_PHY/MDIO appears not to) to confirm the reset write-list landed:
     * RX_CTL START=0x80, MEDIUM RECEIVE_EN=0x100, PHYSICAL_LINK_STATUS USB speed. */
    s_eth.rxctl_rb  = (uint16_t)ax_read_mac(slot_id, 0x0b, 2);
    s_eth.medium_rb = (uint16_t)ax_read_mac(slot_id, 0x22, 2);
    s_eth.plink_rb  = (uint8_t)ax_read_mac(slot_id, 0x02, 1);

    /* MDIO is dead on this UA2 chip, and a boot-time stick-test LOOP (rev-21)
     * hung the splash — control transfers during PHY negotiation are too slow to
     * iterate synchronously in the boot path. Back to rev-20's fast, no-loop,
     * no-sleep config. rev-20 evidence: we wrote gigabit MEDIUM and the chip
     * CLEARED EN_125MHZ(0x08) → the link is NOT gigabit → statically commit
     * 100M full-duplex. Two quick non-looping probes first just record what the
     * chip keeps for each mode (diagnostics, no delay). */
    {
        static const uint8_t bulkin_gig[5] = {0x07, 0x4f, 0x00, 0x12, 0xff};
        static const uint8_t bulkin_100[5] = {0x07, 0xae, 0x07, 0x18, 0xff};
        uint8_t spd = 0;                                   /* 0=none 1=gig 2=100M */
        /* MEDIUM needs ~tens of ms to LATCH a write before a read reflects it
         * (rev-22: back-to-back write/read returned 0). Settle each probe, THEN
         * read the speed-signature bit (EN_125MHZ=0x08 gig / PS=0x200 100M).
         * Bounded total ~150ms — fast boot, no loop. */
        ax_write_mac(slot_id, 0x22, 2, 0x013Bu);                /* probe gigabit */
        xhci_busy_wait_ms(50);
        s_eth.med_gig_rb = (uint16_t)ax_read_mac(slot_id, 0x22, 2);
        if (s_eth.med_gig_rb & 0x0008u) spd = 1;
        ax_write_mac(slot_id, 0x22, 2, 0x0332u);                /* probe 100M */
        xhci_busy_wait_ms(50);
        s_eth.med_100_rb = (uint16_t)ax_read_mac(slot_id, 0x22, 2);
        if (!spd && (s_eth.med_100_rb & 0x0200u)) spd = 2;
        /* Commit the detected speed (fallback 100M). */
        if (spd == 1) {
            ax_write_mac_buf(slot_id, 0x2e, 5, bulkin_gig);
            ax_write_mac(slot_id, 0x22, 2, 0x013Bu);
            s_eth.det_speed = 1000u;
        } else {
            ax_write_mac_buf(slot_id, 0x2e, 5, bulkin_100);
            ax_write_mac(slot_id, 0x22, 2, 0x0332u);
            s_eth.det_speed = (spd == 2u) ? 100u : 0u;          /* 0 = fallback guess */
        }
        xhci_busy_wait_ms(50);
        s_eth.medium_rb = (uint16_t)ax_read_mac(slot_id, 0x22, 2);
        s_eth.link_up   = 1u;
        printk("[XHCI] ax88179 speed=%u med=%x (gig_rb=%x 100_rb=%x) "
               "in_dci=%u out_dci=%u int_dci=%u\n",
               (unsigned)s_eth.det_speed, (unsigned)s_eth.medium_rb,
               (unsigned)s_eth.med_gig_rb, (unsigned)s_eth.med_100_rb,
               (unsigned)s_eth.bulk_in_dci, (unsigned)s_eth.bulk_out_dci,
               (unsigned)s_eth.int_dci);
    }
    /* Configure bulk endpoints and arm the first RX transfer. */
    if (xhci_eth_configure_bulk() == 0) {
        s_eth.configured = 1;
        if (s_dev_ctx[slot_id]) {
            volatile uint32_t *ei = (volatile uint32_t *)
                (s_dev_ctx[slot_id] + (uint32_t)s_eth.bulk_in_dci * XHCI_CTX_ENTRY_SIZE);
            volatile uint32_t *eo = (volatile uint32_t *)
                (s_dev_ctx[slot_id] + (uint32_t)s_eth.bulk_out_dci * XHCI_CTX_ENTRY_SIZE);
            printk("[XHCI] eth EP states: in d0=%x(state=%u) out d0=%x(state=%u)\n",
                   (unsigned)ei[0], (unsigned)(ei[0] & 7u),
                   (unsigned)eo[0], (unsigned)(eo[0] & 7u));
        }
        xhci_eth_submit_rx();
        printk("[XHCI] eth bulk configured (in dci%u out dci%u), RX armed\n",
               (unsigned)s_eth.bulk_in_dci, (unsigned)s_eth.bulk_out_dci);

        /* Register the netdev so the IP stack + DHCP use the adapter. The IP
         * TX path resolves the interface by the literal name "eth0", so the
         * CABLED USB adapter must claim eth0 to be usable. If an onboard NIC
         * already holds eth0 (e.g. the X13's cable-less RTL8168), demote it to
         * eth1 — otherwise outbound packets (DHCP/ARP/TCP) leave via the dead
         * onboard port and nothing works. Runs in xhci enumeration context
         * (single-core, IRQs off) so the rename is race-free. */
        {
            int k;
            netdev_t *inc = netdev_get("eth0");
            if (inc && inc != &s_eth.nd) {
                inc->name[0] = 'e'; inc->name[1] = 't'; inc->name[2] = 'h';
                inc->name[3] = '1'; inc->name[4] = '\0';
                printk("[XHCI] demoted onboard eth0 -> eth1 (USB adapter is primary)\n");
            }
            const char *nm = "eth0";
            for (k = 0; nm[k] && k < 15; k++) s_eth.nd.name[k] = nm[k];
            s_eth.nd.name[k] = '\0';
            for (k = 0; k < 6; k++) s_eth.nd.mac[k] = s_eth.mac[k];
            s_eth.nd.mtu  = 1500;
            s_eth.nd.send = usb_eth_send;
            s_eth.nd.poll = usb_eth_poll;
            s_eth.nd.priv = &s_eth;
            if (netdev_register(&s_eth.nd) == 0) {
                s_eth.registered = 1;
                printk("[XHCI] ax88179 registered as %s\n", s_eth.nd.name);
            } else {
                printk("[XHCI] ax88179 netdev_register FAILED (table full)\n");
            }
        }
    } else {
        printk("[XHCI] eth bulk configure FAILED\n");
    }
    return 1;
}

/* issue_set_protocol — send SET_PROTOCOL(Boot Protocol=0) class request.
 * bmRequestType=0x21 (Host-to-Device, Class, Interface),
 * bRequest=0x0B (SET_PROTOCOL), wValue=0 (Boot Protocol),
 * wIndex=0, wLength=0.  No data stage. */
static void
issue_set_protocol(uint8_t slot_id)
{
    uint64_t setup = (uint64_t)0x21u          /* bmRequestType */
                   | ((uint64_t)0x0Bu << 8)   /* bRequest: SET_PROTOCOL */
                   | ((uint64_t)0u << 16)      /* wValue: 0 = Boot Protocol */
                   | ((uint64_t)0u << 32)      /* wIndex */
                   | ((uint64_t)0u << 48);     /* wLength */
    issue_control_transfer(slot_id, setup, 0);
}

/* All RW1C bits in PORTSC. Writing 1 to any of these clears the
 * corresponding latched change. When we want to set PR/PED/PP/PLS etc.
 * via a read-modify-write, we MUST mask out these bits in the value we
 * write back, otherwise the write will accidentally clear pending
 * change notifications that we (or the PSC handler) need to see. */
#define XHCI_PORTSC_RW1C_MASK   0x00FE0000u  /* CSC|PEC|WRC|OCC|PRC|PLC|CEC */

/* Compute a "clean" PORTSC value safe for read-modify-write: mask out
 * all RW1C bits and PED (which is itself partially write-1-clear on
 * USB 2.0 ports). The caller can then OR in the bits it wants to set. */
static inline uint32_t
portsc_rmw_mask(uint32_t portsc)
{
    return portsc & ~(XHCI_PORTSC_RW1C_MASK | XHCI_PORTSC_PED);
}

/* enumerate_port — detect device on one port (1-based), reset it, run
 * Enable Slot + Address Device + Configure EP, detect HID type, then
 * schedule first interrupt IN transfer if successful. Idempotent — if
 * a slot is already allocated for this port, returns immediately. */
static void
enumerate_port(uint32_t port_num)
{
    /* Idempotency: if we already enumerated this port (boot scan +
     * subsequent PSC event for the same already-connected device),
     * skip — otherwise we'd leak a slot and the old transfer ring. */
    {
        uint32_t s;
        for (s = 1; s < XHCI_MAX_SLOTS; s++) {
            if (s_hid_slots[s] && s_slot_port[s] == (uint8_t)port_num) {
                printk("[XHCI] port %u already enumerated as slot %u, skip\n",
                       (unsigned)port_num, (unsigned)s);
                return;
            }
        }
    }

    /* Port register array: op_base + 0x400 + (port_num-1)*16 */
    uint8_t *op_base = (uint8_t *)s_op;
    /* SAFETY: The port register offset is within the BAR0 mapping. */
    volatile uint32_t *portsc_reg =
        (volatile uint32_t *)(op_base + 0x400u + (port_num - 1u) * 16u);

    uint32_t portsc;
    uint8_t  slot_id;
    uint8_t  speed;

    portsc = *portsc_reg;
    printk("[XHCI] enum port %u portsc=0x%x ccs=%u pr=%u prc=%u\n",
           (unsigned)port_num, (unsigned)portsc,
           (portsc & XHCI_PORTSC_CCS) ? 1u : 0u,
           (portsc & XHCI_PORTSC_PR)  ? 1u : 0u,
           (portsc & XHCI_PORTSC_PRC) ? 1u : 0u);
    if (!(portsc & XHCI_PORTSC_CCS))
        return;   /* nothing connected */

    /* USB 2.0 device debounce: if we just saw the device connect, give
     * it the spec-mandated 100ms TATTDB before resetting. The boot
     * scan path doesn't strictly need this (the device has been
     * connected since power-up), but the hotplug path absolutely does. */
    xhci_busy_wait_ms(120);

    /* Re-read after debounce in case the device went away. */
    portsc = *portsc_reg;
    if (!(portsc & XHCI_PORTSC_CCS))
        return;

    /* Reset the port. A USB2 port needs a hot reset (PORTSC.PR). A USB3
     * (SuperSpeed) port is different: the controller link-trains it to
     * Enabled/U0 the instant the device connects, so PED is ALREADY set.
     * Issuing a USB2 hot reset on an already-enabled SuperSpeed port disturbs
     * the trained link and makes Address Device fail on real silicon (QEMU
     * tolerates it — which is why FS devices enumerate but the SS adapter
     * failed at Address Device on the X13). So for a USB3 port that is already
     * Enabled, SKIP the reset and proceed straight to Enable Slot. Only USB2
     * ports, or a USB3 port not yet enabled, get the PORTSC.PR hot reset. */
    if (port_num <= XHCI_MAX_PORTS && s_port_is_usb3[port_num] &&
        (portsc & XHCI_PORTSC_PED)) {
        if (!s_post_boot)
            printk("[XHCI] port %u: USB3 already enabled (portsc=0x%x), skipping hot reset\n",
                   (unsigned)port_num, (unsigned)portsc);
    } else {
        /* USB2 (or not-yet-enabled) port: hot reset via PORTSC.PR.
         * Mask out RW1C bits so we don't accidentally clear them. */
        *portsc_reg = portsc_rmw_mask(portsc) | XHCI_PORTSC_PR;

        /* Wait up to ~100ms for PRC (Port Reset Change) to set. Real
         * hardware can take 50-80ms. Use rdtsc-based timing because
         * xhci_init runs early in boot before PIT IRQs fire. */
        {
            if (s_cycles_per_ms == 0) s_cycles_per_ms = xhci_ticks_per_ms();
            uint64_t deadline = xhci_rdtsc() + 100ULL * s_cycles_per_ms;
            while (xhci_rdtsc() < deadline) {
                if (*portsc_reg & XHCI_PORTSC_PRC)
                    break;
                xhci_relax();
            }
        }
        if (!(*portsc_reg & XHCI_PORTSC_PRC)) {
            if (port_num <= XHCI_MAX_PORTS) s_enum_stage[port_num] = XHCI_ENUM_RESET_TO;
            if (!s_post_boot)
                printk("[XHCI] port %u: reset timeout (portsc=0x%x)\n",
                       (unsigned)port_num, (unsigned)*portsc_reg);
            return;
        }
        /* Clear PRC by writing 1 to it (RW1C) — but ONLY PRC, not other
         * pending change bits which the PSC handler may need to see. */
        *portsc_reg = portsc_rmw_mask(*portsc_reg) | XHCI_PORTSC_PRC;
    }

    /* Re-read speed AFTER reset — for some controllers the speed field
     * is only valid post-reset. */
    portsc = *portsc_reg;
    speed = (uint8_t)((portsc >> 10) & 0xFu);
    if (speed == 0)
        speed = XHCI_SPEED_HS;
    printk("[XHCI] port %u speed=%u (1=FS,2=LS,3=HS,4=SS) post-reset\n",
           (unsigned)port_num, (unsigned)speed);

    /* USB 2.0 spec §7.1.7.5 TRSTRCY: device needs ≥10ms after reset
     * before the host can issue SETUP. Real hardware is sensitive
     * to this — qemu auto-completes so this was invisible there. */
    xhci_busy_wait_ms(20);

    /* Pre-Enable-Slot diagnostic dump */
    {
        uint32_t usbsts = op_read32(XHCI_OP_USBSTS_OFF);
        uint32_t usbcmd = op_read32(XHCI_OP_USBCMD_OFF);
        printk("[XHCI] before EnableSlot: usbcmd=0x%x usbsts=0x%x s_cmd_enq=%u s_cmd_cyc=%u s_evt_deq=%u s_evt_cyc=%u\n",
               (unsigned)usbcmd, (unsigned)usbsts,
               (unsigned)s_cmd_enqueue, (unsigned)s_cmd_cycle,
               (unsigned)s_evt_dequeue, (unsigned)s_evt_cycle);
    }

    /* Enable Slot */
    slot_id = issue_enable_slot();

    /* Post-Enable-Slot diagnostic dump */
    {
        uint32_t usbsts = op_read32(XHCI_OP_USBSTS_OFF);
        printk("[XHCI] after EnableSlot: slot_id=%u usbsts=0x%x evt_ring[0].ctrl=0x%x evt_ring[0].status=0x%x\n",
               (unsigned)slot_id, (unsigned)usbsts,
               (unsigned)s_evt_ring[0].control,
               (unsigned)s_evt_ring[0].status);
    }

    if (slot_id == 0 || slot_id >= XHCI_MAX_SLOTS) {
        if (port_num <= XHCI_MAX_PORTS) s_enum_stage[port_num] = XHCI_ENUM_SLOT_FAIL;
        if (!s_post_boot)
            printk("[XHCI] port %u: Enable Slot failed\n", (unsigned)port_num);
        return;
    }

    /* Allocate the Output Device Context and install its PA in DCBAA[slot]
     * BEFORE Address Device (xHCI §4.3.3 step 4). alloc_page returns a zeroed
     * page; reuse the existing one across re-enumeration of the same slot. */
    if (!s_dev_ctx[slot_id])
        s_dev_ctx[slot_id] = (uint8_t *)alloc_page(&s_dev_ctx_phys[slot_id]);
    s_dcbaa[slot_id] = s_dev_ctx_phys[slot_id];

    /* Allocate transfer ring for this slot */
    {
        xhci_trb_t *xr =
            (xhci_trb_t *)alloc_page(&s_xfer_ring_phys[slot_id]);
        s_xfer_ring[slot_id]    = xr;
        s_xfer_enqueue[slot_id] = 0;
        s_xfer_cycle[slot_id]   = 1;
        /* Link TRB at end — wraps back to start, toggle-cycle=1 */
        xr[XHCI_TRANSFER_RING_SIZE - 1].param   = s_xfer_ring_phys[slot_id];
        xr[XHCI_TRANSFER_RING_SIZE - 1].status  = 0;
        xr[XHCI_TRANSFER_RING_SIZE - 1].control =
            (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | 1u;
    }

    /* Allocate 8-byte HID boot report buffer */
    s_hid_buf[slot_id] =
        (uint8_t *)alloc_page(&s_hid_buf_phys[slot_id]);

    /* Address Device */
    if (issue_address_device(slot_id, (uint8_t)port_num, speed) != 0) {
        if (port_num <= XHCI_MAX_PORTS) {
            s_enum_stage[port_num]  = XHCI_ENUM_ADDR_FAIL;
            s_enum_cc[port_num]     = s_last_cmd_cc;
            s_enum_usbsts[port_num] = op_read32(XHCI_OP_USBSTS_OFF);
        }
        if (!s_post_boot)
            printk("[XHCI] port %u: Address Device failed (cc=%u usbsts=0x%x)\n",
                   (unsigned)port_num, (unsigned)s_last_cmd_cc,
                   (unsigned)op_read32(XHCI_OP_USBSTS_OFF));
        return;
    }
    printk("[XHCI] slot %u Address Device OK\n", (unsigned)slot_id);

    /* Classify the device via its Configuration Descriptor over EP0 FIRST.
     * EP0 is set up by Address Device, so this needs no Configure-Endpoint.
     * Doing it before Configure-EP is essential: a non-HID device (USB
     * ethernet — bulk-only, no interrupt endpoint) must NOT be forced through
     * the HID interrupt-EP setup, which a real controller rejects (cc != 1) →
     * the old code returned here and the ethernet probe never ran. */
    {
        uint8_t proto = detect_hid_protocol(slot_id);
        printk("[XHCI] slot %u detect_hid_protocol returned %u\n",
               (unsigned)slot_id, (unsigned)proto);

        if (proto != 1 && proto != 2) {
            /* Not HID — hand off to the USB-ethernet probe, which configures
             * its OWN bulk endpoints. The HID interrupt EP is never installed. */
            if (port_num <= XHCI_MAX_PORTS) s_enum_stage[port_num] = XHCI_ENUM_PROBED;
            if (detect_interface_class(slot_id) == 0x08u)   /* USB mass storage */
                probe_usb_msc(slot_id, (uint8_t)port_num, speed);
            else
                probe_usb_ethernet(slot_id, (uint8_t)port_num, speed);
            return;
        }

        /* HID device. FIRST put it in the Configured state via a USB
         * SET_CONFIGURATION(1): the xHCI Configure Endpoint command below only
         * sets up the HOST-side endpoint contexts — the DEVICE only enables its
         * interrupt endpoint once it's configured. Without this the interrupt-IN
         * gets no valid response (cc=4 USB Transaction Error) and the endpoint
         * halts, so no keystroke/motion report is ever delivered (the strict RP1
         * dwc3 exposes it; lenient x86/QEMU device models answered regardless).
         * Then SET_PROTOCOL(boot). Both are EP0 control transfers and must
         * precede Configure Endpoint: the interrupt EP shares EP0's transfer
         * ring, and issue_configure_ep snapshots its TR Dequeue Pointer to the
         * current ring position — no EP0 traffic may follow that snapshot. All
         * boot-HID configurations use bConfigurationValue=1. */
        {
            uint64_t sc = (uint64_t)0x00u          /* bmRequestType: H2D/std/dev */
                        | ((uint64_t)0x09u << 8)   /* bRequest = SET_CONFIGURATION */
                        | ((uint64_t)1u    << 16); /* wValue = config #1          */
            issue_control_transfer(slot_id, sc, 0);   /* no data stage */
        }
        issue_set_protocol(slot_id);

        /* Now install the interrupt IN endpoint. */
        if (issue_configure_ep(slot_id, (uint8_t)port_num, speed) != 0) {
            if (port_num <= XHCI_MAX_PORTS) s_enum_stage[port_num] = XHCI_ENUM_CFG_FAIL;
            if (!s_post_boot)
                printk("[XHCI] port %u: Configure Endpoint failed\n",
                       (unsigned)port_num);
            return;
        }
        printk("[XHCI] slot %u Configure EP OK\n", (unsigned)slot_id);

        s_hid_slots[slot_id]     = 1;
        s_hid_slot_type[slot_id] = (proto == 1) ? USB_DEV_KBD : USB_DEV_MOUSE;
        s_slot_port[slot_id]     = (uint8_t)port_num;
    }

    if (port_num <= XHCI_MAX_PORTS) s_enum_stage[port_num] = XHCI_ENUM_HID_OK;

    /* Schedule the first interrupt IN transfer.
     * Note: we only queue ONE TRB and re-arm after each completion.
     * This is fine for keyboards (typing rate << polling rate). If
     * report drops are observed under load, increase the queue depth. */
    xhci_schedule_interrupt_in(slot_id, XHCI_EP1_IN_DCI,
                               s_hid_buf_phys[slot_id], 8u);
    printk("[XHCI] slot %u HID %s ready, first interrupt-in scheduled\n",
           (unsigned)slot_id,
           s_hid_slot_type[slot_id] == USB_DEV_MOUSE ? "mouse" : "kbd");
}

/* -------------------------------------------------------------------------
 * xhci_init
 * ---------------------------------------------------------------------- */

/* xhci_init_one — initialize a single xHCI controller and return:
 *   1 = success and at least one port has a connected device
 *   0 = success but no devices found (try next controller)
 *  -1 = init failure (controller broken or unsupported)
 *
 * Refactored from xhci_init to support multi-controller systems where
 * the keyboard might be on the second/third/fourth xhci PCI device. */
static int
xhci_init_one(const pcie_device_t *dev);

void
xhci_init(void)
{
    /* Step 1: Locate ALL xHCI controllers via PCIe.
     * class=0x0C (Serial Bus), subclass=0x03 (USB), prog-if=0x30 (xHCI).
     *
     * Modern AMD platforms (Ryzen 6800H) expose 2-4 xHCI controllers.
     * We try each in order, stopping at the first one that successfully
     * initializes AND has at least one connected port. The keyboard may
     * be on any of them depending on which physical USB jack is used. */
    int n_xhci = 0;
    int n_dev = pcie_device_count();
    int j;
    /* Count total xHCI controllers up front (for /proc/usbnet diagnostics) so
     * the user can tell "4 controllers exist, only #1 was scanned". */
    s_hdiag_total = 0;
    s_hdiag_count = 0;
    s_hdiag_adopted = -1;
    for (j = 0; j < n_dev; j++) {
        const pcie_device_t *d = &pcie_get_devices()[j];
        if (d->class_code == 0x0C && d->subclass == 0x03 && d->progif == 0x30)
            s_hdiag_total++;
    }
    for (j = 0; j < n_dev; j++) {
        const pcie_device_t *d = &pcie_get_devices()[j];
        if (d->class_code != 0x0C || d->subclass != 0x03 || d->progif != 0x30)
            continue;
        n_xhci++;
        printk("[XHCI] trying controller #%u at %x:%x.%x (vendor=%x device=%x)\n",
               (unsigned)n_xhci, (unsigned)d->bus, (unsigned)d->dev, (unsigned)d->fn,
               (unsigned)d->vendor_id, (unsigned)d->device_id);
        int rc = xhci_init_one(d);
        /* Record this controller's outcome for /proc/usbnet. */
        if (s_hdiag_count < XHCI_HDIAG_MAX) {
            s_hdiag[s_hdiag_count].bus    = d->bus;
            s_hdiag[s_hdiag_count].dev    = d->dev;
            s_hdiag[s_hdiag_count].fn     = d->fn;
            s_hdiag[s_hdiag_count].vendor = d->vendor_id;
            s_hdiag[s_hdiag_count].device = d->device_id;
            s_hdiag[s_hdiag_count].result = (rc > 0) ? 1 : (rc == 0 ? 0 : -1);
            if (rc > 0) s_hdiag_adopted = (int8_t)s_hdiag_count;
            s_hdiag_count++;
        }
        if (rc > 0) {
            printk("[XHCI] controller #%u has connected device(s) — adopting\n",
                   (unsigned)n_xhci);
            /* This PCI-scan path (x86) adopts a single controller into s_hc[0]
             * (s_cur's default); mark one controller live so xhci_poll iterates
             * it. (The native RP1 path uses xhci_init_at, which counts its own.) */
            s_hc_count = 1;
            return;
        }
        if (rc == 0) {
            printk("[XHCI] controller #%u empty, trying next\n",
                   (unsigned)n_xhci);
            /* Reset state for next controller. */
            s_xhci_active = 0;
            s_post_boot   = 0;
            s_bar0_va     = NULL;
            s_evt_ring_phys = 0;
            s_cap         = NULL;
            s_op          = NULL;
            s_cmd_ring    = NULL;
            s_evt_ring    = NULL;
            s_dcbaa       = NULL;
            s_evt_dequeue = 0;
            s_evt_cycle   = 1;
            s_cmd_enqueue = 0;
            s_cmd_cycle   = 1;
            __builtin_memset(s_port_is_usb2, 0, sizeof(s_port_is_usb2));
            __builtin_memset(s_port_is_usb3, 0, sizeof(s_port_is_usb3));
            __builtin_memset(s_pending_enum, 0, sizeof(s_pending_enum));
            continue;
        }
        printk("[XHCI] controller #%u init failed, trying next\n",
               (unsigned)n_xhci);
    }
    if (n_xhci == 0)
        return;   /* no xHCI device — silent skip */
    printk("[XHCI] no xHCI controller had connected devices\n");
}

/* xhci_init_at — bring up an xHCI controller at an explicit MMIO base rather
 * than a discoverable PCI function. For the RP1 dwc3 on Pi 5, whose xHCI
 * registers are an MMIO block inside the RP1 BAR1 window. The caller must have
 * put the dwc3 core in host mode and, for a non-coherent bus, called
 * xhci_set_dma_noncoherent(1) first. Injects a synthetic pcie_device_t with
 * bus==0xFF so xhci_init_one skips the PCI config-space step. */
void
xhci_init_at(uint64_t bar0_phys)
{
    if (s_hc_count >= XHCI_MAX_HC) {
        printk("[XHCI] init_at 0x%lx: no free controller slot\n", bar0_phys);
        return;
    }
    /* Claim the next controller slot; all the s_* state now redirects here. */
    s_cur = &s_hc[s_hc_count];
    pcie_device_t d;
    __builtin_memset(&d, 0, sizeof(d));
    d.bus = 0xFFu; d.dev = 0; d.fn = 0;
    d.class_code = 0x0Cu; d.subclass = 0x03u; d.progif = 0x30u;
    d.bar[0] = bar0_phys;
    int rc = xhci_init_one(&d);
    printk("[XHCI] init_at 0x%lx (hc%u) -> rc=%d\n",
           bar0_phys, (unsigned)s_hc_count, rc);
    /* Keep any controller that initialised (rc 0=empty or 1=has device) so
     * xhci_poll iterates it; the per-controller `active` guard skips empties.
     * rc<0 means the controller is broken — leave the slot for reuse. */
    if (rc >= 0)
        s_hc_count++;
}

/* The actual init body. Returns 1=success+ports, 0=success+empty, -1=fail. */
static int
xhci_init_one(const pcie_device_t *dev)
{
    uint32_t i;

    /* Step 1.5: enable PCI Memory Space + Bus Master BEFORE any BAR0 MMIO.
     * Real AMD silicon hands the controller over with these bits CLEAR when
     * firmware never powered USB (the X13 boots from NVMe with a PS/2 keyboard,
     * so its xHCI controllers are left disabled). With Memory Space disabled
     * every MMIO read returns 0xFFFFFFFF (HCRST never clears → init "fails");
     * with Bus Master disabled the controller cannot DMA completion TRBs into
     * the event ring, so no command/transfer ever completes and nothing
     * enumerates. QEMU pre-enables both, which is why this was invisible until
     * bare metal. Mirrors rtl8169.c (pcie.h exposes only 32-bit cfg writes).
     * Skipped for an injected MMIO controller (bus==0xFF, e.g. the RP1 dwc3):
     * it has no PCI config space, and firmware already enabled it. */
    if (dev->bus != 0xFFu) {
        uint32_t cmd = pcie_read32(dev->bus, dev->dev, dev->fn, 0x04);
        cmd &= 0xFFFF0000u;     /* preserve the status word (upper 16 bits) */
        cmd |= 0x02u | 0x04u;   /* bit1 = Memory Space Enable, bit2 = Bus Master */
        pcie_write32(dev->bus, dev->dev, dev->fn, 0x04, cmd);
    }

    /* Step 2: Map BAR0 MMIO.
     * pcie_device_t stores decoded 64-bit base addresses in bar[].
     * pcie.c strips the flag bits during enumeration (same as nvme.c).
     * Map with WC+UCMINUS (uncached MMIO). */
    {
        uint64_t  bar0_phys = dev->bar[0];
        uintptr_t bar0_kva  = (uintptr_t)kva_alloc_pages(XHCI_BAR0_PAGES);

        for (i = 0; i < XHCI_BAR0_PAGES; i++) {
            uintptr_t va = bar0_kva + (uintptr_t)i * 4096u;
            /* Unmap the PMM-backed page kva_alloc_pages installed so that
             * vmm_map_page does not panic on a double-map.
             * SAFETY: va is a present kva page; vmm_unmap_page is valid. */
            vmm_unmap_page(va);
            /* SAFETY: map BAR0 MMIO uncached (WC+UCMINUS = PWT+PCD).
             * The PA is device MMIO; the kernel VA is the intended accessor. */
            vmm_map_page(va, bar0_phys + (uint64_t)i * 4096u,
                         VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS);
        }
        s_bar0_va = (uint8_t *)bar0_kva;
    }

    /* SAFETY: s_cap/s_op are volatile casts of MMIO-mapped kernel VAs. */
    s_cap = (volatile xhci_cap_regs_t *)s_bar0_va;
    s_op  = (volatile xhci_op_regs_t  *)(s_bar0_va + s_cap->caplength);

    s_max_slots = (s_cap->hcsparams1)       & 0xFFu;
    s_max_ports = (s_cap->hcsparams1 >> 24) & 0xFFu;

    /* HCCPARAMS1.CSZ (bit 2) — 0 = 32-byte contexts, 1 = 64-byte. */
    s_ctx_entry_size = (s_cap->hccparams1 & (1u << 2)) ? 64u : 32u;
    printk("[XHCI] hccparams1=0x%x ctx_size=%u\n",
           (unsigned)s_cap->hccparams1, (unsigned)s_ctx_entry_size);

    /* Step 2.5: BIOS handoff (USBLEGSUP).
     *
     * On real hardware (especially AMD), the BIOS owns the controller
     * via SMI until we walk the extended capabilities and explicitly
     * claim ownership. Without this, BIOS SMM keeps fighting our
     * register writes and the keyboard never enumerates. Must run
     * BEFORE any USBCMD writes. QEMU has no LEGSUP cap so this is
     * a no-op there. */
    xhci_bios_handoff();

    /* Step 2.6: Walk Supported Protocol caps to learn which port
     * numbers are USB 2.0 vs USB 3.x. The boot scan loop uses this
     * to skip dead SS-only ports. */
    xhci_walk_supported_protocols();

    /* Step 3: Stop controller — clear USBCMD.RS, wait for USBSTS.HCH.
     * Use op_read32/op_write32 to avoid packed-member address errors. */
    op_write32(XHCI_OP_USBCMD_OFF,
               op_read32(XHCI_OP_USBCMD_OFF) & ~XHCI_CMD_RS);
    /* Real hardware can take 16ms+ to halt; the 100ms timeout here
     * is real-time, not a fixed-iteration loop. */
    if (op_spin_until_set_ms(XHCI_OP_USBSTS_OFF, XHCI_STS_HCH, 100u) != 0) {
        printk("[XHCI] FAIL: controller did not stop\n");
        return -1;
    }

    printk("[XHCI] pre-HCRST usbsts=0x%x usbcmd=0x%x\n",
           (unsigned)op_read32(XHCI_OP_USBSTS_OFF),
           (unsigned)op_read32(XHCI_OP_USBCMD_OFF));

    /* Step 4: Reset controller — set USBCMD.HCRST, wait for it to clear. */
    op_write32(XHCI_OP_USBCMD_OFF,
               op_read32(XHCI_OP_USBCMD_OFF) | XHCI_CMD_HCRST);
    if (op_spin_until_clear(XHCI_OP_USBCMD_OFF, XHCI_CMD_HCRST) != 0) {
        printk("[XHCI] FAIL: controller reset timeout\n");
        return -1;
    }
    printk("[XHCI] post-HCRST usbsts=0x%x\n",
           (unsigned)op_read32(XHCI_OP_USBSTS_OFF));

    /* xHCI spec §4.2: software shall not write any operational/runtime
     * register (other than USBSTS) until USBSTS.CNR is '0'. */
    if (op_spin_until_clear(XHCI_OP_USBSTS_OFF, XHCI_STS_CNR) != 0) {
        printk("[XHCI] FAIL: CNR did not clear after reset\n");
        return -1;
    }
    printk("[XHCI] post-CNR-clear usbsts=0x%x\n",
           (unsigned)op_read32(XHCI_OP_USBSTS_OFF));

    /* Clear any sticky RW1C bits in USBSTS so we start with a clean slate. */
    op_write32(XHCI_OP_USBSTS_OFF,
               XHCI_STS_HSE | XHCI_STS_EINT | XHCI_STS_HCE);
    printk("[XHCI] post-RW1C-clear usbsts=0x%x\n",
           (unsigned)op_read32(XHCI_OP_USBSTS_OFF));

    /* Step 5: Allocate DCBAA (Device Context Base Address Array).
     * DCBAA[0] is reserved for the Scratchpad Buffer Array pointer
     * (if MaxScratchpadBufs > 0); slots are 1..MaxSlots. */
    {
        uint8_t *dcbaa_va = (uint8_t *)alloc_page(&s_dcbaa_phys);
        s_dcbaa      = (uint64_t *)dcbaa_va;

        /* Step 5.1: Scratchpad buffers.
         *
         * HCSPARAMS2 holds Max Scratchpad Bufs:
         *   bits 25:21 = Max Scratchpad Bufs Hi
         *   bits 31:27 = Max Scratchpad Bufs Lo
         * Total = (Hi << 5) | Lo.
         *
         * If non-zero, the OS MUST allocate that many 4KB pages and
         * install pointers in a Scratchpad Buffer Array, whose
         * physical address goes in DCBAA[0]. AMD Ryzen / Renesas
         * controllers commonly require 1-8 scratchpad buffers; QEMU
         * reports 0. Without this on real HW, the controller posts
         * Host System Error after USBCMD.RS=1 and Address Device
         * fails with cc=5/HCE. */
        uint32_t hcsp2 = s_cap->hcsparams2;
        uint32_t max_sp = (((hcsp2 >> 21) & 0x1Fu) << 5) |
                          ((hcsp2 >> 27) & 0x1Fu);
        printk("[XHCI] hcsparams2=0x%x max_scratchpad_bufs=%u\n",
               (unsigned)hcsp2, (unsigned)max_sp);
        if (max_sp > 0) {
            uint64_t  sp_array_phys;
            uint64_t *sp_array = (uint64_t *)alloc_page(&sp_array_phys);
            uint32_t  i;
            for (i = 0; i < max_sp && i < 512; i++) {
                uint64_t sp_buf_phys;
                (void)alloc_page(&sp_buf_phys);
                sp_array[i] = sp_buf_phys;
            }
            s_dcbaa[0] = sp_array_phys;
            printk("[XHCI] scratchpad: allocated %u bufs, array PA=0x%x\n",
                   (unsigned)max_sp, (unsigned)sp_array_phys);
        }

        /* SAFETY: s_op->dcbaap is a packed MMIO field at a known fixed offset.
         * Writing through op_write32 would require a 64-bit accessor; the
         * dcbaap field is at offset 0x30 in xhci_op_regs_t.  Access it via
         * a volatile 64-bit pointer derived from the base address. */
        {
            volatile uint64_t *dcbaap =
                (volatile uint64_t *)((volatile uint8_t *)s_op + 0x30u);
            *dcbaap = s_dcbaa_phys;
        }
    }

    /* Step 6: Command Ring — alloc one page, place Link TRB at index 63,
     * write CRCR with PA | RCS (Running Cycle State = initial cycle bit). */
    {
        s_cmd_ring    = (xhci_trb_t *)alloc_page(&s_cmd_ring_phys);
        s_cmd_enqueue = 0;
        s_cmd_cycle   = 1;

        s_cmd_ring[XHCI_CMD_RING_SIZE - 1].param   = s_cmd_ring_phys;
        s_cmd_ring[XHCI_CMD_RING_SIZE - 1].status  = 0;
        s_cmd_ring[XHCI_CMD_RING_SIZE - 1].control =
            (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) | 1u;

        /* CRCR at offset 0x18 in xhci_op_regs_t */
        {
            volatile uint64_t *crcr =
                (volatile uint64_t *)((volatile uint8_t *)s_op + 0x18u);
            *crcr = s_cmd_ring_phys | 1u;   /* PA | RCS=1 */
        }
    }

    /* Steps 7+8+9: Event Ring Segment + ERST + Interrupter 0 registers */
    {
        uint64_t              evt_ring_phys;
        volatile xhci_trb_t  *evt_ring;
        uint64_t              erst_phys;
        uint64_t             *erst;
        uint8_t              *rts;

        evt_ring        = (volatile xhci_trb_t *)alloc_page(&evt_ring_phys);
        s_evt_ring      = evt_ring;
        s_evt_ring_phys = evt_ring_phys;
        s_evt_dequeue   = 0;
        s_evt_cycle     = 1;

        /* ERST entry (16 bytes):
         *   [0..7]:   Ring Segment Base Address (64-bit PA)
         *   [8..11]:  Ring Segment Size (TRB count, low 32 bits)
         *   [12..15]: Reserved — zeroed by alloc_page */
        erst    = (uint64_t *)alloc_page(&erst_phys);
        erst[0] = evt_ring_phys;
        erst[1] = XHCI_EVT_RING_SIZE;   /* low 32-bit count; high 32=0 */

        /* Interrupter 0 register set (xHCI 1.0 §5.5.2):
         *   IMAN   at +0x00 (32-bit) — Interrupter Management
         *   IMOD   at +0x04 (32-bit) — Interrupter Moderation
         *   ERSTSZ at +0x08 (32-bit) — Event Ring Segment Table Size
         *   (reserved at +0x0C)
         *   ERSTBA at +0x10 (64-bit) — Event Ring Segment Table Base Address
         *   ERDP   at +0x18 (64-bit) — Event Ring Dequeue Pointer
         *
         * The interrupter registers begin at runtime_base + 0x20 (the first
         * 0x20 bytes are MFINDEX + reserved). */
        rts = s_bar0_va + s_cap->rtsoff;
        {
            volatile uint32_t *erstsz =
                (volatile uint32_t *)(rts + 0x20u + 0x08u);
            volatile uint64_t *erstba =
                (volatile uint64_t *)(rts + 0x20u + 0x10u);
            volatile uint64_t *erdp =
                (volatile uint64_t *)(rts + 0x20u + 0x18u);

            *erstsz = 1u;
            *erstba = erst_phys;
            *erdp   = evt_ring_phys;
        }
    }

    /* Step 10: Configure MaxSlotsEn (CONFIG register at offset 0x38) */
    {
        volatile uint32_t *config_reg =
            (volatile uint32_t *)((volatile uint8_t *)s_op + 0x38u);
        *config_reg = s_max_slots;
    }

    /* Step 11: Start controller — set USBCMD.RS, wait for HCH to clear. */
    op_write32(XHCI_OP_USBCMD_OFF,
               op_read32(XHCI_OP_USBCMD_OFF) | XHCI_CMD_RS);
    if (op_spin_until_clear(XHCI_OP_USBSTS_OFF, XHCI_STS_HCH) != 0) {
        printk("[XHCI] FAIL: controller did not start\n");
        return -1;
    }
    {
        uint32_t usbsts = op_read32(XHCI_OP_USBSTS_OFF);
        uint32_t usbcmd = op_read32(XHCI_OP_USBCMD_OFF);
        volatile uint64_t *crcr =
            (volatile uint64_t *)((volatile uint8_t *)s_op + 0x18u);
        printk("[XHCI] running: usbcmd=0x%x usbsts=0x%x crcr=0x%x cmd_ring_phys=0x%x\n",
               (unsigned)usbcmd, (unsigned)usbsts,
               (unsigned)*crcr, (unsigned)s_cmd_ring_phys);
    }

    /* Step 11.5: Power on every port (set PORTSC.PP) before sensing
     * connect status. Controllers with Port Power Control (PPC=1, the
     * norm on real hardware) bring ports up UNPOWERED after HCRST, so
     * CCS reads 0 and devices are never seen. The firmware only leaves
     * ports powered if it used USB itself (e.g. booting from a USB
     * stick) — so a keyboard works on the live USB boot but vanishes on
     * an NVMe-booted installed system. Set PP unconditionally (idempotent
     * where firmware already powered them, e.g. QEMU) and wait for the
     * power-good settle before sensing CCS. */
    int powered_any = 0;
    for (i = 1; i <= s_max_ports && i <= XHCI_MAX_PORTS; i++) {
        volatile uint32_t *portsc_reg =
            (volatile uint32_t *)((volatile uint8_t *)s_op + 0x400u +
                                  (i - 1u) * 16u);
        uint32_t pv = *portsc_reg;
        if (!(pv & XHCI_PORTSC_PP)) {
            *portsc_reg = portsc_rmw_mask(pv) | XHCI_PORTSC_PP;
            powered_any = 1;
        }
    }
    /* Only pay the settle delay when we actually powered a port up. Ports
     * already powered by firmware (or QEMU) have a valid CCS immediately,
     * so the common fast path is unaffected. A freshly powered port needs
     * power-good (~20ms) PLUS USB connect debounce (~100ms) before CCS is
     * meaningful, or the pre-scan below would miss a real device. */
    if (powered_any) {
        printk("[XHCI] powered ports (PPC controller); waiting for connect\n");
        xhci_busy_wait_ms(150);
    }

    /* Step 12: Pre-scan ports to see if any have a connected device.
     * If none do, return 0 to let xhci_init try the next controller
     * — the keyboard might be on a different xhci PCI device. */
    int connected_ports = 0;
    for (i = 1; i <= s_max_ports && i <= XHCI_MAX_PORTS; i++) {
        volatile uint32_t *portsc_reg =
            (volatile uint32_t *)((volatile uint8_t *)s_op + 0x400u +
                                  (i - 1u) * 16u);
        if (*portsc_reg & XHCI_PORTSC_CCS)
            connected_ports++;
    }
    printk("[XHCI] %u port(s) have CCS=1\n", (unsigned)connected_ports);
    if (connected_ports == 0) {
        /* No devices on this controller — caller will try the next. */
        return 0;
    }

    /* Enumerate every port that has a connected device. We try ALL
     * ports — even ones marked USB 3.x — because:
     *   1. The Supported Protocol cap walk may have failed silently.
     *   2. enumerate_port early-returns on CCS=0, so it's cheap.
     *   3. A misclassified port would otherwise become invisible. */
    for (i = 1; i <= s_max_ports && i <= XHCI_MAX_PORTS; i++)
        enumerate_port(i);

    s_xhci_active = 1;
    s_post_boot   = 1;

    printk("[XHCI] OK: %u ports, %u slots\n",
           (unsigned)s_max_ports, (unsigned)s_max_slots);
    return 1;
}

/* -------------------------------------------------------------------------
 * xhci_poll — called from PIT ISR at 100 Hz
 * ---------------------------------------------------------------------- */

void
xhci_poll(void)
{
    volatile xhci_trb_t *trb;

    /* Service EVERY brought-up controller. RP1 has two independent xHCIs, so
     * the keyboard and mouse can live on different ones; s_cur redirects all
     * the s_* state at the controller being serviced this iteration. */
    for (uint32_t hc = 0; hc < s_hc_count; hc++) {
    s_cur = &s_hc[hc];

    if (!s_xhci_active)
        continue;
    /* USB mass storage drives the event ring synchronously (CBW/data/CSW). While
     * it does, the ISR must NOT consume the shared event ring or it desyncs the
     * cycle bit out from under the MSC poll. */
    if (s_msc_busy)
        continue;

    trb = &s_evt_ring[s_evt_dequeue];

    /* SAFETY: trb is a volatile pointer into a kva-mapped page; the hardware
     * writes the cycle bit when a TRB is posted.  Volatile prevents the
     * compiler from hoisting the load out of the while loop. */
    while ((trb->control & 1u) == (uint32_t)s_evt_cycle) {
        uint32_t ctrl     = trb->control;
        uint32_t trb_type = (ctrl >> 10) & 0x3Fu;
        uint8_t  slot     = (uint8_t)((ctrl >> 24) & 0xFFu);

        if (trb_type == XHCI_TRB_TRANSFER_EVENT &&
            slot > 0 && slot < XHCI_MAX_SLOTS && s_hid_slots[slot]) {
            /* NOTE: no per-report printk here. This fires on EVERY HID transfer
             * event — every keystroke and every mouse-motion report. A moving
             * USB mouse emits ~125 reports/sec; each printk is a synchronous
             * ~200-byte serial write (~17 ms @ 115200), so the dump used to flood
             * COM1 and bog the whole system down on real hardware whenever a
             * mouse moved. Per-report diagnostics belong behind a debug flag, not
             * unconditionally on the hot input path. */
            if (!s_hid_buf[slot]) goto next_trb;  /* alloc failure guard */
            if (s_hid_slot_type[slot] == USB_DEV_KBD)
                usb_hid_process_report(s_hid_buf[slot], 8u);
            else if (s_hid_slot_type[slot] == USB_DEV_MOUSE)
                usb_mouse_process_report(s_hid_buf[slot], 8u);
            /* Re-arm: schedule the next interrupt IN */
            xhci_schedule_interrupt_in(slot, XHCI_EP1_IN_DCI,
                                       s_hid_buf_phys[slot], 8u);
        }

        /* USB ethernet bulk completion: route by Endpoint ID (control[20:16]). */
        if (trb_type == XHCI_TRB_TRANSFER_EVENT && s_eth.present &&
            s_eth.configured && slot == s_eth.slot_id) {
            uint8_t  ep_id    = (uint8_t)((ctrl >> 16) & 0x1Fu);
            uint32_t residual = trb->status & 0xFFFFFFu;
            if (ep_id == s_eth.bulk_in_dci) {
                uint32_t rxlen = (s_eth.rx_buf_len > residual)
                               ? s_eth.rx_buf_len - residual : 0u;
                xhci_eth_rx_complete(rxlen);
                xhci_eth_submit_rx();           /* re-arm RX */
            } else if (ep_id == s_eth.bulk_out_dci) {
                s_eth.tx_inflight = 0;          /* TX slot free */
                s_eth.tx_done++;
            } else if (s_eth.int_dci && ep_id == s_eth.int_dci) {
                /* Link-status report (mainline ax88179_status): intdata1 bit 16
                 * = AX_INT_PPLS_LINK. On a 0→1 transition, force the MAC to a
                 * gigabit-full-duplex medium so RX flows even though MDIO is
                 * dead on this UA2 silicon. */
                uint32_t d1 = le32(s_eth.int_buf);
                uint8_t  up = (d1 & (1u << 16)) ? 1u : 0u;
                s_eth.int_count++;
                s_eth.intdata1 = d1;
                s_eth.intdata2 = le32(s_eth.int_buf + 4);
                /* Just record link state — a plain flag write, ISR-safe. RX is
                 * fully configured at probe time (gigabit MEDIUM=0x013B + RX_CTL
                 * START + gig-SS bulkin), so we do NOT issue any control transfer
                 * (link_reset) here: those would re-enter the event-ring drain
                 * (poll advances s_evt_dequeue) AND fail from ISR context. */
                s_eth.link_up_intr = up;
                s_eth.link_up = up;
                xhci_eth_submit_int();          /* re-arm */
            }
        }

        if (trb_type == XHCI_TRB_PORT_STATUS_CHG) {
            /* Port ID is in bits [31:24] of param (low dword).
             * xHCI spec §6.4.2.3: Port Status Change Event TRB
             * param[31:24] = Port ID (1-based). */
            uint8_t port_id = (uint8_t)((trb->param >> 24) & 0xFFu);
            if (port_id >= 1 && port_id <= s_max_ports &&
                port_id <= XHCI_MAX_PORTS) {
                volatile uint32_t *portsc_reg =
                    (volatile uint32_t *)((volatile uint8_t *)s_op + 0x400u +
                                          (port_id - 1u) * 16u);
                uint32_t portsc = *portsc_reg;

                /* Clear ALL latched RW1C change bits at once. We're not
                 * acting on most of them (PEC/WRC/OCC/PLC/CEC) but
                 * leaving them latched would re-fire PSC events forever.
                 * Use a clean RW1C value: keep non-RW1C state, set ALL
                 * change bits to 1 to clear them. */
                *portsc_reg = portsc_rmw_mask(portsc) | XHCI_PORTSC_RW1C_MASK;

                if (portsc & XHCI_PORTSC_CSC) {
                    if (portsc & XHCI_PORTSC_CCS) {
                        /* Device connected — DEFER enumeration to after
                         * the event ring drain to avoid the re-entrancy
                         * bug where poll_cmd_completion (called inside
                         * enumerate_port) corrupts s_evt_dequeue. */
                        s_pending_enum[port_id] = 1;
                    } else {
                        /* Device disconnected — issue Disable Slot to
                         * release controller resources, then free the
                         * driver-side slot. */
                        uint32_t s;
                        for (s = 1; s < XHCI_MAX_SLOTS; s++) {
                            if (s_slot_port[s] == port_id && s_hid_slots[s]) {
                                printk("[XHCI] port %u disconnect, freeing slot %u\n",
                                       (unsigned)port_id, (unsigned)s);
                                issue_disable_slot((uint8_t)s);
                                s_hid_slots[s]     = 0;
                                s_hid_slot_type[s] = USB_DEV_NONE;
                                s_slot_port[s]     = 0;
                                if (s_dcbaa)
                                    s_dcbaa[s] = 0;
                                /* Note: leaks transfer ring + HID buf
                                 * pages — Aegis has no reverse free path.
                                 * Acceptable for short-lived hotplug. */
                                break;
                            }
                        }
                    }
                }
            }
        }

        next_trb:
        s_evt_dequeue++;
        if (s_evt_dequeue >= XHCI_EVT_RING_SIZE) {
            s_evt_dequeue = 0;
            s_evt_cycle  ^= 1;
        }
        update_erdp();

        trb = &s_evt_ring[s_evt_dequeue];
    }

    /* Now that the outer event ring drain is complete, process any
     * pending hot-enumerate requests. enumerate_port internally calls
     * poll_cmd_completion which advances s_evt_dequeue / s_evt_cycle —
     * doing this OUTSIDE the outer while loop avoids the re-entrancy
     * corruption that breaks both initial enumeration and hotplug. */
    {
        uint32_t p;
        for (p = 1; p <= s_max_ports && p <= XHCI_MAX_PORTS; p++) {
            if (s_pending_enum[p]) {
                s_pending_enum[p] = 0;
                enumerate_port(p);
            }
        }
    }

    }   /* end for (hc) — service the next controller */
}

/* -------------------------------------------------------------------------
 * xhci_schedule_interrupt_in — place a Normal TRB on a slot's transfer ring
 * ---------------------------------------------------------------------- */

int
xhci_schedule_interrupt_in(uint8_t slot_id, uint8_t ep_id,
                            uint64_t buf_phys, uint32_t buf_len)
{
    xhci_trb_t        *trb;
    volatile uint32_t *db;

    if (slot_id == 0 || slot_id >= XHCI_MAX_SLOTS ||
        s_xfer_ring[slot_id] == NULL)
        return -1;

    trb = &s_xfer_ring[slot_id][s_xfer_enqueue[slot_id]];
    trb->param  = buf_phys;
    trb->status = buf_len;
    /* Normal TRB | IOC (Interrupt On Completion, bit 5) | cycle bit */
    trb->control = (uint32_t)(XHCI_TRB_NORMAL << 10) |
                   (1u << 5) |
                   (uint32_t)s_xfer_cycle[slot_id];

    s_xfer_enqueue[slot_id]++;
    if (s_xfer_enqueue[slot_id] >= XHCI_TRANSFER_RING_SIZE - 1u) {
        /* Wrap. The Link TRB must carry the cycle of the TRBs BEFORE it (the
         * CURRENT producer cycle) so the controller — which reaches it with a
         * matching consumer cycle — finds it owned, follows it, and only then
         * toggles its cycle. Stamp the Link FIRST, THEN flip our producer cycle
         * for the wrapped region. (Flipping first stamped the Link with the
         * already-toggled cycle, leaving it "not owned" the moment the ring
         * wrapped, which halted the endpoint after exactly one lap — the "mouse
         * dies after a few seconds" symptom.) */
        s_xfer_ring[slot_id][XHCI_TRANSFER_RING_SIZE - 1].control =
            (uint32_t)(XHCI_TRB_LINK << 10) | (1u << 1) |
            (uint32_t)s_xfer_cycle[slot_id];
        s_xfer_cycle[slot_id]  ^= 1;
        s_xfer_enqueue[slot_id] = 0;
    }

    /* Ring doorbell: slot_id selects device doorbell, ep_id selects endpoint.
     * SAFETY: s_bar0_va + cap->dboff is the doorbell array base within the
     * 64KB BAR0 mapping; db[slot_id] is within that range for slot_id < 32. */
    db = (volatile uint32_t *)(s_bar0_va + s_cap->dboff);
    /* sfence: TRB write must be globally visible before doorbell write. */
    arch_wmb();
    db[slot_id] = ep_id;

    return 0;
}
