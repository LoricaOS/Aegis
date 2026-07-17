/*
 * pcie_brcmstb.c — Broadcom STB PCIe root-complex driver (BCM2712 / Pi 5).
 *
 * Real Pi 5 hardware has NO generic-ECAM PCIe host (kernel/arch/arm64/
 * pcie.c skips cleanly on this board for exactly that reason) -- every
 * PCIe root complex here is `compatible = "brcm,bcm2712-pcie"`, a
 * proprietary Broadcom controller needing real reset/link-training
 * bring-up before its config space is even readable. Nothing upstream of
 * Aegis does this bring-up for us on the native boot path (unlike Linux/
 * U-Boot machines, where a bootloader stage often already trained the
 * link) -- this file is Aegis's first PCIe owner on this board.
 *
 * Ported from three real reference drivers (kept outside this repo at
 * ~/Developer/rpi5-pcie-ref/, see rpi5-pcie-driver-research memory):
 *   - U-Boot's drivers/pci/pcie_brcmstb.c: the fullest real bare-metal-
 *     style bring-up sequence (reset -> SerDes -> PLL -> link-up poll) --
 *     this file's primary template, since like U-Boot, Aegis is the
 *     first owner and can't assume a prior stage trained the link.
 *   - Linux's drivers/pci/controller/pcie-brcmstb.c: register-offset
 *     ground truth (cross-checked every constant against this).
 *   - Zephyr's drivers/pcie/controller/pcie_brcmstb.c: confirmed which
 *     steps are safe to skip when nothing needs MSI/DMA yet (this file
 *     follows suit for its first milestone -- see below).
 *   - Linux's drivers/reset/reset-brcmstb.c + reset-brcmstb-rescal.c:
 *     register layout for the two small reset controllers gating this
 *     root complex (no reset *framework* here, just their raw registers).
 *
 * Scope of this file (first milestone, matches the "one thing per flash"
 * discipline used for the rest of this native-boot port): bring pcie1 (the
 * board's NVMe M.2 slot -- confirmed via the real DTB's own
 * `nvme = <&pciex1>` alias, node_index 1 of the three `brcm,bcm2712-pcie`
 * nodes) up to a trained link, then enumerate bus 0 (the RC's own bridge
 * function) and bus 1 dev 0 (the actual downstream NVMe controller,
 * reached only after this file programs the bridge's own Primary/
 * Secondary/Subordinate Bus Number registers -- standard PCI-PCI bridge
 * config, not Broadcom-specific), and print what's found. Deliberately
 * NOT done here (separate, later flash): outbound MMIO windows (needed to
 * reach the NVMe device's own BAR0 registers), inbound DMA windows
 * (needed for the device to DMA into system RAM), and MSI (both reference
 * drivers mask it entirely when nothing consumes interrupts yet -- this
 * file does the same; Aegis's eventual NVMe driver will poll, like the
 * existing virtio_blk poll-mode path).
 */
#include "pcie.h"
#include "printk.h"
#include "kva.h"
#include "fdt.h"
#include <stdint.h>
#include <stddef.h>

/* This board's three brcm,bcm2712-pcie nodes, in DTB order (confirmed via
 * the real upstream bcm2712.dtsi/bcm2712-rpi-5-b.dts, not guessed):
 *   node_index 0 = pcie0 @ phys 0x10_00100000, x1, unused on this board
 *   node_index 1 = pcie1 @ phys 0x10_00110000, x1, THE NVME M.2 SLOT
 *   node_index 2 = pcie2 @ phys 0x10_00120000, x4, RP1 (not this file)
 */
#define PCIE_BRCMSTB_COMPAT   "brcm,bcm2712-pcie"
#define PCIE1_NODE_INDEX      1

/* --- Register offsets (BCM2712, cross-checked against all 3 reference
 * drivers' bcm2712/bcm7712 constants) --- */
#define PCIE_RC_CFG_VENDOR_SPECIFIC_REG1        0x0188
#define  VENDOR_REG1_ENDIAN_MODE_BAR2_MASK      0xc
#define PCIE_RC_CFG_PRIV1_ID_VAL3                0x043c
#define  ID_VAL3_CLASS_CODE_MASK                0xffffffUL
#define  BCM2712_CLASS_CODE                     0x060400UL /* PCI bridge */
#define PCIE_RC_DL_MDIO_ADDR                    0x1100
#define PCIE_RC_DL_MDIO_WR_DATA                 0x1104
#define  MDIO_DATA_DONE_MASK                    0x80000000UL
#define PCIE_RC_PL_PHY_CTL_15                   0x184c
#define  PHY_CTL_15_PM_CLK_PERIOD_MASK          0xff

#define PCIE_MISC_MISC_CTRL                     0x4008
#define  MISC_CTRL_SCB0_SIZE_MASK               0xf8000000UL
#define  MISC_CTRL_SCB0_SIZE_LSB                27
#define  MISC_CTRL_MAX_BURST_SIZE_MASK          0x300000UL
#define  MISC_CTRL_MAX_BURST_SIZE_128_2712      0x100000UL
#define  MISC_CTRL_RCB_MPS_MODE_MASK            0x400UL
#define  MISC_CTRL_SCB_ACCESS_EN_MASK           0x1000UL
#define  MISC_CTRL_CFG_READ_UR_MODE_MASK        0x2000UL
#define PCIE_MISC_RC_BAR1_CONFIG_LO              0x402c
#define PCIE_MISC_RC_BAR1_CONFIG_HI              0x4030
#define  RC_BAR_CONFIG_LO_SIZE_MASK              0x1f
#define PCIE_MISC_RC_BAR3_CONFIG_LO              0x403c
#define PCIE_MISC_UBUS_BAR1_CONFIG_REMAP         0x40ac
#define PCIE_MISC_UBUS_BAR1_CONFIG_REMAP_HI      0x40b0
#define  UBUS_BAR_CONFIG_REMAP_ENABLE_MASK        0x1UL
#define  UBUS_BAR_CONFIG_REMAP_LO_MASK             0xfffff000UL
#define  UBUS_BAR_CONFIG_REMAP_HI_MASK              0xffUL
#define PCIE_MISC_PCIE_CTRL                      0x4064
#define  PCIE_CTRL_PCIE_PERSTB_MASK               0x4UL
#define PCIE_MISC_PCIE_STATUS                    0x4068
#define  STATUS_PCIE_PHYLINKUP_MASK               0x10UL
#define  STATUS_PCIE_DL_ACTIVE_MASK                0x20UL
#define  STATUS_PCIE_PORT_MASK                     0x80UL
#define PCIE_MISC_UBUS_CTRL                      0x40a4
#define  UBUS_CTRL_REPLY_ERR_DIS_MASK              0x2000UL
#define  UBUS_CTRL_REPLY_DECERR_DIS_MASK          0x80000UL
#define PCIE_MISC_UBUS_TIMEOUT                   0x40a8
#define PCIE_MISC_RC_CONFIG_RETRY_TIMEOUT        0x405c
#define PCIE_MISC_AXI_READ_ERROR_DATA             0x4170
#define PCIE_MISC_HARD_DEBUG                     0x4304   /* bcm7712/bcm2712 table */
#define  HARD_DEBUG_SERDES_IDDQ_MASK              0x08000000UL
#define PCIE_EXT_CFG_DATA                        0x8000
#define PCIE_EXT_CFG_INDEX                       0x9000

/* Both pcie_rescal and bcm_reset live under the real DTB's `soc@107c000000`
 * node (compatible "simple-bus"), whose `ranges = <0x0 0x10 0x0
 * 0x80000000>` maps child address 0 to real CPU-physical 0x10_00000000 --
 * their own `reg` properties (0x119500, 0x1504318) are CHILD addresses,
 * not final physical ones. Missing this translation was this driver's
 * first real bug: rescal_deassert() timed out on the first hardware flash
 * because these two were pointed at the wrong (untranslated, and on this
 * board almost certainly unmapped/unrelated) physical addresses. The
 * pcie0/1/2 nodes themselves need no such fix -- they're 2-cell-addressed
 * children of the root node directly, already carrying the real 0x10_...
 * address in their own reg property (confirmed: this offset already
 * matched real hardware, since bring-up got as far as attempting
 * rescal). */
#define SOC_BUS_BASE             0x1000000000UL

/* bcm_reset (brcm,brcmstb-reset): bit-per-line, banked every 32 bits.
 * pcie1's bridge reset is bit 43 (bank 1, bit 11) -- confirmed via the
 * real DTB (`resets = <&pcie_rescal>, <&bcm_reset 43>` on the pcie1 node)
 * and Linux's drivers/reset/reset-brcmstb.c register layout. */
#define BCM_RESET_PHYS           (SOC_BUS_BASE + 0x1504318UL)
#define BCM_RESET_BANK_SIZE      0x18UL
#define BCM_RESET_SET            0x00UL
#define BCM_RESET_CLEAR          0x04UL
#define PCIE1_BRIDGE_RESET_ID    43
#define PCIE0_BRIDGE_RESET_ID    42   /* unused slot, but shares rescal below */
#define PCIE2_BRIDGE_RESET_ID    44   /* RP1 (x4) -- shares rescal below */

/* pcie_rescal (brcm,bcm7216-pcie-sata-rescal): single shared "kick and
 * poll" reset, id-less (#reset-cells = 0) -- confirmed via the real DTB
 * and Linux's drivers/reset/reset-brcmstb-rescal.c. */
#define RESCAL_PHYS              (SOC_BUS_BASE + 0x119500UL)
#define RESCAL_START             0x0UL
#define  RESCAL_START_BIT        0x1UL
#define RESCAL_STATUS            0x8UL
#define  RESCAL_STATUS_BIT       0x1UL

static volatile uint8_t *s_base;   /* KVA of pcie1's own 0x9310-byte BAR */
static volatile uint8_t *s_rescal;
static volatile uint8_t *s_bcm_reset;

static inline uint32_t r32(uint32_t off) { return *(volatile uint32_t *)(s_base + off); }
static inline void w32(uint32_t off, uint32_t v) { *(volatile uint32_t *)(s_base + off) = v; }

/* Real, calibrated delay off the ARM generic timer (CNTPCT_EL0/CNTFRQ_EL0)
 * -- always available regardless of GIC/timer_init state, unlike an
 * uncalibrated instruction-count busy loop (which this file's first
 * real-hardware flash showed gives an unreliable, likely far-too-short
 * "10us" in practice: rescal's poll loop reported "timed out" despite
 * every reference driver treating this as a routine ~100us-1ms wait). */
static void
busy_wait_us(uint32_t us)
{
    uint64_t freq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    uint64_t start;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(start));
    uint64_t target = start + (freq / 1000000UL) * us;
    uint64_t now;
    do {
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
    } while (now < target);
}

static int
rescal_deassert(void)
{
    /* "Kick and poll" -- not a level-held reset: set START, wait for
     * STATUS to report done, then clear START. Matches Linux's
     * reset-brcmstb-rescal.c exactly (its only real operation, called
     * "reset" there, not assert/deassert). */
    volatile uint32_t *start  = (volatile uint32_t *)(s_rescal + RESCAL_START);
    volatile uint32_t *status = (volatile uint32_t *)(s_rescal + RESCAL_STATUS);

    /* DIAGNOSTIC (temporary): two prior real-hardware flashes both timed
     * out here (one before, one after fixing the soc-bus address
     * translation) with byte-identical output -- meaning neither attempt
     * actually told us WHERE it failed. Raw readbacks before touching the
     * sequence again, per advisor guidance, rather than guessing a third
     * time. */
    printk("[PCIE-BRCM] diag: rescal START(before)=0x%x STATUS(before)=0x%x\n",
           (unsigned)*start, (unsigned)*status);

    *start = *start | RESCAL_START_BIT;
    uint32_t start_after = *start;
    printk("[PCIE-BRCM] diag: rescal START(after-write)=0x%x\n", (unsigned)start_after);
    if (!(start_after & RESCAL_START_BIT))
        return -1;

    /* DIAGNOSTIC (temporary): 1ms (matching Linux/U-Boot's own budget)
     * consistently times out on real hardware. Extended to ~200ms with
     * periodic readouts to discriminate "genuinely needs more time than
     * upstream assumes" (STATUS would visibly move) from "never changes
     * no matter how long we wait" (a real precondition/config gap, likely
     * something firmware normally handles that this from-scratch native
     * path doesn't yet). */
    for (int i = 0; i < 2000; i++) {
        uint32_t s = *status;
        if (s & RESCAL_STATUS_BIT)
            break;
        if (i == 0 || i == 100 || i == 500 || i == 1000 || i == 1999)
            printk("[PCIE-BRCM] diag: rescal poll i=%d STATUS=0x%x\n", i, (unsigned)s);
        busy_wait_us(100);
    }
    uint32_t status_final = *status;
    printk("[PCIE-BRCM] diag: rescal STATUS(final)=0x%x\n", (unsigned)status_final);
    if (!(status_final & RESCAL_STATUS_BIT))
        return -1;

    *start = *start & ~RESCAL_START_BIT;
    return 0;
}

static void
bridge_reset_set_id(uint32_t reset_id, int assert)
{
    uint32_t bank = reset_id >> 5;
    uint32_t bit  = 1UL << (reset_id & 0x1f);
    uint32_t off  = (uint32_t)(bank * BCM_RESET_BANK_SIZE) +
                    (assert ? BCM_RESET_SET : BCM_RESET_CLEAR);
    *(volatile uint32_t *)(s_bcm_reset + off) = bit;
}

static void
bridge_reset_set(int assert)
{
    bridge_reset_set_id(PCIE1_BRIDGE_RESET_ID, assert);
}

static void
mdio_write(uint8_t port, uint8_t regad, uint16_t wrdata)
{
    uint32_t addr_pkt = ((uint32_t)0 << 20) | ((uint32_t)port << 16) | regad; /* cmd=write=0 */
    w32(PCIE_RC_DL_MDIO_ADDR, addr_pkt);
    r32(PCIE_RC_DL_MDIO_ADDR); /* per reference drivers: read-back before the data write */
    w32(PCIE_RC_DL_MDIO_WR_DATA, MDIO_DATA_DONE_MASK | wrdata);
    for (int i = 0; i < 20; i++) {
        if (!(r32(PCIE_RC_DL_MDIO_WR_DATA) & MDIO_DATA_DONE_MASK))
            return;
        busy_wait_us(10);
    }
}

/* BCM2712-only: allow a 54MHz (xosc) refclk source. Identical register
 * sequence in all three reference drivers -- opaque PHY tuning values,
 * not derivable from first principles, so ported verbatim. */
static void
munge_pll(void)
{
    static const uint8_t  regs[] = {0x16, 0x17, 0x18, 0x19, 0x1b, 0x1c, 0x1e};
    static const uint16_t vals[] = {0x50b9, 0xbda1, 0x0094, 0x97b4, 0x5030, 0x5030, 0x0007};

    mdio_write(0, 0x1f, 0x1600); /* SET_ADDR_OFFSET */
    for (unsigned i = 0; i < sizeof(regs); i++)
        mdio_write(0, regs[i], vals[i]);
    busy_wait_us(150);
}

static int
link_up(void)
{
    uint32_t v = r32(PCIE_MISC_PCIE_STATUS);
    return (v & STATUS_PCIE_DL_ACTIVE_MASK) && (v & STATUS_PCIE_PHYLINKUP_MASK);
}

static int
rc_mode(void)
{
    return (r32(PCIE_MISC_PCIE_STATUS) & STATUS_PCIE_PORT_MASK) != 0;
}

/* PCIE_MISC_RC_BARx_CONFIG_LO's SIZE field is a non-linear encoding, not a
 * raw byte count -- ported from brcm_pcie_encode_ibar_size (all 3
 * reference drivers agree on this table). size must be a power of two. */
static uint32_t
encode_ibar_size(uint64_t size)
{
    uint32_t log2 = 63 - __builtin_clzll(size);
    if (log2 >= 12 && log2 <= 15)
        return (log2 - 12) + 0x1c;     /* 4KB..32KB */
    if (log2 >= 16 && log2 <= 36)
        return log2 - 15;              /* 64KB..64GB */
    return 0;
}

/* Inbound DMA window (RC_BAR1 + its UBUS remap pair): lets a downstream
 * device's DMA reach system RAM. This is NOT optional/DMA-only setup as
 * first assumed -- Linux and U-Boot both program this BEFORE PERST# is
 * ever deasserted, as part of basic bring-up, and skipping it was this
 * driver's real bug (confirmed by a real-hardware A/B: identical "link
 * down" with a physical NVMe module connected, matching real Linux
 * exactly minus this step -- see rpi5-pcie-driver-research memory).
 * BCM2712-specific encoding (confirmed against U-Boot's `is_2712` branch):
 * the BAR holds the RAW PCIe-bus address; a separate UBUS remap register
 * pair supplies the CPU-side physical address translation -- pre-2712
 * chips instead store an offset in the BAR itself and have no UBUS remap
 * step at all. Values are pcie1's own dma-ranges (real DTB): PCI bus addr
 * 0x10_00000000, CPU addr 0x0, size 64GB (the tiny 4KB MIP1 MSI window in
 * the same dma-ranges property is skipped -- not needed without MSI). */
static void
set_inbound_window(void)
{
    const uint64_t bar_pci  = 0x1000000000UL;
    const uint64_t bar_cpu  = 0x0UL;
    const uint64_t bar_size = 0x1000000000UL; /* 64GB */

    uint32_t tmp = (uint32_t)(bar_pci & 0xFFFFFFFFUL);
    tmp &= ~RC_BAR_CONFIG_LO_SIZE_MASK;
    tmp |= encode_ibar_size(bar_size) & RC_BAR_CONFIG_LO_SIZE_MASK;
    w32(PCIE_MISC_RC_BAR1_CONFIG_LO, tmp);
    w32(PCIE_MISC_RC_BAR1_CONFIG_HI, (uint32_t)(bar_pci >> 32));

    tmp = (uint32_t)(bar_cpu & 0xFFFFFFFFUL) & UBUS_BAR_CONFIG_REMAP_LO_MASK;
    tmp |= UBUS_BAR_CONFIG_REMAP_ENABLE_MASK;
    w32(PCIE_MISC_UBUS_BAR1_CONFIG_REMAP, tmp);
    w32(PCIE_MISC_UBUS_BAR1_CONFIG_REMAP_HI, (uint32_t)(bar_cpu >> 32) & UBUS_BAR_CONFIG_REMAP_HI_MASK);
}

/* --- Config space: bus 0 is the RC's own bridge function, reachable
 * directly at s_base+offset. Bus 1 (the single downstream device this
 * root complex's x1 link can ever carry) goes through the indirect
 * EXT_CFG_INDEX/DATA window, and only after the bridge's own Primary/
 * Secondary/Subordinate Bus Number register (offset 0x18, standard PCI
 * type-1 header, not Broadcom-specific) has been programmed -- otherwise
 * the RC has no idea bus 1 exists yet. */
static uint32_t
cfg_read32(uint8_t bus, uint8_t dev, uint16_t off)
{
    if (bus == 0)
        return r32(off);
    if (!link_up() || dev != 0)
        return 0xFFFFFFFFUL;
    uint32_t idx = ((uint32_t)bus << 20) | ((uint32_t)dev << 15) | (0u << 12);
    w32(PCIE_EXT_CFG_INDEX, idx);
    return r32(PCIE_EXT_CFG_DATA + off);
}

static void
program_bridge_bus_numbers(uint8_t primary, uint8_t secondary, uint8_t subordinate)
{
    uint32_t v = (uint32_t)primary | ((uint32_t)secondary << 8) |
                 ((uint32_t)subordinate << 16);
    w32(0x18, v); /* standard type-1 header: Primary/Secondary/Subordinate Bus # */
}

static void
print_found(uint8_t bus, uint8_t dev)
{
    uint32_t idreg = cfg_read32(bus, dev, 0x00);
    uint16_t vendor = (uint16_t)(idreg & 0xFFFF);
    if (vendor == 0xFFFF)
        return;
    uint16_t device = (uint16_t)(idreg >> 16);
    uint32_t cls = cfg_read32(bus, dev, 0x08);
    printk("[PCIE-BRCM] found %x:%x class=%x at bus %u dev %u\n",
           (unsigned)vendor, (unsigned)device, (unsigned)(cls >> 24),
           (unsigned)bus, (unsigned)dev);
}

void
pcie_brcmstb_init(void)
{
    uint64_t base_phys, base_sz;
    if (!fdt_reg_by_compat_nth(PCIE_BRCMSTB_COMPAT, PCIE1_NODE_INDEX, &base_phys, &base_sz)) {
        printk("[PCIE-BRCM] skip: pcie1 (NVMe root complex) not found in DTB\n");
        return;
    }
    /* DIAGNOSTIC (temporary): never actually printed the resolved address
     * before this flash -- expect 0x1000110000/0x9310 for pcie1. Also dump
     * node_index 0/2 to independently confirm fdt_reg_by_compat_nth's
     * node-counting isn't off by one (real DTB order: pcie0, pcie1, pcie2). */
    printk("[PCIE-BRCM] diag: pcie1 base_phys=0x%lx base_sz=0x%lx\n", base_phys, base_sz);
    {
        uint64_t a, s;
        if (fdt_reg_by_compat_nth(PCIE_BRCMSTB_COMPAT, 0, &a, &s))
            printk("[PCIE-BRCM] diag: node0 base=0x%lx sz=0x%lx\n", a, s);
        if (fdt_reg_by_compat_nth(PCIE_BRCMSTB_COMPAT, 2, &a, &s))
            printk("[PCIE-BRCM] diag: node2 base=0x%lx sz=0x%lx\n", a, s);
    }

    /* 10 pages covers the DTB's own 0x9310-byte reg size with margin.
     * pcie1's own BAR is naturally 4K-aligned, but RESCAL_PHYS/
     * BCM_RESET_PHYS are NOT (vmm_map_page panics on a misaligned phys --
     * confirmed by reading it before ever building this, not discovered
     * by crashing) -- map each one's containing page and add the
     * sub-page offset back onto the returned KVA. */
    s_base = (volatile uint8_t *)kva_map_mmio(base_phys, 16);
    s_rescal = (volatile uint8_t *)kva_map_mmio(RESCAL_PHYS & ~0xFFFUL, 1)
               + (RESCAL_PHYS & 0xFFFUL);
    s_bcm_reset = (volatile uint8_t *)kva_map_mmio(BCM_RESET_PHYS & ~0xFFFUL, 1)
                  + (BCM_RESET_PHYS & 0xFFFUL);
    if (!s_base || !s_rescal || !s_bcm_reset) {
        printk("[PCIE-BRCM] WARN: MMIO map failed\n");
        return;
    }

    /* DIAGNOSTIC (temporary): independently confirm the pcie1 mapping
     * itself (offset 0 = vendor/device ID; Broadcom RCs report 0x14e4 in
     * the low 16 bits) and that the timer isn't reporting a bogus
     * cntfrq_el0 (which would silently break busy_wait_us). */
    {
        uint64_t freq;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
        printk("[PCIE-BRCM] diag: cntfrq_el0=%lu pcie1[0x0]=0x%x\n",
               freq, (unsigned)r32(0x00));
    }

    /* DIAGNOSTIC (temporary): every rescal/reset-ordering variant tried
     * this session has produced byte-identical "garbage" at both
     * pcie1[0x0] (vendor/device ID) and rescal STATUS, including after a
     * full bridge reset pulse -- but a vendor/device ID is a fixed silicon
     * constant with zero dependence on rescal/PERST#/link training, so no
     * amount of reset reordering could ever fix a bad vendor-ID read. That
     * means the RC's own register block may simply not be answering yet on
     * THIS boot path (Aegis boots from USB; the real-Linux ground truth was
     * captured booting *from* pcie1/NVMe itself, where firmware necessarily
     * brings the RC fully up -- Aegis's boot path may inherit a half-
     * initialized block Linux never has to deal with). Dump every register
     * we have a real-Linux devmem baseline for, wait 2s with zero writes,
     * then dump the identical set again: if everything is still garbage
     * after just waiting, the block is genuinely inaccessible from this
     * boot path (a firmware-init gap, not a sequencing bug in this driver);
     * if the vendor ID (or anything else) flips to the expected value on
     * its own, this is a settling-time issue and needs a readiness poll
     * instead of more reset-ordering guesses. */
    printk("[PCIE-BRCM] diag: pre-wait  vendorid=0x%x misc_ctrl=0x%x "
           "hard_debug=0x%x pcie_ctrl=0x%x pcie_status=0x%x\n",
           (unsigned)r32(0x00), (unsigned)r32(PCIE_MISC_MISC_CTRL),
           (unsigned)r32(PCIE_MISC_HARD_DEBUG), (unsigned)r32(PCIE_MISC_PCIE_CTRL),
           (unsigned)r32(PCIE_MISC_PCIE_STATUS));
    busy_wait_us(2000000);
    printk("[PCIE-BRCM] diag: post-wait vendorid=0x%x misc_ctrl=0x%x "
           "hard_debug=0x%x pcie_ctrl=0x%x pcie_status=0x%x\n",
           (unsigned)r32(0x00), (unsigned)r32(PCIE_MISC_MISC_CTRL),
           (unsigned)r32(PCIE_MISC_HARD_DEBUG), (unsigned)r32(PCIE_MISC_PCIE_CTRL),
           (unsigned)r32(PCIE_MISC_PCIE_STATUS));

    /* DIAGNOSTIC (temporary): a real Linux boot on this exact board reads
     * pcie1[0x0]=0x271214e4 (BCM2712 vendor/device ID) and rescal
     * START=0x0/STATUS=0x73 at these same physical addresses via devmem --
     * our own captures instead showed pcie1[0x0]=0xf3a8d9e8 and rescal
     * values with no resemblance to a real control/status register, on the
     * very first read after mapping, before any writes. That points at the
     * KVA->phys translation itself rather than sequencing. Independently
     * ask the VMM what physical address it thinks s_base/s_rescal resolve
     * to -- if this printed phys doesn't match base_phys/RESCAL_PHYS
     * exactly, the PTE is wrong and that's the bug; if it matches, the
     * mapping is fine and the fault is downstream (hardware enable
     * sequencing, or a wrong assumption about what's at this offset). */
    printk("[PCIE-BRCM] diag: kva_page_phys(s_base)=0x%lx (want 0x%lx) "
           "kva_page_phys(s_rescal)=0x%lx (want 0x%lx)\n",
           kva_page_phys((void *)((uint64_t)(uintptr_t)s_base & ~0xFFFUL)),
           base_phys,
           kva_page_phys((void *)((uint64_t)(uintptr_t)s_rescal & ~0xFFFUL)),
           RESCAL_PHYS & ~0xFFFUL);

    /* 0. Deassert the OTHER two controllers' bridges first -- harmless
     * (we never assert them, don't rely on their own link training), and
     * covers the real Linux driver's own documented quirk: "the RESCAL
     * block is tied to PCIe controller #1, regardless of the number of
     * controllers, and turning off PCIe controller #1 prevents access to
     * the RESCAL register blocks ... depending upon the bus fabric we may
     * get a timeout, or a hang." All three pcie nodes share ONE rescal
     * block (pcie0->bcm_reset 42, pcie1(us)->43, pcie2/RP1->44). Tested in
     * isolation on real hardware already (byte-identical result either
     * way) but kept since it's cheap and still matches upstream intent. */
    bridge_reset_set_id(PCIE0_BRIDGE_RESET_ID, 0);
    bridge_reset_set_id(PCIE2_BRIDGE_RESET_ID, 0);

    /* 1. rescal FIRST, before our OWN bridge is touched at all -- this is
     * U-Boot's actual real order (uboot-pcie-brcmstb.c brcm_pcie_probe()):
     * "Ensure rescal reset for BCM2712 is really disabled" is the literal
     * FIRST hardware action, called with the bridge still in whatever
     * state it naturally powers up in. Our own bridge's assert->deassert
     * pulse happens ONLY afterward (step 2). This directly reverses the
     * order we had before (deassert-then-rescal, based on a since-
     * unverifiable recollection of Linux's probe() order) -- that ordering
     * was tested on real hardware and produced no change, so trying the
     * ground-truth U-Boot order instead, not another guess. */
    if (rescal_deassert() != 0) {
        printk("[PCIE-BRCM] WARN: rescal reset timed out (continuing anyway)\n");
    }

    /* 2. Assert then release our own bridge (bcm_reset bit 43) -- U-Boot's
     * single reset pulse, run only after rescal above, not before. */
    bridge_reset_set(1);
    busy_wait_us(100); /* precludes the reset looking like a glitch */
    bridge_reset_set(0);

    /* DIAGNOSTIC (temporary): the vendor-ID garbage read earlier (before
     * step 0) happened while the bridge was still cold-reset -- an
     * unclocked/held-in-reset APB register block returning undefined bus
     * data would look exactly like that, and wouldn't indicate a
     * translation bug. Re-read the SAME register now that the bridge has
     * been through its full reset pulse (steps 0-2) and rescal has run --
     * if this now reads 0x271214e4 (matches a real Linux boot's devmem
     * readback of this exact address), the RC is genuinely alive and the
     * remaining bug is downstream (rescal completion / PERST# / link
     * training); if it's still garbage, the reset sequence itself isn't
     * reaching hardware and that's the next place to look. */
    printk("[PCIE-BRCM] diag: post-reset pcie1[0x0]=0x%x rescal STATUS=0x%x\n",
           (unsigned)r32(0x00),
           (unsigned)(*(volatile uint32_t *)(s_rescal + RESCAL_STATUS)));

    /* 3. Clear SerDes IDDQ (power-down) now that the bridge is out of reset. */
    w32(PCIE_MISC_HARD_DEBUG, r32(PCIE_MISC_HARD_DEBUG) & ~HARD_DEBUG_SERDES_IDDQ_MASK);
    busy_wait_us(100);

    /* 4. BCM2712-only PHY tuning: 54MHz refclk + L1SS PM clock period fix. */
    munge_pll();
    {
        uint32_t tmp = r32(PCIE_RC_PL_PHY_CTL_15);
        tmp &= ~(uint32_t)PHY_CTL_15_PM_CLK_PERIOD_MASK;
        tmp |= 0x12; /* 18.52ns (1/54MHz), rounded down -- opaque HW constant */
        w32(PCIE_RC_PL_PHY_CTL_15, tmp);
    }

    /* 5. MISC_CTRL: burst size, SCB access enable, UR-on-bad-cfg-read mode.
     * BCM2712 uses a fixed 32GB SCB0 window (encoding 20), not sized from
     * a DMA region -- correct for this milestone since no DMA is wired up
     * yet, and matches what U-Boot does unconditionally for this SoC. */
    {
        uint32_t tmp = r32(PCIE_MISC_MISC_CTRL);
        tmp &= ~(MISC_CTRL_MAX_BURST_SIZE_MASK | MISC_CTRL_SCB0_SIZE_MASK);
        tmp |= MISC_CTRL_SCB_ACCESS_EN_MASK | MISC_CTRL_CFG_READ_UR_MODE_MASK |
               MISC_CTRL_RCB_MPS_MODE_MASK | MISC_CTRL_MAX_BURST_SIZE_128_2712;
        tmp |= 20UL << MISC_CTRL_SCB0_SIZE_LSB;
        w32(PCIE_MISC_MISC_CTRL, tmp);
    }

    /* 6. Anti-hang registers -- LOAD-BEARING, not polish. This SoC stalls
     * the bus forever on an unanswered access with no exception (same
     * lesson as this session's UART/PCIe-ECAM findings); these bits are
     * what makes a config read to an absent/CRS device return 0xFFFFFFFF
     * instead of wedging the kernel. Must be set before any enumeration. */
    {
        uint32_t tmp = r32(PCIE_MISC_UBUS_CTRL);
        tmp |= UBUS_CTRL_REPLY_ERR_DIS_MASK | UBUS_CTRL_REPLY_DECERR_DIS_MASK;
        w32(PCIE_MISC_UBUS_CTRL, tmp);
    }
    w32(PCIE_MISC_AXI_READ_ERROR_DATA, 0xFFFFFFFFUL);
    w32(PCIE_MISC_UBUS_TIMEOUT, 0xB2D0000UL);          /* ~250ms @ 750MHz */
    w32(PCIE_MISC_RC_CONFIG_RETRY_TIMEOUT, 0xABA0000UL); /* ~240ms @ 750MHz */

    /* 7. Disable the PCIe->GISB/SCB inbound windows (BAR1/BAR3) as a clean
     * baseline -- BAR1 gets overwritten with the real inbound DMA window
     * below (step 7b); BAR3 stays disabled (no second DMA region needed). */
    w32(PCIE_MISC_RC_BAR1_CONFIG_LO, r32(PCIE_MISC_RC_BAR1_CONFIG_LO) & ~(uint32_t)RC_BAR_CONFIG_LO_SIZE_MASK);
    w32(PCIE_MISC_RC_BAR3_CONFIG_LO, r32(PCIE_MISC_RC_BAR3_CONFIG_LO) & ~(uint32_t)RC_BAR_CONFIG_LO_SIZE_MASK);

    /* 7b. Inbound DMA window -- MUST run before PERST# deassert (step 9),
     * matching Linux/U-Boot's own ordering. This was missing entirely on
     * the previous flash (wrongly assumed to be DMA-only, needed only
     * after enumeration) -- that flash reproduced "link down" even with a
     * real NVMe module physically connected, proving something in the
     * pre-link-training sequence was incomplete. See set_inbound_window's
     * own comment + rpi5-pcie-driver-research memory for the full trail. */
    set_inbound_window();

    /* 8. RC's own class code (bridge, 0x060400) + BAR2 endian mode. Both
     * reference drivers set these unconditionally on BCM2712. */
    {
        uint32_t tmp = r32(PCIE_RC_CFG_PRIV1_ID_VAL3);
        tmp &= ~ID_VAL3_CLASS_CODE_MASK;
        tmp |= BCM2712_CLASS_CODE;
        w32(PCIE_RC_CFG_PRIV1_ID_VAL3, tmp);

        tmp = r32(PCIE_RC_CFG_VENDOR_SPECIFIC_REG1);
        tmp &= ~(uint32_t)VENDOR_REG1_ENDIAN_MODE_BAR2_MASK; /* 0 = little-endian */
        w32(PCIE_RC_CFG_VENDOR_SPECIFIC_REG1, tmp);
    }

    /* MSI deliberately left masked/untouched -- this milestone (and the
     * eventual NVMe driver) polls, same as the existing virtio_blk path.
     * No outbound/inbound DMA windows either -- not needed to enumerate
     * config space, only to actually talk to or DMA through the device;
     * that's separate, later work once this bring-up is proven. */

    /* 9. Release PERST# (active-low; BCM2712 moved this into
     * PCIE_MISC_PCIE_CTRL, unlike older SoCs' RGR1_SW_INIT_1 register).
     * PERSTB_MASK=1 means "not held in reset" -- confirmed via U-Boot's
     * own perst_set_2712, which writes !val into this same bit. */
    w32(PCIE_MISC_PCIE_CTRL, r32(PCIE_MISC_PCIE_CTRL) | (uint32_t)PCIE_CTRL_PCIE_PERSTB_MASK);

    /* Per PCIe CEM spec 2.2 / PCIe r5.0 6.6.1: 100ms after PERST# deassert
     * before touching the RC, then poll link-up for up to another 100ms. */
    busy_wait_us(100000);
    int up = 0;
    for (int i = 0; i < 20; i++) {
        if (link_up()) { up = 1; break; }
        busy_wait_us(5000);
    }
    if (!up) {
        printk("[PCIE-BRCM] WARN: link down (no device present, or bring-up bug)\n");
        return;
    }
    if (!rc_mode()) {
        printk("[PCIE-BRCM] WARN: misconfigured -- in EP mode, not RC mode\n");
        return;
    }
    printk("[PCIE-BRCM] OK: link up @ phys 0x%lx\n", base_phys);

    print_found(0, 0);
    /* Bus 1 has no device tree entry of its own to check against -- give
     * the RC its bridge bus numbers before trying bus 1, or it has no
     * idea that bus exists yet (standard PCI-PCI bridge behavior). */
    program_bridge_bus_numbers(0, 1, 1);
    print_found(1, 0);
}
