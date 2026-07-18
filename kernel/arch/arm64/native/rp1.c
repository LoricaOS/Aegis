/*
 * rp1.c — Raspberry Pi RP1 southbridge access on native Pi 5.
 *
 * The RP1 hosts the USB-A ports, gigabit Ethernet, GPIO, PWM (the fan), etc. It
 * is a PCIe endpoint (1de4:0001) on domain 2 (pcie@1000120000). With
 * `pciex4_reset=0` in config.txt the stock firmware leaves the RP1's PCIe link
 * AND its PLLs up before OS handoff, so from bare metal we do NOT bring up the
 * PCIe RC or the RP1 PLLs — we just map its single BAR1 register window and, per
 * peripheral, enable a clock gate + de-assert a reset.
 *
 * BAR1 window: CPU-phys 0x1f_00000000 (DTB pcie@1000120000 ranges: PCIe 0x0 ->
 * CPU 0x1f_00000000). Every peripheral is a flat offset from there:
 *   SYSINFO 0x000000, RESETS 0x014000, CLOCKS 0x018000, PWM1 0x09c000,
 *   IO_BANK0/1/2 0x0d0000/4000/8000, SYS_RIO0/1/2 0x0e0000/4000/8000,
 *   PADS_BANK0 0x0f0000, ETH 0x100000, PCIE_APBS(MSI-X) 0x108000,
 *   USB dwc3 0x200000/0x300000.
 *
 * Step 0 (this file, for now): map the window and read SYSINFO.CHIP_ID. It must
 * read 0x20001927 (C0 silicon; 0x10001927 = B0). SYSINFO is always-on, so a
 * correct value proves the domain-2 outbound window works with zero clock/reset
 * dependencies — the gate everything else (fan, USB, Ethernet) hangs on.
 */

#include "arch.h"
#include "printk.h"
#include "kva.h"
#include <stdint.h>

#define RP1_BAR1_PHYS      0x1f00000000UL
#define RP1_WINDOW_PAGES   0x400          /* 4 MiB — the full BAR1 (reaches dwc3 @ 0x200000) */

#define RP1_SYSINFO_BASE   0x000000
#define RP1_CHIP_ID_OFF    0x00
#define RP1_CHIP_ID_C0     0x20001927u
#define RP1_CHIP_ID_B0     0x10001927u

int pcie_rp1_map_window(void);            /* native/pcie_brcmstb.c — domain-2 outbound win */

static volatile uint8_t *s_rp1;           /* KVA base of the BAR1 window, or NULL */

/* rp1_reg — byte-offset accessor into the mapped RP1 window (32-bit regs). */
static inline volatile uint32_t *
rp1_reg(uint32_t off)
{
    return (volatile uint32_t *)(s_rp1 + off);
}

static inline void     rp1_w(uint32_t off, uint32_t v) { *rp1_reg(off) = v; }
static inline uint32_t rp1_r(uint32_t off)             { return *rp1_reg(off); }

/* RP1 GPIO/PAD/RIO for bank 2 (GPIOs 34-53). Per-pin CTRL @ bank+n*8+4
 * (FUNCSEL in bits[4:0]); pad @ pads+4+n*4 (OUT_DISABLE=bit7); RIO OUT@+0, OE@+4
 * with atomic SET@+0x2000 / CLR@+0x3000 aliases. */
#define RP1_IO_BANK2    0x0d8000
#define RP1_RIO2        0x0e8000
#define RP1_PADS2       0x0f8000
#define RP1_ATOM_SET    0x2000
#define RP1_ATOM_CLR    0x3000
#define RP1_FSEL_GPIO   0x05
#define RP1_PAD_OUT_DIS (1u << 7)
#define FAN_PIN         11          /* GPIO45 (FAN_PWM) = bank2 local pin 11 */

/* rp1_fan_full — spin the Pi 5 fan at full. The FAN_PWM line is inverted
 * (firmware drives it HIGH to STOP the fan), so full speed = pin driven LOW.
 * Drive GPIO45 as a plain GPIO output held low — no PWM peripheral/clock. */
static void
rp1_fan_full(void)
{
    uint32_t ctrl = rp1_r(RP1_IO_BANK2 + FAN_PIN * 8 + 4);
    rp1_w(RP1_IO_BANK2 + FAN_PIN * 8 + 4, (ctrl & ~0x1Fu) | RP1_FSEL_GPIO);
    uint32_t pad = rp1_r(RP1_PADS2 + 4 + FAN_PIN * 4);
    rp1_w(RP1_PADS2 + 4 + FAN_PIN * 4, pad & ~RP1_PAD_OUT_DIS);
    rp1_w(RP1_RIO2 + RP1_ATOM_SET + 0x04, 1u << FAN_PIN);   /* output-enable */
    rp1_w(RP1_RIO2 + RP1_ATOM_CLR + 0x00, 1u << FAN_PIN);   /* drive LOW = full */
    printk("[RP1] fan: GPIO45 low (full speed, inverted line)\n");
}

/* dwc3 host controllers (RP1 offsets 0x200000/0x300000). xHCI regs at the
 * controller base (+0), dwc3 globals at +0xc100 (GSNPSID @ +0xc120 reads the
 * Synopsys core id 0x5533xxxx). Step-0 USB probe: confirm the dwc3 answers
 * through the window before attempting host-mode bring-up. */
#define RP1_USB0        0x200000
#define DWC3_GSNPSID    0xc120

static void
rp1_usb_probe(void)
{
    uint32_t snpsid = rp1_r(RP1_USB0 + DWC3_GSNPSID);
    uint32_t cap    = rp1_r(RP1_USB0 + 0x00);         /* xHCI CAPLENGTH/HCIVERSION */
    printk("[RP1] usb0: dwc3 GSNPSID=0x%x  xhci CAPLENGTH=0x%x HCIVERSION=0x%x\n",
           snpsid, cap & 0xffu, (cap >> 16) & 0xffffu);
}

/* rp1_init — map the BAR1 window and verify the chip is reachable. Leaves
 * s_rp1 set on success so later peripheral bring-up (fan/USB/eth) can reuse it.
 * Returns 1 if the RP1 answered with a known chip id, 0 otherwise. */
int
rp1_init(void)
{
    /* Firmware (pciex4_reset=0) trained the link but left no usable outbound
     * window — program one on pcie2 first, else the read below returns poison. */
    if (!pcie_rp1_map_window()) {
        printk("[RP1] skip: no domain-2 outbound window\n");
        return 0;
    }

    s_rp1 = (volatile uint8_t *)kva_map_mmio(RP1_BAR1_PHYS, RP1_WINDOW_PAGES);
    if (!s_rp1) {
        printk("[RP1] FAIL: could not map BAR1 window at 0x%lx\n", RP1_BAR1_PHYS);
        return 0;
    }

    uint32_t id = *rp1_reg(RP1_SYSINFO_BASE + RP1_CHIP_ID_OFF);
    if (id == RP1_CHIP_ID_C0 || id == RP1_CHIP_ID_B0) {
        printk("[RP1] OK: CHIP_ID 0x%x — reachable over PCIe (firmware-configured)\n",
               id);
        rp1_fan_full();       /* thermal relief now that the RP1 is reachable */
        rp1_usb_probe();      /* step-0: is the dwc3 USB controller reachable? */
        return 1;
    }

    printk("[RP1] WARN: CHIP_ID 0x%x (want 0x20001927) — outbound window/link not "
           "set up, or pciex4_reset!=0\n", id);
    s_rp1 = 0;      /* don't let peripheral code touch a bad window */
    return 0;
}
