/* iwl_ax200.c — Intel Wi-Fi 6 AX200 (8086:2723) driver.
 *
 * The AX200 is an iwlwifi "22000"-family part: a compact 16 KB MMIO register
 * window (BAR0) plus DMA rings the firmware sets up. This is a from-scratch
 * driver, developed against a real AX200 forwarded into a VM via VFIO
 * passthrough (see the Proxmox host's spare 04:00.0).
 *
 * PHASE 1 (this file): PCI bring-up — find the device, enable it, map BAR0,
 * wake to D0, and read the always-on hardware-revision / RF-ID registers. That
 * confirms the MMIO window is live and identifies the exact silicon stepping
 * (which selects the firmware image + PHY config). Firmware upload, the host-
 * command interface, scanning and association are later phases.
 *
 * Register offsets are the standard iwlwifi CSRs (see reference iwl-csr.h).
 */
#include "iwl_ax200.h"
#include "pcie.h"
#include "arch.h"
#include "kva.h"
#include "vmm.h"
#include "ramdisk.h"
#include "printk.h"
#include <stdint.h>

#define AX200_VENDOR   0x8086
#define AX200_DEVICE   0x2723

/* iwlwifi CSR register offsets within BAR0. HW_REV / HW_RF_ID are "always on"
 * (readable without requesting MAC clock access), so they are safe first reads. */
#define CSR_HW_IF_CONFIG_REG   0x000
#define CSR_INT                0x008
#define CSR_RESET              0x020
#define CSR_GP_CNTRL           0x024
#define CSR_HW_REV             0x028
#define CSR_HW_RF_ID           0x09C
#define CSR_GIO_CHICKEN_BITS   0x100
#define CSR_DBG_HPET_MEM_REG   0x240

/* CSR bit fields used by the power-up handshake (iwl-csr.h). */
#define HW_IF_CONFIG_HAP_WAKE_L1A     0x00080000
#define HW_IF_CONFIG_NIC_READY        0x00400000  /* PCI_OWN_SEM */
#define HW_IF_CONFIG_NIC_PREPARE_DONE 0x02000000  /* ME_OWN */
#define HW_IF_CONFIG_PREPARE          0x08000000  /* WAKE_ME */
#define GP_CNTRL_MAC_CLOCK_READY      0x00000001
#define GP_CNTRL_INIT_DONE            0x00000004
#define GIO_CHICKEN_L1A_NO_L0S_RX     0x00800000
#define DBG_HPET_MEM_REG_VAL          0xFFFF0000

/* PCI command register bits + PM capability id */
#define PCI_CMD_MEM    0x02
#define PCI_CMD_BM     0x04
#define PCI_CAP_ID_PM  0x01

/* MMIO must be uncached (device registers). Matches rtl8169's mapping flags. */
#define MMIO_FLAGS (VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS)

static volatile uint8_t *s_mmio;   /* BAR0 kernel VA */

static inline uint32_t csr_rd(uint32_t off) { return *(volatile uint32_t *)(s_mmio + off); }
static inline void     csr_wr(uint32_t off, uint32_t v) { *(volatile uint32_t *)(s_mmio + off) = v; }
static inline void csr_set(uint32_t off, uint32_t m) { csr_wr(off, csr_rd(off) | m); }
static inline void csr_clr(uint32_t off, uint32_t m) { csr_wr(off, csr_rd(off) & ~m); }

/* Approximate busy-wait (no scheduler in early init); mirrors rtl8169. */
static void busy_wait_us(uint32_t us)
{
    for (volatile uint32_t i = 0; i < us * 100u; i++)
        __asm__ volatile("pause");
}

/* Poll a CSR until (reg & mask) == want, up to timeout_us. Returns us waited, or -1. */
static int csr_poll(uint32_t off, uint32_t want, uint32_t mask, uint32_t timeout_us)
{
    for (uint32_t t = 0; t <= timeout_us; t += 10) {
        if ((csr_rd(off) & mask) == want)
            return (int)t;
        busy_wait_us(10);
    }
    return -1;
}

/* Request device ownership (PCI_OWN_SEM). Returns 0 if the NIC is ready. */
static int set_hw_ready(void)
{
    csr_set(CSR_HW_IF_CONFIG_REG, HW_IF_CONFIG_NIC_READY);
    return csr_poll(CSR_HW_IF_CONFIG_REG, HW_IF_CONFIG_NIC_READY,
                    HW_IF_CONFIG_NIC_READY, 50) >= 0 ? 0 : -1;
}

/* Take the device from firmware/ME ownership if needed (iwl_pcie_prepare_card_hw).
 * On a VFIO-passed device this usually succeeds on the first try. */
static int prepare_card(void)
{
    if (set_hw_ready() == 0)
        return 0;
    csr_set(CSR_HW_IF_CONFIG_REG, HW_IF_CONFIG_PREPARE);
    csr_poll(CSR_HW_IF_CONFIG_REG, 0, HW_IF_CONFIG_NIC_PREPARE_DONE, 2000);
    for (int i = 0; i < 15; i++) {
        if (set_hw_ready() == 0)
            return 0;
        busy_wait_us(10000);
    }
    return -1;
}

/* Power up the NIC: APM init + finish_nic_init → MAC clock stable, prph/SRAM
 * accessible. AX200 is device-family 22000 (< BZ): set INIT_DONE, poll CLOCK_READY. */
static int power_up(void)
{
    if (prepare_card() != 0) {
        printk("[AX200] FAIL: prepare_card (device not ready / owned by ME)\n");
        return -1;
    }
    /* APM init (gen2): chicken bits + HPET wait threshold + HAP wake. */
    csr_set(CSR_GIO_CHICKEN_BITS, GIO_CHICKEN_L1A_NO_L0S_RX);
    csr_set(CSR_DBG_HPET_MEM_REG, DBG_HPET_MEM_REG_VAL);
    csr_set(CSR_HW_IF_CONFIG_REG, HW_IF_CONFIG_HAP_WAKE_L1A);

    /* finish_nic_init: move D0U*->D0A*, then wait for the MAC clock. */
    csr_set(CSR_GP_CNTRL, GP_CNTRL_INIT_DONE);
    int us = csr_poll(CSR_GP_CNTRL, GP_CNTRL_MAC_CLOCK_READY,
                      GP_CNTRL_MAC_CLOCK_READY, 25000);
    if (us < 0) {
        printk("[AX200] FAIL: MAC clock not ready (GP_CNTRL=0x%x)\n",
               csr_rd(CSR_GP_CNTRL));
        return -1;
    }
    printk("[AX200] power-up OK: MAC clock ready in ~%uus (GP_CNTRL=0x%x)\n",
           (unsigned)us, csr_rd(CSR_GP_CNTRL));
    return 0;
}

/* Map a BAR's physical range into kernel VA as uncached MMIO. Mirrors the
 * rtl8169 helper — kva_alloc_pages reserves the VA, then remap each page to the
 * device's physical BAR. */
static uintptr_t
map_bar(uint64_t pa, uint32_t n_pages)
{
    uintptr_t va = (uintptr_t)kva_alloc_pages(n_pages);
    for (uint32_t i = 0; i < n_pages; i++) {
        uintptr_t page_va = va + (uint64_t)i * 4096;
        vmm_unmap_page(page_va);
        vmm_map_page(page_va, pa + (uint64_t)i * 4096, MMIO_FLAGS);
    }
    return va;
}

/* Find the Power Management capability's PMCSR offset (cap+4), or 0. */
static uint8_t
find_pm_pmcsr(const pcie_device_t *d)
{
    uint16_t status = pcie_read16(d->bus, d->dev, d->fn, 0x06);
    if (!(status & (1 << 4)))
        return 0;
    uint8_t cap = (uint8_t)pcie_read8(d->bus, d->dev, d->fn, 0x34) & 0xFCu;
    int safety = 48;
    while (cap != 0 && safety-- > 0) {
        uint8_t id   = pcie_read8(d->bus, d->dev, d->fn, cap + 0);
        uint8_t next = pcie_read8(d->bus, d->dev, d->fn, cap + 1);
        if (id == PCI_CAP_ID_PM)
            return (uint8_t)(cap + 4);
        cap = next & 0xFCu;
    }
    return 0;
}

/* ── Firmware image: embedded blob + TLV parse (Phase 2 step B) ────────
 * The .ucode is a TLV container: 88-byte header, then {type,len,data} TLVs.
 * The runtime image is carried in IWL_UCODE_TLV_SEC_RT sections; each section's
 * data begins with a __le32 destination offset (or a separator marker) followed
 * by the section bytes. Sections are grouped LMAC | sep | UMAC | sep | paging.
 *
 * The blob is delivered as a Limine boot module (module0 → ramdisk0 on the
 * smoke ISO); we read it straight from there. ponytail: dev-time module load;
 * a shipped kernel would defer firmware load to userspace/rootfs. */
#define IWL_TLV_MAGIC          0x0a4c5749u
#define TLV_HDR_SIZE           88
#define IWL_UCODE_TLV_SEC_RT   19
#define CPU1_CPU2_SEPARATOR    0xFFFFCCCCu
#define PAGING_SEPARATOR       0xAAAABBBBu
#define MAX_FW_SEC             64   /* IWL_MAX_DRAM_ENTRY; firmware has ~27+ secs */

struct fw_sec { uint32_t offset; const uint8_t *data; uint32_t len; };
static struct fw_sec s_sec[MAX_FW_SEC];
static int      s_num_sec;
static uint32_t s_fw_ver;
static int      s_lmac_cnt, s_umac_cnt, s_paging_cnt;

static inline uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Count sections from `start` until a separator (== iwl_pcie_get_num_sections). */
static int sec_count_from(int start)
{
    int i = 0;
    while (start < s_num_sec &&
           s_sec[start].offset != CPU1_CPU2_SEPARATOR &&
           s_sec[start].offset != PAGING_SEPARATOR) {
        start++; i++;
    }
    return i;
}

static int parse_firmware(void)
{
    const uint8_t *fw;
    uint64_t len64;
    if (ramdisk_get_blob(&fw, &len64) != 0) {
        printk("[AX200] no firmware module (boot the .ucode as module0)\n");
        return -1;
    }
    uint32_t len = (uint32_t)len64;

    if (len < TLV_HDR_SIZE || rd_le32(fw + 4) != IWL_TLV_MAGIC) {
        printk("[AX200] FAIL: module is not iwlwifi firmware (len=%u)\n", (unsigned)len);
        return -1;
    }
    s_fw_ver = rd_le32(fw + 4 + 4 + 64);   /* ver field after zero,magic,human[64] */

    s_num_sec = 0;
    uint32_t off = TLV_HDR_SIZE;
    while (off + 8 <= len) {
        uint32_t type = rd_le32(fw + off);
        uint32_t tlen = rd_le32(fw + off + 4);
        const uint8_t *tdata = fw + off + 8;
        if ((uint64_t)off + 8 + tlen > len)
            break;
        if (type == IWL_UCODE_TLV_SEC_RT && tlen >= 4 && s_num_sec < MAX_FW_SEC) {
            s_sec[s_num_sec].offset = rd_le32(tdata);
            s_sec[s_num_sec].data   = tdata + 4;
            s_sec[s_num_sec].len    = tlen - 4;
            s_num_sec++;
        }
        off += 8 + ((tlen + 3u) & ~3u);    /* TLVs are 4-byte padded */
    }

    s_lmac_cnt   = sec_count_from(0);
    s_umac_cnt   = sec_count_from(s_lmac_cnt + 1);
    s_paging_cnt = sec_count_from(s_lmac_cnt + s_umac_cnt + 2);

    printk("[AX200] fw ver=0x%x: %d secs (lmac=%d umac=%d paging=%d)\n",
           (unsigned)s_fw_ver, s_num_sec, s_lmac_cnt, s_umac_cnt, s_paging_cnt);
    if (s_lmac_cnt == 0 || s_umac_cnt == 0) {
        printk("[AX200] FAIL: no lmac/umac sections parsed\n");
        return -1;
    }
    return 0;
}

void
iwl_ax200_init(void)
{
    /* 1. Find the AX200 among the enumerated PCIe devices. */
    const pcie_device_t *devs = pcie_get_devices();
    int n = pcie_device_count();
    const pcie_device_t *found = 0;
    for (int i = 0; i < n; i++) {
        if (devs[i].vendor_id == AX200_VENDOR && devs[i].device_id == AX200_DEVICE) {
            found = &devs[i];
            break;
        }
    }
    if (!found)
        return;   /* silent skip — no AX200 present */

    printk("[AX200] OK: found Intel Wi-Fi 6 AX200 at %x:%x.%x\n",
           (unsigned)found->bus, (unsigned)found->dev, (unsigned)found->fn);

    /* 2. Enable Memory space + Bus Master (BusMaster needed for the DMA rings
     * we set up in later phases; Memory space to reach BAR0). */
    {
        uint32_t cs = pcie_read32(found->bus, found->dev, found->fn, 0x04);
        cs &= 0xFFFF0000u;                 /* preserve status word */
        cs |= (PCI_CMD_MEM | PCI_CMD_BM);
        pcie_write32(found->bus, found->dev, found->fn, 0x04, cs);
    }

    /* 3. Wake to D0 (clear the PM power state) if a PM capability is present. */
    {
        uint8_t pmcsr = find_pm_pmcsr(found);
        if (pmcsr) {
            pcie_write32(found->bus, found->dev, found->fn, pmcsr, 0);
            for (volatile uint32_t i = 0; i < 1000000u; i++)
                __asm__ volatile("pause");   /* D3->D0 settle (<10ms) */
        }
    }

    /* 4. Map BAR0 (16 KB register window; 4 pages). */
    if (found->bar[0] == 0) {
        printk("[AX200] FAIL: BAR0 unmapped\n");
        return;
    }
    {
        uint64_t pa = found->bar[0] & ~0xFFFULL;   /* strip BAR type bits; 4K-aligned */
        s_mmio = (volatile uint8_t *)(map_bar(pa, 4) + (found->bar[0] & 0xFFFULL));
    }

    /* 5. First register reads. CSR_HW_REV is always-on, so a valid (non-0xFF..)
     * value proves the MMIO window is live and gives us the silicon stepping. */
    uint32_t hw_rev = csr_rd(CSR_HW_REV);
    if (hw_rev == 0xFFFFFFFFu) {
        printk("[AX200] FAIL: CSR read 0xFFFFFFFF (BAR0 wrong or device asleep)\n");
        return;
    }
    uint32_t rf_id  = csr_rd(CSR_HW_RF_ID);
    uint32_t if_cfg = csr_rd(CSR_HW_IF_CONFIG_REG);

    /* HW_REV low bits: step = bits [3:2], dash = bits [1:0] (iwlwifi convention). */
    printk("[AX200] HW_REV=0x%x (step=%u dash=%u) RF_ID=0x%x IF_CFG=0x%x\n",
           hw_rev,
           (unsigned)((hw_rev >> 2) & 0x3),
           (unsigned)(hw_rev & 0x3),
           rf_id, if_cfg);

    /* Phase 2 step A: power the NIC up to a clock-stable state. */
    if (power_up() != 0)
        return;
    /* Phase 2 step B: parse the embedded firmware into LMAC/UMAC/paging sections. */
    if (parse_firmware() != 0)
        return;
    /* Next (step C): build the context-info block + kick FW self-load → ALIVE. */
}
