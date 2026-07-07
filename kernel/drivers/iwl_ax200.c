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
#include "pmm.h"
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
#define CSR_RESET_SW_RESET            0x00000080
#define CSR_MAC_SHADOW_REG_CTRL       0x0A8
#define GIO_CHICKEN_L1A_NO_L0S_RX     0x00800000
#define DBG_HPET_MEM_REG_VAL          0xFFFF0000

/* Context-info firmware self-load (step C). CSR_CTXT_INFO_BA is the 64-bit
 * register the chip reads the context-info block address from; writing it kicks
 * the load. Prph writes go through the HBUS indirect window. */
#define CSR_CTXT_INFO_BA        0x040
#define CSR_INT_MASK            0x00C
#define HBUS_TARG_PRPH_WADDR    0x444   /* HBUS_BASE(0x400)+0x044 */
#define HBUS_TARG_PRPH_WDAT     0x44C
#define HBUS_TARG_PRPH_RADDR    0x448
#define HBUS_TARG_PRPH_RDAT     0x450
#define HBUS_TARG_MEM_RADDR     0x40C   /* device SRAM read (auto-increment) */
#define HBUS_TARG_MEM_RDAT      0x41C
/* FW boot-status / program-counter regs — readable without ALIVE, so they name
 * an early assert (SB = secure-boot status; report the ROM/IML/uCode stage). */
#define SB_CPU_1_STATUS         0xA01E30
#define SB_CPU_2_STATUS         0xA01E34
#define UMAG_SB_CPU_1_STATUS    0xA038C0
#define UMAG_SB_CPU_2_STATUS    0xA038C4
#define UREG_UMAC_CURRENT_PC    0xA05C18
#define UREG_LMAC1_CURRENT_PC   0xA05C1C
#define UREG_CPU_INIT_RUN       0xA05C44
#define PRPH_ADDR_MASK          0x000FFFFF   /* 22000 family: 20-bit prph addr */
#define CSR_INT_BIT_ALIVE       (1u << 0)
#define CSR_INT_BIT_RF_KILL     (1u << 7)
#define CSR_INT_BIT_SW_ERR      (1u << 25)
#define CSR_INT_BIT_HW_ERR      (1u << 29)
#define CSR_INT_BIT_FH_RX       (1u << 31)
#define CTXT_INFO_TFD_FORMAT_LONG  0x0100
#define CTXT_INFO_RB_SIZE_4K       0x4
#define NRBDS                   512    /* RX free-buffer ring depth (cb_size=9) */

/* RX/command doorbell (HBUS_BASE+0x060). Low 16 bits = write pointer, high bits
 * select the queue: (q<<16) for TX, ((q+512)<<16) for RX. */
#define HBUS_TARG_WRPTR         0x460
#define UCODE_ALIVE_NTFY        0x01
#define IWL_ALIVE_STATUS_OK     0xCAFE

/* Host command TX (Phase 3b). Command queue id 0 (IWL_MVM_DQA_CMD_QUEUE); the
 * TX doorbell is HBUS_TARG_WRPTR = write_ptr | (q<<16). Commands use the 8-byte
 * wide header and a 2-TB TFD (first 20 bytes in a dedicated first-TB buffer). */
#define CMD_Q_ID                0
#define QUEUE_TO_SEQ(q)         (((q) & 0x1fu) << 8)
#define INDEX_TO_SEQ(i)         ((i) & 0xffu)
#define IWL_FIRST_TB_SIZE       20
#define SYSTEM_GROUP            0x02
#define SHARED_MEM_CFG_CMD      0x00   /* in SYSTEM_GROUP — a read-only query */
#define REGULATORY_AND_NVM_GROUP 0x0c
#define NVM_GET_INFO            0x02   /* in REGULATORY_AND_NVM_GROUP */
#define GP_CNTRL_MAC_ACCESS_REQ 0x00000008

/* Receive Flow Handler (RFH) registers — gen2 RX must be set up here directly,
 * not just via the context-info block (iwl_pcie_rx_mq_hw_init). All are prph
 * (masked to 20 bits by write_prph) except WIDX_TRG which is a direct CSR. */
#define RFH_Q0_FRBDCB_BA_LSB       0xA08000   /* free RBD ring base (64-bit) */
#define RFH_Q0_FRBDCB_WIDX         0xA08080
#define RFH_Q0_FRBDCB_RIDX         0xA080C0
#define RFH_Q0_URBDCB_BA_LSB       0xA08100   /* used RBD ring base (64-bit) */
#define RFH_Q0_URBDCB_WIDX         0xA08180
#define RFH_Q0_URBD_STTS_WPTR_LSB  0xA08200   /* RB status write ptr (64-bit) */
#define RFH_Q0_FRBDCB_WIDX_TRG     0x1C80     /* RX doorbell — DIRECT CSR */
#define RFH_RXF_DMA_CFG            0xA09820
#define RFH_RXF_RXQ_ACTIVE         0xA0980C
#define RFH_GEN_CFG               0xA09800
/* DMA_CFG = enable | RB_4K(0x4<<16) | min-RB-4/8(3<<24) | drop-too-large(bit26)
 * | RBDCB-512(0x9<<20). */
#define RFH_RXF_DMA_CFG_VAL       0x87940000u
/* GEN_CFG = RFH_DMA_SNOOP(b1) | SERVICE_DMA_SNOOP(b0) | RB_CHUNK_128(b4, discrete). */
#define RFH_GEN_CFG_VAL           0x13u
#define RFH_RXQ0_ENABLE           0x00010001u   /* BIT(0)|BIT(16) */
#define CSR_INT_COALESCING        0x004         /* 8-bit reg */

/* PCI command register bits + PM capability id */
#define PCI_CMD_MEM    0x02
#define PCI_CMD_BM     0x04
#define PCI_CAP_ID_PM  0x01

/* MMIO must be uncached (device registers). Matches rtl8169's mapping flags. */
#define MMIO_FLAGS (VMM_FLAG_WRITABLE | VMM_FLAG_WC | VMM_FLAG_UCMINUS)

static volatile uint8_t *s_mmio;   /* BAR0 kernel VA */

/* RX queue state (kept so we can read FW->host notifications). */
static uint8_t          *s_rx_buf_va[512];   /* KVA of each RX buffer (NRBDS) */
static volatile uint8_t *s_rb_stts;          /* KVA of the RB status block */
static volatile uint8_t *s_used_bd;          /* KVA of the used-RBD completion ring */
static volatile uint8_t *s_cmd_ring;         /* KVA of the command TFD ring */
static uint16_t          s_cmd_wr;           /* command queue write pointer */
static uint16_t          s_rx_read;          /* next RX buffer index to examine */

static inline uint32_t csr_rd(uint32_t off) { return *(volatile uint32_t *)(s_mmio + off); }
static inline void     csr_wr(uint32_t off, uint32_t v) { *(volatile uint32_t *)(s_mmio + off) = v; }
static inline void csr_set(uint32_t off, uint32_t m) { csr_wr(off, csr_rd(off) | m); }
static inline void csr_clr(uint32_t off, uint32_t m) { csr_wr(off, csr_rd(off) & ~m); }

/* Indirect peripheral (prph) register writes via the HBUS window. 22000 family
 * masks the address to 20 bits (the 0xA00000 UMAC prefix is implicit). */
static void wr_prph(uint32_t addr, uint32_t val)
{
    csr_wr(HBUS_TARG_PRPH_WADDR, (addr & PRPH_ADDR_MASK) | (3u << 24));
    csr_wr(HBUS_TARG_PRPH_WDAT, val);
}
static uint32_t rd_prph(uint32_t addr)
{
    csr_wr(HBUS_TARG_PRPH_RADDR, (addr & PRPH_ADDR_MASK) | (3u << 24));
    return csr_rd(HBUS_TARG_PRPH_RDAT);
}

/* Read device SRAM: write the address once, then read RDAT (auto-increments). */
static uint32_t s_umac_err_addr;   /* UMAC error-log SRAM addr (from ALIVE ntf) */
static void
dump_fw_error(void)
{
    if (!s_umac_err_addr) return;
    csr_wr(HBUS_TARG_MEM_RADDR, s_umac_err_addr);
    uint32_t w[6];
    for (int i = 0; i < 6; i++) w[i] = csr_rd(HBUS_TARG_MEM_RDAT);
    /* iwl_umac_error_event_table: valid@0, error_id@4, blink1/2@8/12, ilink1/2@16/20 */
    printk("[AX200] FW-ERR umac@0x%x valid=0x%x error_id=0x%x blink=%x/%x ilink=%x/%x\n",
           s_umac_err_addr, w[0], w[1], w[2], w[3], w[4], w[5]);
}

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
#define IWL_UCODE_TLV_DEF_CALIB 22
#define IWL_UCODE_TLV_PHY_SKU  23
#define IWL_UCODE_TLV_CMD_VERSIONS 48
#define CPU1_CPU2_SEPARATOR    0xFFFFCCCCu
#define PAGING_SEPARATOR       0xAAAABBBBu
#define MAX_FW_SEC             64   /* IWL_MAX_DRAM_ENTRY; firmware has ~27+ secs */

struct fw_sec { uint32_t offset; const uint8_t *data; uint32_t len; };
static struct fw_sec s_sec[MAX_FW_SEC];
static int      s_num_sec;
static uint32_t s_fw_ver;
static int      s_lmac_cnt, s_umac_cnt, s_paging_cnt;
static uint32_t s_phy_config;               /* from PHY_SKU TLV */
static uint32_t s_calib_flow, s_calib_event; /* from DEF_CALIB TLV (regular ucode) */
static int      s_ap_found;                       /* target AP seen in scan */
static uint8_t  s_ap_bssid[6];                     /* target AP BSSID (addr3) */
static uint8_t  s_ap_channel;                      /* target AP channel (DS param) */
static uint8_t  s_scan_req_ver, s_scan_req_grp;   /* SCAN_REQ_UMAC (cmd 0x0d) */
static uint8_t  s_scan_cfg_ver, s_scan_cfg_grp;   /* SCAN_CFG_CMD (cmd 0x0c) */
static uint8_t  s_scd_qcfg_ver;                   /* SCD_QUEUE_CONFIG_CMD (0x17/g5) */

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
        } else if (type == IWL_UCODE_TLV_PHY_SKU && tlen >= 4) {
            s_phy_config = rd_le32(tdata);                 /* phy_cfg for PHY_CONFIG */
        } else if (type == IWL_UCODE_TLV_DEF_CALIB && tlen >= 12 &&
                   rd_le32(tdata) == 0 /* IWL_UCODE_REGULAR */) {
            s_calib_flow  = rd_le32(tdata + 4);
            s_calib_event = rd_le32(tdata + 8);
        } else if (type == IWL_UCODE_TLV_CMD_VERSIONS) {
            for (uint32_t o = 0; o + 4 <= tlen; o += 4) {   /* iwl_fw_cmd_version[] */
                uint8_t c = tdata[o], g = tdata[o + 1], v = tdata[o + 2];
                if (c == 0x0d && g == 0x00) { s_scan_req_ver = v; s_scan_req_grp = g; }
                if (c == 0x0c && g == 0x01) { s_scan_cfg_ver = v; s_scan_cfg_grp = g; }
                /* connect-path commands live in LONG_GROUP (g1): PHY_CTXT 0x8 v3,
                 * ADD_STA 0x18 v12, TX 0x1c v7, MAC_CTXT 0x28 v5, BINDING 0x2b v2 */
                if (c == 0x17 && g == 0x05) s_scd_qcfg_ver = v;   /* new txq path */
                /* DATA_PATH_GROUP(5): TLC 0x0f, RLC 0x08, STA_HE 0x07 */
                if (g == 0x05 && (c==0x0f||c==0x08||c==0x07||c==0x0d||c==0x17))
                    printk("[AX200] dpcmdver 0x%x/g%u=v%u\n", c, g, v);
            }
        }
        off += 8 + ((tlen + 3u) & ~3u);    /* TLVs are 4-byte padded */
    }

    s_lmac_cnt   = sec_count_from(0);
    s_umac_cnt   = sec_count_from(s_lmac_cnt + 1);
    s_paging_cnt = sec_count_from(s_lmac_cnt + s_umac_cnt + 2);

    printk("[AX200] fw ver=0x%x: %d secs (lmac=%d umac=%d paging=%d) phy_cfg=0x%x calib=%x/%x\n",
           (unsigned)s_fw_ver, s_num_sec, s_lmac_cnt, s_umac_cnt, s_paging_cnt,
           (unsigned)s_phy_config, (unsigned)s_calib_flow, (unsigned)s_calib_event);
    printk("[AX200] cmd_ver: SCAN_REQ_UMAC=v%u(grp%u) SCAN_CFG=v%u(grp%u)\n",
           s_scan_req_ver, s_scan_req_grp, s_scan_cfg_ver, s_scan_cfg_grp);
    if (s_lmac_cnt == 0 || s_umac_cnt == 0) {
        printk("[AX200] FAIL: no lmac/umac sections parsed\n");
        return -1;
    }
    return 0;
}

/* ── Context-info firmware self-load (Phase 2 step C) ──────────────────
 * The gen2 chip loads its own firmware: we build an iwl_context_info block in
 * host DMA memory pointing at the ucode sections + the RX/command queues, write
 * its address to CSR_CTXT_INFO_BA, start the CPU (UREG_CPU_INIT_RUN), and the
 * chip DMA-loads the ucode and raises an ALIVE interrupt (CSR_INT bit 0). */

/* iwl_context_info — exact on-wire layout (packed, little-endian; x86 is LE). */
struct ci_dram {
    uint64_t umac_img[64];
    uint64_t lmac_img[64];
    uint64_t virtual_img[64];
} __attribute__((packed));

struct context_info {
    uint16_t ver_mac_id, ver_version, ver_size, ver_reserved;      /* +0   version */
    uint32_t control_flags, control_reserved;                       /* +8   control */
    uint64_t reserved0;                                             /* +16  */
    uint64_t free_rbd_addr, used_rbd_addr, status_wr_ptr;           /* +24  rbd_cfg */
    uint64_t cmd_queue_addr; uint8_t cmd_queue_size, hcmd_rsvd[7];  /* +48  hcmd_cfg */
    uint32_t reserved1[4];                                          /* +64  */
    uint64_t dump_addr; uint32_t dump_size, dump_rsvd;              /* +80  dump_cfg */
    uint64_t edbg_addr; uint32_t edbg_size, edbg_rsvd;              /* +96  edbg_cfg */
    uint64_t pnvm_addr; uint32_t pnvm_size, pnvm_rsvd;              /* +112 pnvm_cfg */
    uint32_t reserved2[16];                                        /* +128 */
    struct ci_dram dram;                                            /* +192 */
    uint32_t reserved3[16];                                        /* +1728 (total 1792) */
} __attribute__((packed));

/* Allocate `bytes` of physically-contiguous, zeroed, cacheable DMA memory
 * (<4GB; x86 RAM is DMA-coherent). Returns KVA, *phys_out = physical base. */
static void *
dma_alloc(uint64_t bytes, uint64_t *phys_out)
{
    uint64_t pages = (bytes + 4095) / 4096;
    uint64_t phys = pmm_alloc_contig_low(pages);
    if (!phys)
        return 0;
    uintptr_t va = (uintptr_t)kva_alloc_pages(pages);
    if (!va)
        return 0;
    for (uint64_t i = 0; i < pages; i++) {
        vmm_unmap_page(va + i * 4096);
        vmm_map_page(va + i * 4096, phys + i * 4096, VMM_FLAG_WRITABLE);
    }
    for (uint64_t i = 0; i < pages * 4096; i++)
        ((volatile uint8_t *)va)[i] = 0;
    *phys_out = phys;
    return (void *)va;
}

static void
mcopy(void *dst, const void *src, uint64_t n)
{
    volatile uint8_t *d = dst;
    const uint8_t *s = src;
    for (uint64_t i = 0; i < n; i++)
        d[i] = s[i];
}

/* DMA a firmware section; return its physical address (0 on failure).
 * Returned by value (not via &slot) so callers avoid taking the address of a
 * packed DRAM-map member. */
static uint64_t
load_sec(int sec_idx)
{
    uint64_t p;
    void *m = dma_alloc(s_sec[sec_idx].len, &p);
    if (!m)
        return 0;
    mcopy(m, s_sec[sec_idx].data, s_sec[sec_idx].len);
    return p;
}

/* Read the FW's ALIVE notification out of the RX queue. Each RX buffer holds an
 * iwl_rx_packet: len_n_flags(4) + cmd_header{cmd,group_id,seq}(4) + data. The
 * FW advances rb_stts.closed_rb_num and writes the buffer's rbid into the used
 * ring (iwl_rx_completion_desc: rbid at byte 4). We mapped rbid = index+1. */
static void
process_rx_alive(void)
{
    uint16_t closed = 0;
    for (int t = 0; t < 20000; t++) {             /* up to ~200ms for the ntf */
        closed = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
        if (closed != 0)
            break;
        busy_wait_us(10);
    }
    if (closed == 0) {
        printk("[AX200] no RX ntf: rb_stts[0..3]=%x %x %x %x CSR_INT=0x%x used[0..7]=%x %x %x %x %x %x %x %x\n",
               s_rb_stts[0], s_rb_stts[1], s_rb_stts[2], s_rb_stts[3], csr_rd(CSR_INT),
               s_used_bd[0], s_used_bd[1], s_used_bd[2], s_used_bd[3],
               s_used_bd[4], s_used_bd[5], s_used_bd[6], s_used_bd[7]);
        return;
    }

    printk("[AX200] RX closed=%u used_bd[0..11]=%x %x %x %x %x %x %x %x %x %x %x %x\n", closed,
           s_used_bd[0], s_used_bd[1], s_used_bd[2], s_used_bd[3], s_used_bd[4], s_used_bd[5],
           s_used_bd[6], s_used_bd[7], s_used_bd[8], s_used_bd[9], s_used_bd[10], s_used_bd[11]);
    /* The first RX uses free_rbd[0] (vid 1) = buffer 0; read the packet there:
     * iwl_rx_packet = len_n_flags(4) + cmd_header{cmd,grp,seq}(4) + data. */
    const uint8_t *pkt = s_rx_buf_va[0];
    printk("[AX200] buf0: len_n_flags=0x%x cmd=0x%x grp=0x%x status=0x%x\n",
           rd_le32(pkt), pkt[4], pkt[5], (uint16_t)(pkt[8] | (pkt[9] << 8)));
    if (pkt[4] == UCODE_ALIVE_NTFY) {
        uint16_t status = (uint16_t)(pkt[8] | (pkt[9] << 8));
        printk("[AX200] ALIVE ntf: status=0x%x (%s) — FW fully initialized\n",
               status, status == IWL_ALIVE_STATUS_OK ? "OK" : "ERR");
        /* umac error_info_addr: alive body @pkt+8; umac_data after lmac_data[].
         * v6 (2 lmac) -> +108, v5 (1 lmac) -> +60. Pick the plausible SRAM addr. */
        uint32_t a_v6 = rd_le32(pkt + 8 + 108);
        uint32_t a_v5 = rd_le32(pkt + 8 + 60);
        printk("[AX200] err_info_addr candidates v6=0x%x v5=0x%x\n", a_v6, a_v5);
        s_umac_err_addr = a_v6;
    }
}

/* Append a transmit buffer to a gen2 TFD (iwl_tfh_tfd: num_tbs(2) then tbs[];
 * iwl_tfh_tb = tb_len(2) + addr(8), 10 bytes each). */
static void
set_tfd_tb(volatile uint8_t *tfd, uint64_t addr, uint16_t len)
{
    uint16_t n = (uint16_t)(tfd[0] | (tfd[1] << 8));
    volatile uint8_t *tb = tfd + 2 + (uint32_t)n * 10;
    tb[0] = (uint8_t)(len & 0xff);
    tb[1] = (uint8_t)((len >> 8) & 0xff);
    for (int i = 0; i < 8; i++)
        tb[2 + i] = (uint8_t)(addr >> (i * 8));
    n++;
    tfd[0] = (uint8_t)(n & 0xff);
    tfd[1] = (uint8_t)((n >> 8) & 0xff);
}

/* Send a host command (id = (group_id<<8)|opcode) with an optional payload.
 * Builds the wide-header command in DMA, copies its first 20 bytes into a
 * first-TB buffer, builds a 2-TB TFD in the command queue, rings the doorbell. */
static void
send_cmd(uint16_t cmd_id, const void *payload, uint16_t plen)
{
    uint64_t cmd_phys = 0, ftb_phys = 0;
    uint8_t *cmd = dma_alloc((uint64_t)8 + plen + 64, &cmd_phys);
    uint8_t *ftb = dma_alloc(64, &ftb_phys);
    if (!cmd || !ftb) {
        printk("[AX200] send_cmd: DMA alloc failed\n");
        return;
    }

    uint16_t seq = (uint16_t)(QUEUE_TO_SEQ(CMD_Q_ID) | INDEX_TO_SEQ(s_cmd_wr));
    cmd[0] = (uint8_t)(cmd_id & 0xff);          /* opcode */
    cmd[1] = (uint8_t)((cmd_id >> 8) & 0xff);   /* group_id */
    cmd[2] = (uint8_t)(seq & 0xff);
    cmd[3] = (uint8_t)((seq >> 8) & 0xff);       /* sequence (le16) */
    cmd[4] = (uint8_t)(plen & 0xff);
    cmd[5] = (uint8_t)((plen >> 8) & 0xff);      /* length (le16) */
    cmd[6] = 0; cmd[7] = 0;                       /* reserved, version */
    if (plen)
        mcopy(cmd + 8, payload, plen);

    uint16_t copy_size = (uint16_t)(8 + plen);
    uint16_t tb0 = copy_size < IWL_FIRST_TB_SIZE ? copy_size : IWL_FIRST_TB_SIZE;
    mcopy(ftb, cmd, tb0);

    volatile uint8_t *tfd = s_cmd_ring + (uint32_t)s_cmd_wr * 256;
    tfd[0] = 0; tfd[1] = 0;                       /* num_tbs = 0 */
    set_tfd_tb(tfd, ftb_phys, tb0);
    if (copy_size > tb0)
        set_tfd_tb(tfd, cmd_phys + tb0, (uint16_t)(copy_size - tb0));

    s_cmd_wr = (uint16_t)((s_cmd_wr + 1) & 31);
    csr_wr(HBUS_TARG_WRPTR, (uint32_t)(s_cmd_wr | (CMD_Q_ID << 16)));
    printk("[AX200] sent cmd 0x%x (seq=0x%x, %u bytes) wr->%u\n",
           cmd_id, seq, copy_size, s_cmd_wr);
}

/* Send a command and dump the FW's response packet (cmd/group + 24 payload
 * bytes). The response is the newest RX buffer once rb_stts advances. */
static void wr_le32b(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* Wait for a FW notification with the given cmd/group to arrive via RX, scanning
 * each new RB in order (buffer i = RB i). Returns the buffer index, or -1. */
static int
wait_notif(uint8_t want_cmd, uint8_t want_grp, int timeout_ms)
{
    for (int t = 0; t < timeout_ms * 100; t++) {
        uint16_t closed = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
        while (s_rx_read != closed) {
            const uint8_t *r = s_rx_buf_va[s_rx_read & 511];
            uint8_t c = r[4], g = r[5];
            printk("[AX200]   ntf cmd=0x%x grp=0x%x\n", c, g);
            s_rx_read++;
            if (c == want_cmd && g == want_grp)
                return (s_rx_read - 1) & 511;
        }
        uint32_t ie = csr_rd(CSR_INT);
        if (ie & (CSR_INT_BIT_SW_ERR | CSR_INT_BIT_HW_ERR)) {
            printk("[AX200] FW error waiting for ntf 0x%x/0x%x: CSR_INT=0x%x umacPC=0x%x\n",
                   want_cmd, want_grp, ie, rd_prph(UREG_UMAC_CURRENT_PC));
            return -1;
        }
        busy_wait_us(10);
    }
    return -1;
}

/* Post-ALIVE init sequence (iwl_run_unified_mvm_ucode): INIT_EXTENDED_CFG ->
 * NVM_ACCESS_COMPLETE -> PHY_CONFIGURATION_CMD -> wait INIT_COMPLETE_NOTIF. The
 * NVM load is skipped (the AX200 uses its on-die OTP). */
/* Send a command and watch ~100ms for a FW assert, to isolate a failing step. */
static int
send_check(uint16_t cmd_id, const void *pl, uint16_t plen, const char *tag)
{
    send_cmd(cmd_id, pl, plen);
    for (int t = 0; t < 10000; t++) {
        uint32_t ie = csr_rd(CSR_INT);
        if (ie & (CSR_INT_BIT_SW_ERR | CSR_INT_BIT_HW_ERR)) {
            printk("[AX200] %s ASSERTED CSR_INT=0x%x umacPC=0x%x\n",
                   tag, ie, rd_prph(UREG_UMAC_CURRENT_PC));
            dump_fw_error();
            return -1;
        }
        busy_wait_us(10);
    }
    printk("[AX200] %s ok (no assert; rb_stts=%u)\n",
           tag, *(volatile uint16_t *)s_rb_stts & 0x0FFFu);
    return 0;
}

static int
init_after_alive(void)
{
    s_rx_read = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;   /* skip past the alive ntf */

    uint8_t buf[28];
    /* 1. INIT_EXTENDED_CFG_CMD (SYSTEM_GROUP 0x2, cmd 0x03): flag NVM access. */
    wr_le32b(buf, 1u << 1 /* BIT(IWL_INIT_NVM) */);
    if (send_check((SYSTEM_GROUP << 8) | 0x03, buf, 4, "INIT_EXTENDED_CFG") != 0) return -1;

    /* 2. NVM_ACCESS_COMPLETE (REGULATORY_AND_NVM_GROUP 0xc, cmd 0x00). */
    wr_le32b(buf, 0);
    if (send_check((REGULATORY_AND_NVM_GROUP << 8) | 0x00, buf, 4, "NVM_ACCESS_COMPLETE") != 0) return -1;

    /* PHY_CONFIGURATION_CMD is intentionally NOT sent: iwl_send_phy_cfg_cmd is a
     * no-op for the unified ucode (returns early), and sending it asserts. */

    /* 3. Wait for INIT_COMPLETE_NOTIF (cmd 0x04, legacy group 0x0). */
    if (wait_notif(0x04, 0x00, 3000) < 0) {
        printk("[AX200] no INIT_COMPLETE (rb_stts=%u)\n",
               *(volatile uint16_t *)s_rb_stts & 0x0FFFu);
        return -1;
    }
    printk("[AX200] *** INIT_COMPLETE *** FW fully initialized past ALIVE!\n");
    return 0;
}

/* Phase 3d: a passive scan of the 2.4GHz band (SCAN_REQ_UMAC v14, group 1). We
 * build the ~1940-byte iwl_scan_req_umac_v17 for v14, force a passive/pass-all
 * scan, list channels 1-13, then watch RX for beacon frames and print any that
 * contain the target SSID. */
static void
do_scan(void)
{
    uint64_t phys;
    uint8_t *cmd = dma_alloc(2560, &phys);   /* zeroed */
    if (!cmd) { printk("[AX200] scan: DMA alloc failed\n"); return; }
    (void)phys;

    /* SCAN_CFG_CMD (v4, group 1, cmd 0x0c => 0x10c): the reduced scan config,
     * required once before any scan request. struct iwl_scan_config (12B):
     * bcast_sta_id=0xff (cmd_ver<5), tx/rx chains = ANT_AB (AX200 2x2, from
     * phy_cfg 0x330018). */
    uint8_t cfg[12] = {0};
    cfg[2] = 0xff;
    wr_le32b(cfg + 4, 3);
    wr_le32b(cfg + 8, 3);
    if (send_check(0x10c, cfg, 12, "SCAN_CFG") != 0) return;

    wr_le32b(cmd + 0, 1);                     /* uid */
    wr_le32b(cmd + 4, 6);                     /* ooc_priority = EXT_6 */

    /* general_params_v11 @ +8. flags = PASS_ALL(0x2)|USE_ALL_RX_CHAINS(0x40)|
     * FORCE_PASSIVE(0x800) = 0x842 (iwl_mvm_scan_umac_flags_v2). */
    cmd[8] = 0x42; cmd[9] = 0x08;
    cmd[12] = 10; cmd[13] = 10;               /* active_dwell[2] */
    cmd[14] = 10; cmd[15] = 10; cmd[16] = 10; /* adwell 2g/5g/social */
    cmd[18] = 44; cmd[19] = 1;                /* adwell_max_budget (le16) = 300 */
    wr_le32b(cmd + 36, 6);                    /* scan_priority = EXT_6 */
    cmd[40] = 110; cmd[41] = 110;             /* passive_dwell[2] */

    /* channel_params_v7 @ +44: count + channel_config[] (each 8B: flags(4)+
     * v2{channel_num,band,iter_count,iter_interval}). Band 1 = 2.4GHz. */
    cmd[45] = 13;                             /* count */
    for (int i = 0; i < 13; i++) {
        uint8_t *ch = cmd + 48 + i * 8;
        ch[4] = (uint8_t)(i + 1);             /* channel_num 1..13 */
        ch[5] = 1;                            /* band = PHY_BAND_24 */
        ch[6] = 1;                            /* iter_count */
    }

    /* periodic_params_v1 @ +584: schedule[0].iter_count = 1 */
    cmd[584 + 2] = 1;

    /* probe_params_v4 @ +596. preq (iwl_scan_probe_req) = mac_header seg (4) +
     * band_data[3] seg (12) + common_data seg (4) + buf[512]. Build a minimal
     * broadcast probe request in buf so the FW's preq validation passes. */
    uint8_t *buf = cmd + 596 + 4 + 12 + 4;    /* preq.buf */
    /* 802.11 MAC header (24 bytes): probe request, broadcast DA/BSSID. */
    buf[0] = 0x40; buf[1] = 0x00;             /* frame control = probe req */
    for (int i = 4; i < 10; i++)  buf[i] = 0xff;  /* addr1 DA = broadcast */
    /* addr2 SA (10..15) = 0 (any) */
    for (int i = 16; i < 22; i++) buf[i] = 0xff;  /* addr3 BSSID = broadcast */
    /* IEs @ buf+24: SSID (wildcard, len 0) + supported rates. */
    buf[24] = 0x00; buf[25] = 0x00;           /* SSID IE id=0 len=0 */
    buf[26] = 0x01; buf[27] = 0x04;           /* rates IE id=1 len=4 */
    buf[28] = 0x82; buf[29] = 0x84; buf[30] = 0x8b; buf[31] = 0x96;
    /* Segments (each __le16 offset, __le16 len into buf). */
    uint8_t *seg = cmd + 596;
    seg[0] = 0;  seg[1] = 0;  seg[2] = 24; seg[3] = 0;   /* mac_header: off 0, len 24 */
    /* band_data[3] @ seg+4: leave zero */
    seg[16] = 24; seg[17] = 0; seg[18] = 8; seg[19] = 0; /* common_data: off 24, len 8 */
    /* Total struct = 1940 bytes. */

    send_cmd(0x10d, cmd, 1940);              /* SCAN_REQ_UMAC, group 1 */
    printk("[AX200] SCAN_REQ_UMAC sent (passive, ch 1-13); watching for beacons...\n");

    s_rx_read = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
    int found = 0;
    for (int t = 0; t < 600000; t++) {        /* up to ~6s */
        uint16_t closed = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
        while (s_rx_read != closed) {
            const uint8_t *r = s_rx_buf_va[s_rx_read & 511];
            uint8_t c = r[4], g = r[5];
            s_rx_read++;
            /* Scan the RB for the target SSID (pragmatic: find it in the beacon). */
            for (int o = 8; o < 4090; o++) {
                if (r[o]=='H' && r[o+1]=='a' && r[o+2]=='r' && r[o+3]=='t') {
                    char ss[40]; int j = 0;
                    for (int k = o; k < o + 32 && r[k] >= 0x20 && r[k] < 0x7f; k++)
                        ss[j++] = (char)r[k];
                    ss[j] = 0;
                    printk("[AX200] *** SCAN FOUND SSID: '%s' *** (ntf cmd=0x%x grp=0x%x)\n", ss, c, g);
                    found = 1;
                    /* For "Hart Guest": capture BSSID + channel from the beacon.
                     * o points at the SSID value; the 802.11 frame body starts 38
                     * bytes back (24 hdr + 12 fixed + 2 IE hdr), so addr3/BSSID is
                     * at o-22 and the IE list at o-2. */
                    if (!s_ap_found && o >= 40 &&
                        ss[0]=='H'&&ss[4]==' '&&ss[5]=='G') {   /* "Hart Guest" */
                        for (int k = 0; k < 6; k++) s_ap_bssid[k] = r[o - 22 + k];
                        int slen = r[o - 1];
                        int p = (o - 2) + 2 + slen;            /* IE after SSID */
                        for (int gd = 0; gd < 32 && p < 4088; gd++) {
                            uint8_t id = r[p], ln = r[p + 1];
                            if (id == 3 && ln >= 1) { s_ap_channel = r[p + 2]; break; }
                            p += 2 + ln;
                        }
                        s_ap_found = 1;
                        printk("[AX200] target 'Hart Guest' BSSID %x:%x:%x:%x:%x:%x ch=%u\n",
                               s_ap_bssid[0],s_ap_bssid[1],s_ap_bssid[2],
                               s_ap_bssid[3],s_ap_bssid[4],s_ap_bssid[5], s_ap_channel);
                    }
                }
            }
            if (c == 0x0f && g == 0x00) {
                printk("[AX200] SCAN_COMPLETE (found Hart=%d)\n", found);
                return;
            }
        }
        uint32_t ie = csr_rd(CSR_INT);
        if (ie & (CSR_INT_BIT_SW_ERR | CSR_INT_BIT_HW_ERR)) {
            printk("[AX200] scan FW error CSR_INT=0x%x umacPC=0x%x\n",
                   ie, rd_prph(UREG_UMAC_CURRENT_PC));
            return;
        }
        busy_wait_us(10);
    }
    printk("[AX200] scan timeout (found Hart=%d)\n", found);
}

/* Data TX queue (allocated dynamically; the FW returns its qid). */
#define TXQ_SLOTS 256
static volatile uint8_t *s_tx_ring;
static uint64_t          s_tx_ring_phys;
static int               s_tx_qid = -1;
static uint16_t          s_tx_wr;
static volatile uint8_t *s_tx_bc_va;              /* byte-count table (iwlagn_scd_bc_tbl) */
static const uint8_t     s_our_mac[6] = {0x02,0x00,0x00,0xae,0x61,0x5a};

/* Transmit an 802.11 frame: a TX_CMD (0x11c) on the data queue, wrapping
 * iwl_tx_cmd_gen2 (len, offload_assist, flags, dram_info, rate_n_flags) + frame. */
static void
send_frame(const uint8_t *frame, uint16_t flen, uint32_t rate, const char *tag)
{
    if (s_tx_qid < 0) return;
    /* TX frames use the SHORT 4-byte cmd header (not the 8-byte wide header that
     * host commands use): [hdr 4][iwl_tx_cmd_gen2 20][802.11 frame]. */
    uint64_t cmd_phys = 0, ftb_phys = 0;
    uint8_t *cmd = dma_alloc((uint64_t)4 + 20 + flen + 64, &cmd_phys);
    uint8_t *ftb = dma_alloc(64, &ftb_phys);
    if (!cmd || !ftb) { printk("[AX200] TX dma fail\n"); return; }

    uint16_t seq = (uint16_t)(QUEUE_TO_SEQ(s_tx_qid) | INDEX_TO_SEQ(s_tx_wr));
    cmd[0] = 0x1c; cmd[1] = 0x00;                    /* TX_CMD, group 0 (legacy) —
                                                        iwlwifi leaves group_id=0 for
                                                        the gen2 TX cmd; group 1 makes
                                                        the FW silently drop the TFD */
    cmd[2] = (uint8_t)(seq & 0xff); cmd[3] = (uint8_t)(seq >> 8);
    uint8_t *tc = cmd + 4;                           /* iwl_tx_cmd_gen2 */
    tc[0] = (uint8_t)(flen & 0xff); tc[1] = (uint8_t)(flen >> 8);   /* len */
    /* offload_assist: MH_SIZE (mac hdr in 2-byte words) << 8. 24B mgmt hdr = 12. */
    tc[2] = 0x00; tc[3] = 0x0c;                       /* 12 << 8 = 0x0C00 */
    wr_le32b(tc + 4, 0x6);                           /* flags ENCRYPT_DIS|HIGH_PRI —
                                                        matches iwlwifi's live auth TX
                                                        (0x06, NOT CMD_RATE); rate=0 so
                                                        the FW uses the TLC rate table */
    /* dram_info @8 = 0 (8 bytes) */
    wr_le32b(tc + 16, rate);                          /* rate_n_flags */
    mcopy(tc + 20, frame, flen);

    uint16_t copy_size = (uint16_t)(4 + 20 + flen);
    uint16_t tb0 = copy_size < IWL_FIRST_TB_SIZE ? copy_size : IWL_FIRST_TB_SIZE;
    mcopy(ftb, cmd, tb0);
    volatile uint8_t *tfd = s_tx_ring + (uint32_t)s_tx_wr * 256;
    tfd[0] = 0; tfd[1] = 0;
    set_tfd_tb(tfd, ftb_phys, tb0);                        /* TB0: first 20 bytes */
    /* Match iwlwifi's TB layout: TB1 ends exactly at the end of the 802.11 header
     * (4 hdr + 20 tx_cmd + 24 mac hdr = 48), payload goes in its own TB. */
    uint16_t hdr_end = 4 + 20 + 24;
    if (hdr_end > tb0)
        set_tfd_tb(tfd, cmd_phys + tb0, (uint16_t)(hdr_end - tb0));   /* TB1 */
    if (copy_size > hdr_end)
        set_tfd_tb(tfd, cmd_phys + hdr_end, (uint16_t)(copy_size - hdr_end)); /* TB2: payload */

    /* Byte-count table entry for this TFD (gen2: dword count, 2 TBs -> 0 chunks).
     * byte_cnt = tx_cmd_gen2.len = the 802.11 frame length. */
    uint16_t idx = s_tx_wr;
    uint16_t bc = (uint16_t)((flen + 3) / 4);
    s_tx_bc_va[idx * 2]     = (uint8_t)(bc & 0xff);
    s_tx_bc_va[idx * 2 + 1] = (uint8_t)((bc >> 8) & 0xff);

    /* Dump the built TFD + command so we can byte-compare against iwlwifi. */
    volatile uint8_t *td = tfd;
    printk("[AX200] TFD: ntb=%u tb0[len=%u] tb1[len=%u] | cmd: %x %x %x %x tc.len=%u off=%x%x rate=%x%x%x%x\n",
           td[0], td[2] | (td[3] << 8), td[12] | (td[13] << 8),
           cmd[0], cmd[1], cmd[2], cmd[3], tc[0] | (tc[1] << 8),
           tc[3], tc[2], tc[19], tc[18], tc[17], tc[16]);

    s_tx_wr = (uint16_t)((s_tx_wr + 1) & (TXQ_SLOTS - 1));
    csr_wr(HBUS_TARG_WRPTR, (uint32_t)(s_tx_wr | (s_tx_qid << 16)));   /* v6.6: qid<<16 */
    printk("[AX200] TX %s (%u B) on qid %d wr->%u bc[%u]=%u\n", tag, flen, s_tx_qid,
           s_tx_wr, idx, s_tx_bc_va[idx*2] | (s_tx_bc_va[idx*2+1] << 8));
}

/* Allocate a dynamic TX queue for sta_id 0: driver owns the TFD ring + byte-count
 * table, tells the FW their addresses (SCD_QUEUE_CFG 0x11d v2), reads back the qid. */
static int
alloc_tx_queue(void)
{
    uint64_t rp = 0, bp = 0;
    s_tx_ring = dma_alloc(TXQ_SLOTS * 256, &rp);
    uint8_t *bc = dma_alloc(4096, &bp);
    if (!s_tx_ring || !bc) { printk("[AX200] txq DMA fail\n"); return -1; }
    s_tx_ring_phys = rp;
    s_tx_bc_va = bc;

    uint8_t cmd[24];
    for (int i = 0; i < 24; i++) cmd[i] = 0;
    cmd[0] = 0;                  /* sta_id */
    cmd[1] = 15;                 /* tid = IWL_MGMT_TID (mgmt frames) */
    cmd[2] = 1;                  /* flags = TX_QUEUE_CFG_ENABLE_QUEUE (le16) */
    wr_le32b(cmd + 4, 1);        /* cb_size = ilog2(16)-3 = 1 — iwlwifi's mgmt queue is
                                    size 16 (IWL_MGMT_QUEUE_SIZE); live trace showed cb_size=1 */
    wr_le32b(cmd + 8,  (uint32_t)bp);          /* byte_cnt_addr (le64) */
    wr_le32b(cmd + 12, (uint32_t)(bp >> 32));
    wr_le32b(cmd + 16, (uint32_t)rp);          /* tfdq_addr (le64) */
    wr_le32b(cmd + 20, (uint32_t)(rp >> 32));

    uint16_t before = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
    send_cmd(0x11d, cmd, 24);
    for (int t = 0; t < 30000; t++) {
        uint32_t ie = csr_rd(CSR_INT);
        if (ie & (CSR_INT_BIT_SW_ERR | CSR_INT_BIT_HW_ERR)) {
            printk("[AX200] TX_QUEUE_CFG ASSERTED CSR_INT=0x%x\n", ie);
            dump_fw_error();
            return -1;
        }
        uint16_t closed = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
        for (uint16_t i = before; i != closed; i = (uint16_t)((i + 1) & 511)) {
            const uint8_t *r = s_rx_buf_va[i & 511];
            if (r[4] == 0x1d) {                 /* SCD_QUEUE_CFG response */
                s_tx_qid = (int)(r[8] | (r[9] << 8));   /* iwl_tx_queue_cfg_rsp.queue_number */
                s_tx_wr = 0;
                printk("[AX200] *** TX queue: qid=%u resp=%x %x %x %x %x %x %x %x ***\n",
                       s_tx_qid, r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
                /* No alloc-time doorbell — iwlwifi only rings HBUS_TARG_WRPTR when
                 * it actually queues a TFD. A spurious wr=0 ring can disturb the SCD. */
                return 0;
            }
        }
        before = closed;
        busy_wait_us(10);
    }
    printk("[AX200] TX_QUEUE_CFG: no response\n");
    return -1;
}

/* Phase 4: associate to the (open) target AP. Built up command-by-command; each
 * step uses send_check so one boot reports the first command that asserts. */
#define FW_CTXT_ACTION_ADD 1
static void
do_connect(void)
{
    printk("[AX200] --- connect: target ch=%u ---\n", s_ap_channel);
    uint64_t phys;
    uint8_t c[64];
    for (int i = 0; i < 64; i++) c[i] = 0;

    /* Step 1: PHY_CONTEXT_CMD (0x08, group 0) — configure the PHY for the AP's
     * channel. iwl_phy_context_cmd (32B): id_and_color, action, ci(8), lmac_id,
     * rxchain_info, dsp_cfg_flags, reserved. */
    wr_le32b(c + 0, 0);                                     /* id_and_color: id=0, color=1 */
    wr_le32b(c + 4, FW_CTXT_ACTION_ADD);
    wr_le32b(c + 8, s_ap_channel);             /* ci.channel */
    c[12] = 1;                                 /* ci.band = PHY_BAND_24 */
    c[13] = 0;                                 /* ci.width = MODE20 */
    c[14] = 0;                                 /* ci.ctrl_pos */
    wr_le32b(c + 20, (3 << 1) | (1 << 10) | (1 << 12)); /* rxchain: valid AB, 1/1 */
    if (send_check(0x108, c, 32, "PHY_CONTEXT") != 0) return;   /* LONG_GROUP */
    printk("[AX200] PHY_CONTEXT ok\n");

    /* RLC_CONFIG_CMD (0x508, DATA_PATH_GROUP): configure the PHY's rx chains.
     * iwl_rlc_config_cmd (32B): phy_id + rlc{rx_chain_info,rsvd} + sad(16) +
     * flags + rsvd[3]. iwlwifi sends this after PHY_CONTEXT on fw-59. */
    {
        uint8_t rlc[32];
        for (int i = 0; i < 32; i++) rlc[i] = 0;
        /* phy_id @0 = 0 (the PHY context index, not id_and_color) */
        wr_le32b(rlc + 4, 0x1406);              /* rx_chain_info: valid chains A+B */
        if (send_check(0x508, rlc, 32, "RLC_CONFIG") != 0) return;
        printk("[AX200] RLC_CONFIG ok\n");
    }

    /* Step 2: MAC_CONTEXT_CMD (0x128 v5, 144B) — add our BSS_STA MAC, not yet
     * associated. iwl_mac_ctx_cmd: common hdr + ac[5] EDCA + iwl_mac_data_sta. */
    uint8_t *m = dma_alloc(256, &phys); (void)phys;
    for (int i = 0; i < 256; i++) m[i] = 0;
    wr_le32b(m + 0, 0);                    /* id_and_color: id=0 color=1 */
    wr_le32b(m + 4, FW_CTXT_ACTION_ADD);
    wr_le32b(m + 8, 5);                        /* mac_type = FW_MAC_TYPE_BSS_STA */
    /* tsf_id @12 = 0 */
    for (int i = 0; i < 6; i++) m[16 + i] = s_our_mac[i];    /* node_addr */
    for (int i = 0; i < 6; i++) m[24 + i] = s_ap_bssid[i];   /* bssid_addr */
    wr_le32b(m + 32, 0x0f);                    /* cck_rates (1/2/5.5/11) */
    wr_le32b(m + 36, 0xff);                    /* ofdm_rates */
    /* protection/preamble/short_slot @40,44,48 = 0 */
    wr_le32b(m + 52, 0x04 | 0x40);             /* filter: ACCEPT_GRP | IN_BEACON */
    /* qos_flags @56 = 0. ac[5] @60: reasonable EDCA defaults, fifo per index. */
    for (int i = 0; i < 5; i++) {
        uint8_t *a = m + 60 + i * 8;
        a[0] = 15; a[1] = 0;                   /* cw_min = 15 */
        a[2] = 0xff; a[3] = 0x03;              /* cw_max = 1023 */
        a[4] = 3;                              /* aifsn */
        a[5] = (uint8_t)(1u << (i < 4 ? i : 5)); /* fifos_mask */
    }
    /* iwl_mac_data_sta @100: is_assoc=0, bi=100, dtim_interval=100, listen=10 */
    wr_le32b(m + 116, 100);                    /* bi */
    wr_le32b(m + 124, 100);                    /* dtim_interval */
    wr_le32b(m + 132, 10);                     /* listen_interval */
    /* size = 100 (hdr+ac[5]) + 48 (union max = iwl_mac_data_p2p_sta) = 148 */
    if (send_check(0x128, m, 148, "MAC_CONTEXT") != 0) return;
    printk("[AX200] MAC_CONTEXT ok\n");

    /* Step 3: BINDING_CONTEXT_CMD (0x12b v2, 28B) — bind our MAC to the PHY.
     * iwl_binding_cmd: id_and_color, action, macs[3], phy, lmac_id. */
    for (int i = 0; i < 64; i++) c[i] = 0;
    wr_le32b(c + 0, 0);                    /* binding id=0 color=1 */
    wr_le32b(c + 4, FW_CTXT_ACTION_ADD);
    wr_le32b(c + 8,  0);                   /* macs[0] = our MAC id_and_color */
    wr_le32b(c + 12, 0xffffffff);              /* macs[1] = invalid */
    wr_le32b(c + 16, 0xffffffff);              /* macs[2] = invalid */
    wr_le32b(c + 20, 0);                   /* phy = PHY id_and_color */
    /* lmac_id @24 = 0 */
    if (send_check(0x12b, c, 28, "BINDING") != 0) return;
    printk("[AX200] BINDING ok — MAC bound to PHY\n");

    /* MAC_PM_POWER_TABLE (0x1a9, LONG_GROUP): disable power save so the station
     * stays awake to service its TX queue. iwl_mac_power_cmd = 40B; flags=0 = no
     * power-save. iwlwifi sends this before the first TX. */
    {
        uint8_t pm[40];
        for (int i = 0; i < 40; i++) pm[i] = 0;
        wr_le32b(pm + 0, 0);             /* id_and_color (MAC 0) */
        if (send_check(0x1a9, pm, 40, "MAC_PM") != 0) return;
        printk("[AX200] MAC_PM ok — power-save off\n");
    }

    /* MAC_CONTEXT MODIFY: iwlwifi sends MAC_CONTEXT twice — add, then modify after
     * binding — to activate the MAC on the bound PHY. Re-send m with action=MODIFY. */
    wr_le32b(m + 4, 2 /* FW_CTXT_ACTION_MODIFY */);
    if (send_check(0x128, m, 148, "MAC_CTXT_MODIFY") != 0) return;
    printk("[AX200] MAC_CONTEXT MODIFY ok\n");

    /* Step 4: ADD_STA (0x118 v12, 48B) — add the AP as our peer station.
     * iwl_mvm_add_sta_cmd: add_modify, mac_id_n_color, addr, sta_id, flags,
     * station_type. gen2 allocates TX queues separately (tfd_queue_msk=0). */
    for (int i = 0; i < 64; i++) c[i] = 0;
    c[0] = 0;                                  /* add_modify = STA_MODE_ADD */
    wr_le32b(c + 4, 0);                    /* mac_id_n_color */
    for (int i = 0; i < 6; i++) c[8 + i] = s_ap_bssid[i];   /* addr = AP */
    c[16] = 0;                                 /* sta_id = 0 */
    /* station_flags @20 = 0 (20MHz SISO); station_type @35 = IWL_STA_LINK(0) */
    if (send_check(0x118, c, 48, "ADD_STA") != 0) return;
    printk("[AX200] ADD_STA ok — AP peer added\n");

    /* Step 4b: TLC_MNG_CONFIG_CMD (0x50f, DATA_PATH_GROUP) — the station's
     * rate-scaling config. THE MISSING PIECE: the FW won't service the station's
     * TX queue until this is set (found via iwlwifi fw-59 ftrace: 0x05.0x0f is
     * sent right after ADD_STA, before the queue + first TX). iwl_tlc_config_cmd
     * v3/v4 are both 36B with these fields at identical offsets. */
    {
        uint8_t tlc[36];
        for (int i = 0; i < 36; i++) tlc[i] = 0;
        /* sta_id@0=0; max_ch_width@4=20MHz(0); mode@5=CCK/NON_HT(0) */
        tlc[6] = 1;                          /* chains = IWL_TLC_MNG_CHAIN_A_MSK */
        tlc[10] = 0xff; tlc[11] = 0x0f;      /* non_ht_rates = 0x0fff (all legacy) */
        /* fw-59 uses the older TLC struct: ht_rates[2][2] -> 28 bytes, not 36. */
        if (send_check(0x50f, tlc, 28, "TLC_CONFIG") != 0) return;
        printk("[AX200] TLC_CONFIG ok — station rate table set\n");
    }

    /* Step 5: session protection — reserve on-channel airtime for the auth/assoc
     * exchange (a non-associated station isn't otherwise kept on-channel).
     * SESSION_PROTECTION_CMD (0x305, MAC_CONF_GROUP): action=ADD, conf=ASSOC. */
    {
        uint8_t sp[24];
        for (int i = 0; i < 24; i++) sp[i] = 0;
        wr_le32b(sp + 0, 0);              /* id_and_color */
        wr_le32b(sp + 4, FW_CTXT_ACTION_ADD); /* action */
        wr_le32b(sp + 8, 0);                  /* conf_id = SESSION_PROTECT_CONF_ASSOC */
        wr_le32b(sp + 12, 1000);              /* duration_tu */
        wr_le32b(sp + 16, 1);                 /* repetition_count */
        /* Capture the RX read index BEFORE sending: the FW delivers the
         * session-prot START notif (start=1) within ~us of the command, i.e.
         * DURING send_check's response wait. Scanning from here catches it;
         * resetting s_rx_read to "now" afterwards would skip start=1 and only
         * see the later start=0 (session ENDED) notif — leaving us off-channel. */
        uint16_t pre_sp = s_rx_read;
        if (send_check(0x305, sp, 24, "SESSION_PROT") != 0) return;
        s_rx_read = pre_sp;
        for (int t = 0; t < 150000; t++) {    /* wait for the START notif (0xFB, start=1) */
            uint16_t closed = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
            int got = 0;
            while (s_rx_read != closed) {
                const uint8_t *r = s_rx_buf_va[s_rx_read & 511];
                s_rx_read++;
                /* iwl_mvm_session_prot_notif: status[12], start[16], conf[20]. */
                if (r[4] == 0xfb && r[16] == 1) {
                    printk("[AX200] session-prot STARTED (status=%u conf=%u) — on-channel\n",
                           r[12], r[20]);
                    got = 1;
                }
            }
            if (got) break;
            busy_wait_us(10);
        }
    }

    /* Step 5b: allocate the data TX queue AFTER session protection (iwlwifi order:
     * the queue is allocated lazily right before the first frame, on-channel). */
    if (alloc_tx_queue() != 0) return;
    printk("[AX200] TX queue ready\n");

    /* Step 6: send an open-system 802.11 auth request and watch for the AP's
     * reply (a mgmt frame addressed to our MAC). */
    uint8_t f[64];
    for (int i = 0; i < 64; i++) f[i] = 0;
    f[0] = 0xb0;                               /* FC: mgmt, subtype auth */
    for (int i = 0; i < 6; i++) { f[4+i] = s_ap_bssid[i]; f[10+i] = s_our_mac[i]; f[16+i] = s_ap_bssid[i]; }
    f[24] = 0; f[25] = 0;                      /* auth alg = open system */
    f[26] = 1; f[27] = 0;                      /* auth transaction seq = 1 */
    f[28] = 0; f[29] = 0;                      /* status = 0 */

    s_rx_read = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
    send_frame(f, 30, 0, "auth-v1");            /* rate_n_flags=0: FW picks from TLC table */

    uint16_t rb0 = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
    printk("[AX200] watch start rb_stts=%u qid=%d tx_wr=%u\n", rb0, s_tx_qid, s_tx_wr);
    for (int t = 0; t < 400000; t++) {         /* ~4s */
        if (t == 150000) send_frame(f, 30, 0x4000, "auth-v2");  /* v2 rate format */
        if (t == 399999)
            printk("[AX200] watch end rb_stts=%u\n", *(volatile uint16_t *)s_rb_stts & 0x0FFFu);
        uint32_t ie = csr_rd(CSR_INT);
        if (ie & (CSR_INT_BIT_SW_ERR | CSR_INT_BIT_HW_ERR)) {
            printk("[AX200] auth TX ASSERTED CSR_INT=0x%x\n", ie); dump_fw_error(); return;
        }
        uint16_t closed = *(volatile uint16_t *)s_rb_stts & 0x0FFFu;
        while (s_rx_read != closed) {
            const uint8_t *r = s_rx_buf_va[s_rx_read & 511];
            uint8_t c = r[4], g = r[5];
            s_rx_read++;
            printk("[AX200] ntf cmd=0x%x/g%u data=%x %x %x %x %x %x %x %x\n",
                   c, g, r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
            if (c == 0x1c)                     /* TX response: status in the payload */
                printk("[AX200]   TX-RESP status=0x%x %x %x %x\n", r[8], r[9], r[10], r[11]);
            for (int o = 8; o < 300; o++) {    /* find a frame addressed to us */
                if (r[o]==s_our_mac[0] && r[o+1]==s_our_mac[1] && r[o+2]==s_our_mac[2] &&
                    r[o+3]==s_our_mac[3] && r[o+4]==s_our_mac[4] && r[o+5]==s_our_mac[5]) {
                    printk("[AX200] *** RX frame to us *** cmd=0x%x @+%d FC=0x%x body=%x %x %x %x %x %x\n",
                           c, o, r[o-4], r[o+20], r[o+21], r[o+22], r[o+23], r[o+24], r[o+25]);
                    break;
                }
            }
        }
        busy_wait_us(10);
    }
    printk("[AX200] auth: done watching\n");
}

static int
load_firmware_and_kick(uint32_t hw_rev)
{
    uint64_t ci_phys = 0, free_phys = 0, used_phys = 0, stts_phys = 0, cmd_phys = 0;
    struct context_info *ci = dma_alloc(sizeof(*ci), &ci_phys);
    uint64_t *free_rbd = dma_alloc(NRBDS * 8, &free_phys);
    void     *used_bd  = dma_alloc(NRBDS * 32, &used_phys);   /* iwl_rx_completion_desc = 32B */
    void     *rb_stts  = dma_alloc(4096, &stts_phys);
    void     *cmd_ring = dma_alloc(32 * 256, &cmd_phys);      /* 32 × iwl_tfh_tfd(256B) */
    if (!ci || !free_rbd || !used_bd || !rb_stts || !cmd_ring) {
        printk("[AX200] FAIL: DMA alloc for context-info/queues\n");
        return -1;
    }
    s_rb_stts = rb_stts;
    s_used_bd = used_bd;
    s_cmd_ring = cmd_ring;
    s_cmd_wr = 0;

    /* Populate the RX free-buffer ring: entry = buffer_phys | vid (vid in the
     * low bits, buffers are 4K-aligned so they don't collide). Keep each
     * buffer's KVA so we can read notifications the FW writes into them. */
    for (int i = 0; i < NRBDS; i++) {
        uint64_t bp;
        void *bva = dma_alloc(4096, &bp);
        if (!bva) {
            printk("[AX200] FAIL: RX buffer alloc\n");
            return -1;
        }
        s_rx_buf_va[i] = bva;
        free_rbd[i] = bp | (uint64_t)(i + 1);
    }

    /* NB: the AX200's context-info firmware configures the RFH itself from
     * context_info.rbd_cfg (below) — the driver must NOT run iwl_pcie_rx_mq_hw_init
     * here; doing so makes the UMAC assert before ALIVE. We only publish the free
     * buffers via the RX doorbell, and that is done after ALIVE. */

    /* Firmware sections → DRAM map (indexing mirrors iwl_pcie_init_fw_sec:
     * lmac=sec[0..L-1], umac=sec[L+1..L+U], paging=sec[L+U+2..]). */
    for (int i = 0; i < s_lmac_cnt; i++) {
        uint64_t p = load_sec(i);
        if (!p) goto oom;
        ci->dram.lmac_img[i] = p;
    }
    for (int i = 0; i < s_umac_cnt; i++) {
        uint64_t p = load_sec(s_lmac_cnt + 1 + i);
        if (!p) goto oom;
        ci->dram.umac_img[i] = p;
    }
    for (int i = 0; i < s_paging_cnt; i++) {
        uint64_t p = load_sec(s_lmac_cnt + s_umac_cnt + 2 + i);
        if (!p) goto oom;
        ci->dram.virtual_img[i] = p;
    }

    /* Control fields. cb_size=ilog2(NRBDS)=9; rb_size=4K; long TFD format. */
    ci->ver_mac_id = (uint16_t)hw_rev;
    ci->ver_size   = (uint16_t)(sizeof(*ci) / 4);
    ci->control_flags = CTXT_INFO_TFD_FORMAT_LONG | (9u << 4) |
                        ((uint32_t)CTXT_INFO_RB_SIZE_4K << 9);
    ci->free_rbd_addr  = free_phys;
    ci->used_rbd_addr  = used_phys;
    ci->status_wr_ptr  = stts_phys;
    ci->cmd_queue_addr = cmd_phys;
    ci->cmd_queue_size = 2;    /* TFD_QUEUE_CB_SIZE(32) = ilog2(32)-3 */

    /* Enable ALIVE + FH-RX causes and clear stale status (we poll CSR_INT). */
    csr_wr(CSR_INT_MASK, CSR_INT_BIT_ALIVE | CSR_INT_BIT_FH_RX);
    csr_wr(CSR_INT, 0xFFFFFFFFu);

    /* Kick: point the chip at the context-info block, then start the CPU. */
    csr_wr(CSR_CTXT_INFO_BA,     (uint32_t)(ci_phys & 0xFFFFFFFFu));
    csr_wr(CSR_CTXT_INFO_BA + 4, (uint32_t)(ci_phys >> 32));
    wr_prph(UREG_CPU_INIT_RUN, 1);

    printk("[AX200] firmware loaded, self-load kicked (ci@0x%x); waiting for ALIVE...\n",
           (unsigned)ci_phys);

    /* The FW DMA-loads the ucode then raises ALIVE (CSR_INT bit 0). */
    for (uint32_t t = 0; t < 2000000; t += 200) {
        uint32_t inta = csr_rd(CSR_INT);
        if (inta & CSR_INT_BIT_ALIVE) {
            printk("[AX200] *** FW ALIVE *** CSR_INT=0x%x — firmware is running!\n", inta);
            csr_wr(CSR_INT, inta);   /* ACK */
            /* Theory: the FW self-configured the RFH from context_info.rbd_cfg;
             * just publish the free buffers via the RX doorbell and see if the
             * ALIVE notification lands. */
            csr_wr(RFH_Q0_FRBDCB_WIDX_TRG, (uint32_t)(NRBDS - 8));
            process_rx_alive();

            /* Phase 3c: init sequence → INIT_COMPLETE, then 3d: scan. */
            if (init_after_alive() == 0) {
                do_scan();
                if (s_ap_found)
                    do_connect();
            }
            return 0;
        }
        if (inta & (CSR_INT_BIT_SW_ERR | CSR_INT_BIT_HW_ERR)) {
            csr_set(CSR_GP_CNTRL, GP_CNTRL_MAC_ACCESS_REQ);
            csr_poll(CSR_GP_CNTRL, GP_CNTRL_MAC_CLOCK_READY, GP_CNTRL_MAC_CLOCK_READY, 15000);
            printk("[AX200] FW error CSR_INT=0x%x SB1=0x%x SB2=0x%x UMAG1=0x%x UMAG2=0x%x umacPC=0x%x lmacPC=0x%x\n",
                   inta, rd_prph(SB_CPU_1_STATUS), rd_prph(SB_CPU_2_STATUS),
                   rd_prph(UMAG_SB_CPU_1_STATUS), rd_prph(UMAG_SB_CPU_2_STATUS),
                   rd_prph(UREG_UMAC_CURRENT_PC), rd_prph(UREG_LMAC1_CURRENT_PC));
            return -1;
        }
        busy_wait_us(200);
    }
    printk("[AX200] no ALIVE (CSR_INT=0x%x GP_CNTRL=0x%x) — load path needs work\n",
           csr_rd(CSR_INT), csr_rd(CSR_GP_CNTRL));
    return -1;

oom:
    printk("[AX200] FAIL: DMA alloc for firmware sections\n");
    return -1;
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

    /* 4b. SW-reset the device core. A bare PCI FLR (e.g. VFIO on VM restart)
     * resets the bus interface but NOT the WiFi microcontroller, so after a
     * previous firmware run the MAC clock is stopped and CSRs read poison
     * (0xA5A5A5A5). CSR_RESET.SW_RESET restarts the core (iwl_trans_sw_reset). */
    csr_wr(CSR_RESET, CSR_RESET_SW_RESET);
    busy_wait_us(6000);
    csr_poll(CSR_RESET, 0, CSR_RESET_SW_RESET, 20000);   /* bit self-clears */

    /* 5. First register reads. CSR_HW_REV is always-on, so a valid (non-0xFF..)
     * value proves the MMIO window is live and gives us the silicon stepping. */
    uint32_t hw_rev = csr_rd(CSR_HW_REV);
    if (hw_rev == 0xFFFFFFFFu || hw_rev == 0xA5A5A5A5u) {
        printk("[AX200] FAIL: CSR read 0x%x (BAR0 wrong / core not clocked)\n", hw_rev);
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
    /* Phase 2 step C: build the context-info block + kick FW self-load → ALIVE. */
    load_firmware_and_kick(hw_rev);
}
