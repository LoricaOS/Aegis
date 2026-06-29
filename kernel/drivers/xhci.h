/* xhci.h — xHCI USB host controller driver
 *
 * xHCI 1.2 compliant. Supports device enumeration and interrupt IN
 * transfers for HID boot-protocol keyboards. Polling-based (no MSI).
 */
#ifndef XHCI_H
#define XHCI_H

#include <stdint.h>

/* Capability Registers (BAR0 base) */
typedef struct __attribute__((packed)) {
    uint8_t  caplength;       /* 0x00: Capability Register Length */
    uint8_t  reserved;
    uint16_t hciversion;      /* 0x02: Interface Version Number */
    uint32_t hcsparams1;      /* 0x04: Structural Parameters 1 */
    uint32_t hcsparams2;      /* 0x08: Structural Parameters 2 */
    uint32_t hcsparams3;      /* 0x0C: Structural Parameters 3 */
    uint32_t hccparams1;      /* 0x10: Capability Parameters 1 */
    uint32_t dboff;           /* 0x14: Doorbell Offset */
    uint32_t rtsoff;          /* 0x18: Runtime Register Space Offset */
    uint32_t hccparams2;      /* 0x1C: Capability Parameters 2 */
} xhci_cap_regs_t;

/* Operational Registers (BAR0 + CAPLENGTH) */
typedef struct __attribute__((packed)) {
    uint32_t usbcmd;          /* 0x00: USB Command */
    uint32_t usbsts;          /* 0x04: USB Status */
    uint32_t pagesize;        /* 0x08: Page Size */
    uint8_t  reserved1[8];
    uint32_t dnctrl;          /* 0x14: Device Notification Control */
    uint64_t crcr;            /* 0x18: Command Ring Control */
    uint8_t  reserved2[16];
    uint64_t dcbaap;          /* 0x30: Device Context Base Address Array Pointer */
    uint32_t config;          /* 0x38: Configure */
} xhci_op_regs_t;

/* Port Status and Control Register */
typedef struct __attribute__((packed)) {
    uint32_t portsc;          /* Port Status and Control */
    uint32_t portpmsc;        /* Port Power Management Status and Control */
    uint32_t portli;          /* Port Link Info */
    uint32_t porthlpmc;       /* Port Hardware LPM Control */
} xhci_port_regs_t;

/* Transfer Request Block (TRB) — 16 bytes */
typedef struct __attribute__((packed)) {
    uint64_t param;           /* Parameter (address or inline data) */
    uint32_t status;          /* Status / Transfer Length / Interrupter Target */
    uint32_t control;         /* Cycle bit [0], Type [15:10], flags */
} xhci_trb_t;

/* TRB Types */
#define XHCI_TRB_NORMAL            1
#define XHCI_TRB_SETUP             2
#define XHCI_TRB_DATA              3
#define XHCI_TRB_STATUS            4
#define XHCI_TRB_LINK              6
#define XHCI_TRB_ENABLE_SLOT       9
#define XHCI_TRB_ADDRESS_DEVICE    11
#define XHCI_TRB_CONFIGURE_EP      12
#define XHCI_TRB_EVALUATE_CTX      13
#define XHCI_TRB_NOOP              23
#define XHCI_TRB_TRANSFER_EVENT    32
#define XHCI_TRB_CMD_COMPLETION    33
#define XHCI_TRB_PORT_STATUS_CHG   34

/* TRB additional types */
#define XHCI_TRB_DISABLE_SLOT      10

/* USBCMD bits */
#define XHCI_CMD_RS                (1u << 0)
#define XHCI_CMD_HCRST             (1u << 1)
#define XHCI_CMD_INTE              (1u << 2)

/* USBSTS bits */
#define XHCI_STS_HCH               (1u << 0)   /* Host Controller Halted */
#define XHCI_STS_HSE               (1u << 2)   /* Host System Error */
#define XHCI_STS_EINT              (1u << 3)   /* Event Interrupt */
#define XHCI_STS_CNR               (1u << 11)  /* Controller Not Ready */
#define XHCI_STS_HCE               (1u << 12)  /* Host Controller Error */

/* PORTSC bits */
#define XHCI_PORTSC_CCS            (1u << 0)
#define XHCI_PORTSC_PED            (1u << 1)
#define XHCI_PORTSC_PR             (1u << 4)
#define XHCI_PORTSC_PP             (1u << 9)   /* Port Power */
#define XHCI_PORTSC_CSC            (1u << 17)  /* Connect Status Change (RW1C) */
#define XHCI_PORTSC_PRC            (1u << 21)

/* USB device types for HID boot protocol */
#define USB_DEV_NONE   0u
#define USB_DEV_KBD    1u
#define USB_DEV_MOUSE  2u

/* Command Ring sizes */
#define XHCI_CMD_RING_SIZE         64
#define XHCI_EVT_RING_SIZE         64
#define XHCI_TRANSFER_RING_SIZE    64

/* Initialize xHCI controller. Safe to call when no xHCI device present.
 * Prints [XHCI] OK or skip message. */
void xhci_init(void);

/* Poll event ring for completed transfers. Called from PIT handler at 100Hz. */
void xhci_poll(void);

/* Schedule an interrupt IN transfer for a device slot + endpoint.
 * Used by USB HID driver to receive keyboard reports. */
int xhci_schedule_interrupt_in(uint8_t slot_id, uint8_t ep_id,
                                uint64_t buf_phys, uint32_t buf_len);

/* USB-ethernet (ASIX AX88179) live diagnostics, surfaced via /proc/usbnet.
 * The driver is still in hardware bring-up — it detects the device and arms
 * bulk RX but does not yet register a netdev, so these counters are how we tell
 * (on a serial-less laptop) whether the adapter was found, the link came up,
 * and frames are actually arriving from the wire. */
typedef struct {
    int      present;        /* AX88179 detected on a port */
    int      configured;     /* bulk endpoints set up + RX armed */
    uint8_t  mac[6];
    uint8_t  bulk_in_dci;
    uint8_t  bulk_out_dci;
    uint16_t bulk_in_mps;
    uint16_t bulk_out_mps;
    uint8_t  link_up;        /* link detected at the last poll */
    uint8_t  link_reset_done;/* link_reset ran (RX enabled for the speed) */
    uint16_t physr;          /* last vendor PHY status reg (0x11) */
    uint16_t bmsr;           /* last standard MII BMSR (1) */
    uint16_t medium_rb;      /* MEDIUM_STATUS_MODE read-back (RECEIVE_EN=0x100) */
    uint16_t rxctl_rb;       /* RX_CTL read-back (START=0x80) */
    uint8_t  plink_rb;       /* PHYSICAL_LINK_STATUS read-back (SS=0x04 HS=0x02) */
    uint8_t  genstat_rb;     /* GENERAL_STATUS (AX_SECLD=0x04) */
    uint16_t bcd_device;     /* bcdDevice (>=0x0200 = AX88179A, FW_MODE forced) */
    uint8_t  phy_cc;         /* MDIO-fail completion code (4=txn err,6=stall,0xFF=timeout) */
    uint8_t  int_dci;        /* interrupt-IN endpoint DCI (0 = none found) */
    uint8_t  int_armed;      /* interrupt-IN endpoint configured + armed */
    uint8_t  link_up_intr;   /* link state from the interrupt EP (AX_INT_PPLS_LINK) */
    uint32_t int_count;      /* interrupt-IN completions seen */
    uint32_t intdata1;       /* last link report dword 0 (link = bit 16) */
    uint32_t intdata2;       /* last link report dword 1 */
    uint16_t det_speed;      /* MDIO-free detected speed (0=none/1000/100 Mb/s) */
    uint16_t med_gig_rb;     /* MEDIUM readback after gigabit probe (EN_125MHZ=0x08 sticky) */
    uint16_t med_100_rb;     /* MEDIUM readback after 100M probe (PS=0x200 sticky) */
    uint8_t  bulk_in_addr;   /* bulk IN endpoint address (0x8N) */
    uint8_t  bulk_out_addr;  /* bulk OUT endpoint address (0x0N) */
    uint8_t  int_addr;       /* interrupt IN endpoint address (0x8N) */
    uint8_t  bulk_in_burst;  /* SS Companion bMaxBurst for bulk IN (0 = not parsed) */
    uint32_t rx_count;       /* bulk-IN completions seen */
    uint32_t rx_frames;      /* Ethernet frames delivered to the stack */
    uint32_t rx_bytes;       /* total bulk-IN bytes */
    uint32_t last_rx_len;    /* length of the most recent bulk-IN */
    uint32_t tx_count;       /* bulk-OUT frames sent */
    uint8_t  registered;     /* netdev registered */
    char     ifname[8];      /* netdev name (eth0/eth1) */
    /* Last non-HID USB device the driver probed, claimed or not. Lets us
     * identify an unsupported adapter (e.g. an RTL8153 dongle, vid 0x0BDA)
     * by its VID/PID instead of guessing. saw_device=0 => nothing enumerated. */
    uint8_t  saw_device;
    uint16_t last_vid;
    uint16_t last_pid;
} xhci_usbnet_diag_t;

/* Fill *out with the current USB-ethernet state (present=0 if none found).
 * Safe to call from syscall/procfs context. */
void xhci_usbnet_diag(xhci_usbnet_diag_t *out);

/* xHCI host-controller discovery diagnostics — for /proc/usbnet. Aegis adopts
 * exactly ONE controller at boot (the first with a connected device), so on a
 * multi-controller laptop a USB-C adapter on a different controller is never
 * scanned. This exposes the full controller list + which was adopted + the
 * adopted controller's live per-port connect state, to diagnose exactly that. */
#define XHCI_DIAG_MAX_PORTS 64
typedef struct {
    uint8_t  total_controllers;   /* xHCI PCI functions present */
    int8_t   adopted_index;       /* index into ctrl[] adopted, -1 = none */
    uint8_t  count;               /* controllers recorded in ctrl[] */
    struct {
        uint8_t  bus, dev, fn;
        uint16_t vendor, device;
        int8_t   result;          /* 1=adopted, 0=empty(no connect), -1=init fail */
    } ctrl[8];
    uint8_t  adopted_max_ports;
    uint32_t port[XHCI_DIAG_MAX_PORTS + 1];       /* live PORTSC of adopted ctrl [1..max] */
    uint8_t  enum_stage[XHCI_DIAG_MAX_PORTS + 1]; /* how far enumeration got per port */
    uint8_t  enum_cc[XHCI_DIAG_MAX_PORTS + 1];    /* cmd completion code at a failed stage */
    uint8_t  is_usb3[XHCI_DIAG_MAX_PORTS + 1];    /* 1 = USB3 (SuperSpeed) protocol port */
    uint32_t enum_usbsts[XHCI_DIAG_MAX_PORTS + 1];/* USBSTS at a failed enum stage */
} xhci_host_diag_t;
void xhci_host_diag(xhci_host_diag_t *out);

#endif /* XHCI_H */
