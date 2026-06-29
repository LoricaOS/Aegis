/* fw_cfg.c — QEMU/Proxmox firmware-configuration channel (x86 I/O-port interface).
 *
 * fw_cfg is the agentless host→guest config channel exposed by QEMU (and thus
 * Proxmox/libvirt). The host attaches named blobs with `-fw_cfg name=opt/...`;
 * the guest reads them with no network and no guest agent. We use it to apply
 * an optional host-injected hostname (opt/aegis.hostname), the same pattern
 * cloud platforms use to name a fresh VM.
 *
 * Interface (xHCI-free, pure port I/O — present on every QEMU x86 machine):
 *   selector register  0x510  16-bit write, little-endian
 *   data register      0x511   8-bit read, byte stream (endianness preserved)
 * Multi-byte fw_cfg DATA fields (directory count, file size/select) are
 * BIG-ENDIAN; only the selector port write is little-endian.
 *
 * Verify: `-fw_cfg name=opt/aegis.hostname,string=demohost` → boot log shows
 * `[FWCFG] hostname set from host: demohost` and `uname -n` reports it.
 */

#include <stdint.h>
#include <stddef.h>
#include "arch.h"
#include "sys_impl.h"   /* hostname_set */

void printk(const char *fmt, ...);

#define FW_CFG_PORT_SEL  0x510u
#define FW_CFG_PORT_DATA 0x511u

#define FW_CFG_SIGNATURE 0x0000u   /* read 4 bytes → "QEMU" */
#define FW_CFG_FILE_DIR  0x0019u   /* directory of named files */

#define FW_CFG_MAX_FILES 256u      /* sanity cap on the directory walk */

static int s_present = 0;

/* Select a key, then stream `len` bytes from the data port into buf. */
static void
fw_cfg_select(uint16_t key)
{
    outw(FW_CFG_PORT_SEL, key);
}

static void
fw_cfg_read_bytes(void *buf, uint32_t len)
{
    uint8_t *p = (uint8_t *)buf;
    uint32_t i;
    for (i = 0; i < len; i++)
        p[i] = inb(FW_CFG_PORT_DATA);
}

/* Skip `len` bytes of the current selection's data stream. */
static void
fw_cfg_skip(uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i++)
        (void)inb(FW_CFG_PORT_DATA);
}

static uint32_t
be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t
be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static int
streq(const char *a, const char *b)
{
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* fw_cfg_find — walk the file directory for `name`; on match store the file's
 * selector key and size. Returns 1 if found, 0 otherwise. Leaves the data
 * stream mid-directory (caller re-selects before reading the file). */
static int
fw_cfg_find(const char *name, uint16_t *out_sel, uint32_t *out_size)
{
    uint8_t hdr[4];
    fw_cfg_select(FW_CFG_FILE_DIR);
    fw_cfg_read_bytes(hdr, 4);
    uint32_t count = be32(hdr);
    if (count > FW_CFG_MAX_FILES) count = FW_CFG_MAX_FILES;

    uint32_t i;
    for (i = 0; i < count; i++) {
        /* FWCfgFile: size(BE32) select(BE16) reserved(16) name[56] = 64 bytes */
        uint8_t ent[64];
        fw_cfg_read_bytes(ent, 64);
        ent[63] = '\0';                  /* defensive: bound the name */
        if (streq((const char *)&ent[8], name)) {
            *out_size = be32(&ent[0]);
            *out_sel  = be16(&ent[4]);
            /* Drain the remaining directory entries so the device is left in a
             * clean state for the next selection (not strictly required, but
             * tidy). */
            uint32_t rest = count - i - 1u;
            fw_cfg_skip(rest * 64u);
            return 1;
        }
    }
    return 0;
}

/* fw_cfg_read_file — public: read a named blob into buf (up to maxlen).
 * Returns bytes read (>=0), or -1 if fw_cfg is absent or the file is not found. */
int
fw_cfg_read_file(const char *name, void *buf, uint32_t maxlen)
{
    if (!s_present) return -1;
    uint16_t sel; uint32_t size;
    if (!fw_cfg_find(name, &sel, &size))
        return -1;
    uint32_t n = size < maxlen ? size : maxlen;
    fw_cfg_select(sel);
    fw_cfg_read_bytes(buf, n);
    /* Skip any unread tail so the device stream is consumed cleanly. */
    if (size > n) fw_cfg_skip(size - n);
    return (int)n;
}

/* fw_cfg_init — probe the signature and apply host-injected config.
 * Silent when fw_cfg is absent or no recognised opt blob is present, so the
 * boot oracle (which runs on a plain machine with no -fw_cfg blobs) is
 * unperturbed. */
void
fw_cfg_init(void)
{
    char sig[4];
    fw_cfg_select(FW_CFG_SIGNATURE);
    fw_cfg_read_bytes(sig, 4);
    if (sig[0] != 'Q' || sig[1] != 'E' || sig[2] != 'M' || sig[3] != 'U')
        return;                          /* not present → silent */
    s_present = 1;

    /* Optional host-injected hostname (agentless naming, cloud-init style). */
    char hn[65];
    int n = fw_cfg_read_file("opt/aegis.hostname", hn, sizeof(hn) - 1);
    if (n > 0) {
        /* Trim a trailing newline the host may append. */
        while (n > 0 && (hn[n - 1] == '\n' || hn[n - 1] == '\r'))
            n--;
        if (n > 0) {
            hn[n] = '\0';
            hostname_set(hn, (uint32_t)n);
            printk("[FWCFG] hostname set from host: %s\n", hn);
        }
    }
}
