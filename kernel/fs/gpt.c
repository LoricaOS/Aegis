#include "gpt.h"
#include "blkdev.h"
#include "printk.h"
#include <stdint.h>
#include <stddef.h>

#define GPT_MAX_PARTS 7   /* BLKDEV_MAX=8 minus 1 slot for the parent disk */

/* ── CRC32 (polynomial 0xEDB88320, reflected) ─────────────────────────────
 * Standard CRC32 used by GPT tools (sgdisk, gdisk, parted).
 * Table is computed on first call and cached in s_crc_table[]. */

static uint32_t s_crc_table[256];
static int      s_crc_ready = 0;

static void crc32_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (c & 1 ? 0xEDB88320U : 0U);
        s_crc_table[i] = c;
    }
    s_crc_ready = 1;
}

static uint32_t crc32_compute(const uint8_t *buf, uint32_t len)
{
    if (!s_crc_ready) crc32_init();
    uint32_t crc = 0xFFFFFFFFU;
    for (uint32_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ s_crc_table[(crc ^ buf[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFU;
}

/* ── GPT on-disk types (packed, no padding) ───────────────────────────────
 * Structs are used only as overlays on 512-byte sector buffers; they are
 * never stack-allocated directly (header is copied with memcpy). */

typedef struct __attribute__((packed)) {
    uint8_t  signature[8];          /* "EFI PART" */
    uint32_t revision;              /* 0x00010000 */
    uint32_t header_size;           /* typically 92 */
    uint32_t header_crc32;          /* CRC32 with this field zeroed */
    uint32_t reserved;
    uint64_t my_lba;                /* LBA of this header */
    uint64_t alternate_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t  disk_guid[16];
    uint64_t partition_entry_lba;   /* LBA of partition array */
    uint32_t num_partition_entries;
    uint32_t partition_entry_size;
    uint32_t partition_array_crc32;
} gpt_header_t;

typedef struct __attribute__((packed)) {
    uint8_t  type_guid[16];   /* all-zeros = unused entry */
    uint8_t  part_guid[16];
    uint64_t start_lba;
    uint64_t end_lba;         /* inclusive */
    uint64_t attributes;
    uint16_t name[36];        /* UTF-16LE, ignored */
} gpt_entry_t;

/* ── Partition blkdev callbacks ───────────────────────────────────────────
 * Each partition blkdev delegates to its parent, adding lba_offset.
 * lba_offset is stored in gpt_part_priv_t (not blkdev_t.lba_offset)
 * so that the blkdev interface stays zero-based for callers. */

typedef struct {
    blkdev_t *parent;
    uint64_t  lba_offset;  /* partition start LBA on parent */
} gpt_part_priv_t;

/* MUST be static: blkdev_register stores a pointer, not a copy.
 * Local variables would produce dangling pointers after gpt_scan() returns. */
static gpt_part_priv_t s_parts[GPT_MAX_PARTS];
static blkdev_t        s_devs[GPT_MAX_PARTS];

/* Aegis partition type GUID prefix (first 8 bytes).
 * Full GUID: A3618F24-0C76-4B3D-{role}-000000000000
 * Only partitions with this prefix are registered as blkdevs.
 * See CLAUDE.md "Aegis GPT Partition Type GUIDs" for the full scheme.
 *
 * IMPORTANT: GPT stores GUIDs in mixed-endian format per UEFI spec.
 * UUID A3618F24-0C76-4B3D is stored on disk as:
 *   24 8F 61 A3  76 0C  3D 4B
 * (first 3 groups little-endian, last 2 big-endian) */
static const uint8_t k_aegis_guid_prefix[8] = {
    0x24, 0x8F, 0x61, 0xA3, 0x76, 0x0C, 0x3D, 0x4B
};

/*
 * 512e emulation: partition devices always present 512-byte logical sectors.
 * This keeps ext2_cache and all other kernel consumers unchanged.
 *
 * lba/count in the callbacks are in 512B logical units.
 * p->lba_offset is in parent-native LBAs.
 *
 * For 4K-native drives, callers (ext2_cache) issue reads like lba=2, count=2
 * (two 512B sectors = 1024 bytes) which do NOT align to a 4K boundary.  We
 * use a static bounce buffer (one native sector = 4096 bytes max) to handle
 * sub-block alignment.  At most one native sector is ever needed per call
 * because ext2 block sizes (1024/2048/4096B) are always ≤ native block size
 * (512B or 4096B), so a single native sector contains the full request.
 */
static uint8_t s_part_bounce[4096];  /* sized for one 4K native sector */

static int gpt_part_read(blkdev_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    gpt_part_priv_t *p = (gpt_part_priv_t *)dev->priv;
    if (lba + count > dev->block_count)
        return -1;
    uint32_t native_bs = p->parent->block_size;
    if (native_bs == 512)
        return p->parent->read(p->parent, lba + p->lba_offset, count, buf);

    /* 512B → native translation with bounce for sub-block alignment */
    uint64_t byte_start  = lba * 512ULL;
    uint64_t byte_count  = (uint64_t)count * 512ULL;
    uint64_t nat_lba     = byte_start / native_bs;
    uint32_t sub_off     = (uint32_t)(byte_start % native_bs);
    /* One native sector covers the entire request (ext2 block ≤ native_bs) */
    if (p->parent->read(p->parent, p->lba_offset + nat_lba, 1, s_part_bounce) < 0)
        return -1;
    __builtin_memcpy(buf, s_part_bounce + sub_off, byte_count);
    return 0;
}

static int gpt_part_write(blkdev_t *dev, uint64_t lba, uint32_t count,
                          const void *buf)
{
    gpt_part_priv_t *p = (gpt_part_priv_t *)dev->priv;
    if (lba + count > dev->block_count)
        return -1;
    uint32_t native_bs = p->parent->block_size;
    if (native_bs == 512)
        return p->parent->write(p->parent, lba + p->lba_offset, count, buf);

    uint64_t byte_start = lba * 512ULL;
    uint64_t byte_count = (uint64_t)count * 512ULL;
    uint64_t nat_lba    = byte_start / native_bs;
    uint32_t sub_off    = (uint32_t)(byte_start % native_bs);
    /* Read-modify-write: load the native sector, patch our bytes, write back */
    if (p->parent->read(p->parent, p->lba_offset + nat_lba, 1, s_part_bounce) < 0)
        return -1;
    __builtin_memcpy(s_part_bounce + sub_off, buf, byte_count);
    return p->parent->write(p->parent, p->lba_offset + nat_lba, 1, s_part_bounce);
}

/* ── Header validation ────────────────────────────────────────────────────
 * sector_buf: 512-byte buffer containing the raw sector read from disk.
 * expected_lba: the LBA at which this header was found (1 for primary,
 *               block_count-1 for backup). Checked against hdr.my_lba. */

static const uint8_t k_gpt_sig[8] = { 'E','F','I',' ','P','A','R','T' };

static int header_valid(const uint8_t *sector_buf, uint64_t expected_lba)
{
    const gpt_header_t *h = (const gpt_header_t *)sector_buf;

    /* Signature */
    for (int i = 0; i < 8; i++)
        if (h->signature[i] != k_gpt_sig[i]) return 0;

    /* Header size: 92 (UEFI minimum) to 512 (one full sector).
     * Upper bound prevents CRC from reading past the sector buffer. */
    if (h->header_size < 92 || h->header_size > 512) return 0;

    /* my_lba must equal the LBA we actually read from */
    if (h->my_lba != expected_lba) return 0;

    /* CRC32 over first header_size bytes with header_crc32 field zeroed.
     * header_crc32 is at byte offset 16 (signature[8]+revision[4]+header_size[4]). */
    static uint8_t copy[512];
    __builtin_memcpy(copy, sector_buf, h->header_size);
    copy[16] = copy[17] = copy[18] = copy[19] = 0;   /* zero header_crc32 */
    if (crc32_compute(copy, h->header_size) != h->header_crc32) return 0;

    return 1;
}

/* ── gpt_scan ─────────────────────────────────────────────────────────────
 * Scans devname for a valid GPT, registers partitions as child blkdevs. */

int gpt_scan(const char *devname)
{
    /* All large buffers are static to avoid stack overflow.
     * gpt_scan is called once at boot from a single-threaded context. */
    static uint8_t s_sector[4096];          /* one sector (header read, max 4K native) */
    static uint8_t s_entry_chunk[4096];     /* per-LBA read buffer */
    static uint8_t s_entries[128 * 128];    /* full partition array (16 KB!) */

    blkdev_t *dev = blkdev_get(devname);
    if (!dev) return 0;  /* absent hardware — silent, same as nvme_init */

    /* ── Read + validate primary GPT header (LBA 1) ── */
    if (dev->read(dev, 1, 1, s_sector) < 0) {
        printk("[GPT] WARN: cannot read GPT header on %s\n", devname);
        return 0;
    }

    gpt_header_t hdr;
    __builtin_memcpy(&hdr, s_sector, sizeof(hdr));

    if (!header_valid(s_sector, 1)) {
        /* Primary invalid — try backup header at last LBA */
        uint64_t last_lba = dev->block_count - 1;
        if (dev->read(dev, last_lba, 1, s_sector) < 0 ||
            !header_valid(s_sector, last_lba)) {
            printk("[GPT] WARN: no valid GPT on %s\n", devname);
            return 0;
        }
        __builtin_memcpy(&hdr, s_sector, sizeof(hdr));
    }

    /* ── Validate entry table parameters BEFORE reading the array ──────────
     * Must check here: if num_partition_entries > 128, the 4-chunk loop
     * would cover more than 16 KB, overflowing s_entries[].
     * We only support the standard 128-entry × 128-byte layout. */
    if (hdr.num_partition_entries > 128 || hdr.partition_entry_size != 128) {
        printk("[GPT] WARN: unsupported GPT layout on %s\n", devname);
        return 0;
    }

    /* ── Read partition entry array one native LBA at a time ────────────────
     * 512-byte drives: entry_lbas = 32 (128*128 / 512).
     * 4K-native drives: entry_lbas = 4  (128*128 / 4096).
     * Use hdr.partition_entry_lba (not 2) so the backup header's entry
     * array is read correctly on fallback. */
    uint32_t bs = dev->block_size;
    uint32_t entry_lbas = (128u * 128u + bs - 1u) / bs;
    for (uint32_t ei = 0; ei < entry_lbas; ei++) {
        if (dev->read(dev, hdr.partition_entry_lba + ei, 1, s_entry_chunk) < 0) {
            printk("[GPT] WARN: cannot read partition entries on %s\n", devname);
            return 0;
        }
        __builtin_memcpy(s_entries + ei * bs, s_entry_chunk, bs);
    }

    /* ── Validate partition array CRC ──────────────────────────────────────
     * GPT spec: CRC covers num_partition_entries * partition_entry_size bytes,
     * not the full s_entries[] buffer. The guard above ensured entry_size == 128
     * and num_entries <= 128, so the byte count is safe. We read all 32 sectors
     * (128 × 128 bytes) but only feed the header-declared length to CRC. */
    if (crc32_compute(s_entries, hdr.num_partition_entries * 128) !=
        hdr.partition_array_crc32) {
        printk("[GPT] WARN: partition array CRC mismatch on %s\n", devname);
        return 0;
    }

    /* ── Register valid partition entries as child blkdevs ── */
    int part_num = 1;  /* starts at 1 → first name is "nvme0p1" */

    for (int i = 0; i < 128 && part_num <= GPT_MAX_PARTS; i++) {
        const gpt_entry_t *e =
            (const gpt_entry_t *)(s_entries + (uint32_t)i * 128);

        /* Skip empty entries (type_guid all-zeros) */
        int used = 0;
        for (int j = 0; j < 16; j++) { if (e->type_guid[j]) { used = 1; break; } }
        if (!used) continue;
        /* Strict less-than: single-sector partitions unsupported (simplification) */
        if (e->start_lba >= e->end_lba) continue;

        /* Only register Aegis-typed partitions (8-byte prefix match) */
        int aegis = 1;
        for (int j = 0; j < 8; j++) {
            if (e->type_guid[j] != k_aegis_guid_prefix[j]) { aegis = 0; break; }
        }
        if (!aegis) continue;

        int idx = part_num - 1;

        /* Private data: parent device + partition start LBA */
        s_parts[idx].parent     = dev;
        s_parts[idx].lba_offset = e->start_lba;

        /* blkdev_t: always 512B logical sectors (512e) so ext2/VFS work unchanged.
         * block_count is expressed in 512B units. */
        uint64_t native_count = e->end_lba - e->start_lba + 1;
        s_devs[idx].block_count = native_count * (dev->block_size / 512u);
        s_devs[idx].block_size  = 512;
        s_devs[idx].lba_offset  = 0;
        s_devs[idx].read        = gpt_part_read;
        s_devs[idx].write       = gpt_part_write;
        s_devs[idx].priv        = &s_parts[idx];

        /* Build name manually — kernel has no snprintf.
         * Copy up to 13 chars of devname, append 'p', append ASCII digit,
         * null-terminate. Supports part_num 1–7 (single digit). */
        int ni = 0;
        for (; devname[ni] != '\0' && ni < 13; ni++)
            s_devs[idx].name[ni] = devname[ni];
        s_devs[idx].name[ni++] = 'p';
        s_devs[idx].name[ni++] = '0' + (char)part_num;
        s_devs[idx].name[ni]   = '\0';

        if (blkdev_register(&s_devs[idx]) < 0) {
            printk("[GPT] WARN: blkdev table full, %u partition(s) registered\n",
                   (unsigned)(part_num - 1));
            break;
        }
        part_num++;
    }

    int count = part_num - 1;
    if (count == 0) {
        printk("[GPT] WARN: no valid GPT on %s\n", devname);
        return 0;
    }

    printk("[GPT] OK: %u partition(s) found on %s\n", (unsigned)count, devname);
    return count;
}

int gpt_rescan(const char *devname)
{
    blkdev_unregister_children(devname);
    return gpt_scan(devname);
}
