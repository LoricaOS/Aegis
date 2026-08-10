#!/usr/bin/env python3
"""Seed corpora for fuzz_fat / fuzz_ext2 / fuzz_gpt.

Without valid seeds the mount path is essentially never reached and a fuzz run
looks clean while testing nothing, so this builds images the *kernel* accepts.

FAT is hand-built rather than produced by mkfs.vfat: Aegis's fat_mount does not
enforce FAT32's 65525-cluster minimum, so a valid-to-Aegis volume fits in ~64 KB
instead of the ~33 MB mkfs insists on — which keeps executions fast. ext2 and
GPT come from mkfs.ext2 / sgdisk when those are installed.

Usage:  python3 seeds_disk.py [outdir]
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile

out = sys.argv[1] if len(sys.argv) > 1 else "."
SECTOR = 512


def write(corpus, name, data):
    d = os.path.join(out, corpus)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


# ---------------------------------------------------------------- FAT32 ----
def sfn(name, ext, attr=0x20, cluster=2, size=0, mdate=None):
    """One 8.3 directory entry. mdate is the raw DOS write-date word."""
    e = bytearray(32)
    e[0:11] = (name.ljust(8)[:8] + ext.ljust(3)[:3]).encode()
    e[11] = attr
    if mdate is not None:
        e[24:26] = struct.pack("<H", mdate)
    e[20:22] = struct.pack("<H", (cluster >> 16) & 0xFFFF)
    e[26:28] = struct.pack("<H", cluster & 0xFFFF)
    e[28:32] = struct.pack("<I", size)
    return bytes(e)


def dos_date(year=2006, month=1, day=1):
    return (((year - 1980) & 0x7F) << 9) | ((month & 0x0F) << 5) | (day & 0x1F)


LFN_POS = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]


def lfn_entries(long_name, checksum):
    """VFAT long-name entries, in the on-disk (reverse) order."""
    chunks = [long_name[i:i + 13] for i in range(0, len(long_name), 13)]
    ents = []
    for idx, chunk in enumerate(chunks):
        e = bytearray(32)
        seq = idx + 1
        e[0] = seq | (0x40 if idx == len(chunks) - 1 else 0)
        e[11] = 0x0F                      # ATTR_LFN
        e[13] = checksum
        padded = chunk.ljust(13, "\0")
        for k, ch in enumerate(padded):
            off = LFN_POS[k]
            val = 0xFFFF if (k >= len(chunk) + 1) else ord(ch)
            e[off:off + 2] = struct.pack("<H", val)
        ents.append(bytes(e))
    return list(reversed(ents))


def lfn_checksum(raw11):
    s = 0
    for c in raw11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def make_fat32(spc=1, nfats=2, reserved=32, clusters=64, bad_month=False):
    """A minimal FAT32 volume Aegis will mount, with a populated root dir."""
    fat_entries = clusters + 2
    fat_sectors = max(1, (fat_entries * 4 + SECTOR - 1) // SECTOR)
    data_lba = reserved + nfats * fat_sectors
    total = data_lba + clusters * spc

    root_cluster = 2
    file_cluster = 3
    sub_cluster = 4

    # --- FAT: root -> EOC, file -> EOC, subdir -> EOC
    fat = bytearray(fat_sectors * SECTOR)
    def setfat(cl, val):
        struct.pack_into("<I", fat, cl * 4, val & 0x0FFFFFFF)
    setfat(0, 0x0FFFFFF8)
    setfat(1, 0x0FFFFFFF)
    setfat(root_cluster, 0x0FFFFFFF)
    setfat(file_cluster, 0x0FFFFFFF)
    setfat(sub_cluster, 0x0FFFFFFF)

    # --- root directory
    payload = b"hello from the fuzz corpus\n"
    md = dos_date(month=15) if bad_month else dos_date()
    root = bytearray()
    root += sfn("HELLO", "TXT", 0x20, file_cluster, len(payload), mdate=md)
    root += sfn("SUBDIR", "", 0x10, sub_cluster, 0, mdate=md)
    long_name = "a-deliberately-long-name-for-lfn-reassembly.txt"
    raw = ("LONGNA~1TXT").encode()
    root += b"".join(lfn_entries(long_name, lfn_checksum(raw)))
    root += sfn("LONGNA~1", "TXT", 0x20, file_cluster, len(payload))
    root = bytes(root).ljust(spc * SECTOR, b"\0")

    sub = (sfn(".", "", 0x10, sub_cluster, 0) +
           sfn("..", "", 0x10, root_cluster, 0)).ljust(spc * SECTOR, b"\0")

    # --- BPB
    bpb = bytearray(SECTOR)
    bpb[0:3] = b"\xEB\x58\x90"
    bpb[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", bpb, 11, SECTOR)      # bytes per sector
    bpb[13] = spc                                 # sectors per cluster
    struct.pack_into("<H", bpb, 14, reserved)     # reserved sectors
    bpb[16] = nfats
    struct.pack_into("<H", bpb, 19, 0)            # TotSec16 (use 32-bit)
    bpb[21] = 0xF8
    struct.pack_into("<I", bpb, 32, total)        # TotSec32
    struct.pack_into("<I", bpb, 36, fat_sectors)  # FATSz32
    struct.pack_into("<I", bpb, 44, root_cluster)
    struct.pack_into("<H", bpb, 48, 1)            # FSInfo
    struct.pack_into("<H", bpb, 50, 6)            # backup boot sector
    bpb[510:512] = b"\x55\xAA"

    img = bytearray(total * SECTOR)
    img[0:SECTOR] = bpb
    for i in range(nfats):
        off = (reserved + i * fat_sectors) * SECTOR
        img[off:off + len(fat)] = fat
    def put_cluster(cl, data):
        off = (data_lba + (cl - 2) * spc) * SECTOR
        img[off:off + len(data)] = data
    put_cluster(root_cluster, root)
    put_cluster(sub_cluster, sub)
    put_cluster(file_cluster, payload.ljust(spc * SECTOR, b"\0"))
    return bytes(img)


write("corpus_fat", "fat32_min", make_fat32())
write("corpus_fat", "fat32_spc4", make_fat32(spc=4, clusters=32))
write("corpus_fat", "fat32_1fat", make_fat32(nfats=1, reserved=1))

# REGRESSION SEED. The DOS month field is 4 bits (0..15) but fat_time_unix's
# cum[] table has 12 entries; months 13..15 read past its end. Found by this
# fuzzer 2026-08-09 and fixed by clamping the upper bound. Keep this seed: it
# reaches the bug in one execution, so a regression surfaces immediately.
write("corpus_fat", "fat32_month15", make_fat32(bad_month=True))
print("corpus_fat: 4 crafted FAT32 volumes (incl. the month-overflow regression)")

# ----------------------------------------------------------------- ext2 ----
def have(prog):
    return shutil.which(prog) is not None


if have("mkfs.ext2"):
    tmp = tempfile.mkdtemp()
    try:
        for label, bs in (("ext2_1k", 1024), ("ext2_4k", 4096)):
            p = os.path.join(tmp, label)
            with open(p, "wb") as f:
                f.truncate(2 << 20)
            subprocess.run(["mkfs.ext2", "-q", "-F", "-b", str(bs), p],
                           check=True, capture_output=True)
            if have("debugfs"):
                content = os.path.join(tmp, "f.txt")
                with open(content, "w") as f:
                    f.write("hello from the fuzz corpus\n")
                for cmd in (f"write {content} hello.txt",
                            "mkdir /subdir",
                            "symlink /link hello.txt"):
                    subprocess.run(["debugfs", "-w", "-R", cmd, p],
                                   capture_output=True)
            write("corpus_ext2", label, open(p, "rb").read())
        print("corpus_ext2: 2 mkfs.ext2 volumes")
    finally:
        shutil.rmtree(tmp)
else:
    print("corpus_ext2: SKIPPED (mkfs.ext2 not installed)")

# ------------------------------------------------------------------ GPT ----
if have("sgdisk"):
    tmp = tempfile.mkdtemp()
    try:
        p = os.path.join(tmp, "gpt.img")
        with open(p, "wb") as f:
            f.truncate(16 << 20)
        subprocess.run(["sgdisk", "-n", "1:2048:+4M", "-t", "1:0700",
                        "-c", "1:fuzzpart", p], check=True, capture_output=True)
        subprocess.run(["sgdisk", "-n", "2:0:+4M", "-t", "2:8300",
                        "-c", "2:fuzzpart2", p], check=True, capture_output=True)
        data = open(p, "rb").read()
        write("corpus_gpt", "gpt_two_parts", data)
        # A GPT-prefixed disk is also a useful negative seed for the mounts:
        # they must reject it rather than misparse it.
        write("corpus_fat", "gpt_disk", data[:1 << 20])
        write("corpus_ext2", "gpt_disk", data[:1 << 20])
        print("corpus_gpt: 1 sgdisk image")
    finally:
        shutil.rmtree(tmp)
else:
    print("corpus_gpt: SKIPPED (sgdisk not installed)")
