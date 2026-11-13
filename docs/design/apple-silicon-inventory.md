# J514s/T6030 read-only inventory

Collected 2026-11-12 over SSH while DH Linux was running. Only allowlisted DT
fields, the boot FDT's 40-byte header, CPU sysfs identification, `/proc/iomem`,
mount information and the existing activation digest were read. No raw DT,
random seed, serial number, calibration or SEP state was copied.

These values describe **one Linux boot**, not constants to compile into an
Apple backend. The live OF tree may include Linux runtime changes.

## Platform

- Apple MacBook Pro (14-inch, M3 Pro, November 2023).
- Root compatible list: `apple,j514s`, `apple,t6030`, `apple,arm-platform`.
- Root and `/chosen` use two address cells and two size cells.
- Running kernel: `7.2.11-dh2-touchid-16k+`; Linux page size 16,384 bytes.
- CPU0 MIDR export: `0x00000000611f0451`.
- `id_aa64mmfr0_el1` and `id_aa64mmfr1_el1` were not exported through the
  checked sysfs identification directory. No claim about supported CPU page
  granules follows from that absence or from Linux's chosen page size.

## Loader-expanded FDT size

Only the original boot FDT header was read:

| Field | Value |
| --- | --- |
| total size | 211269 |
| structure offset / size | 120 / 203404 |
| strings offset / size | 203524 / 7745 |
| reservation map offset | 40 |
| version / last-compatible version | 17 / 16 |
| meaningful extent | 211269 |

The staged DTB was only 91,529 bytes. This exposed Aegis's insufficient
128 KiB capture buffer **before** a hardware attempt. The shared reader now
has a 512 KiB bound, with a loader-expansion and oversize-rejection test.

## Boot framebuffer, not desktop mode

`/chosen/framebuffer@104600a2880`:

| Field | Observed value |
| --- | --- |
| compatible | `apple,simple-framebuffer`, `simple-framebuffer` |
| base | `0x104600a2880` |
| declared size | `0x15cd680` = 22861440 bytes |
| width × height | 3024 × 1890 |
| stride | 12096 bytes |
| format | `x2r10g10b10` |
| end, exclusive | `0x1046166ff00` |

Stride × height equals declared size. The range lies inside the reserved
framebuffer allocation `[0x1045ffc8000, 0x10465774000)`, size `0x57ac000`.
The desktop reports 3024 × 1964; that active DCP mode must not be substituted
for the boot framebuffer geometry.

The diagnostic accepts the live 10-bit format as well as XRGB8888. Its QEMU
tests use guarded RAM, including this 3024 × 1890 pitch/size, but do not
exercise a DCP display pipeline.

## RAM and reservations

The main advertised RAM bank was
`[0x10001fac000, 0x1045b434000)`, size `0x459488000`.
The DT also advertises small banks containing firmware/UAT handoff regions.
`/proc/iomem` records reserved areas inside otherwise advertised RAM.

**Do not treat every memory-node range as free memory.** A future allocator
must subtract all DT reservation-map entries and `/reserved-memory` regions,
the payload/stack/tables/DTB/initrd, and the appropriate firmware-owned ranges.
No allocator is active in the entry diagnostic.

Observed reserved-memory categories included ASC/SEP/SIO firmware, DCP text/
data/logs/segments, external-display firmware/heaps/page tables, framebuffer,
GPU firmware/UAT tables and ISP heap. None are reclaimed by the diagnostic.

## Other observations and limits

- `stdout-path` is `serial0`, resolving to `/soc/serial@289200000`,
  compatible `apple,s5l-uart`, MMIO size `0x1000`. This is **not PL011**.
  The diagnostic deliberately does not touch UART MMIO.
- Fedora's mounted ESP is partition 4; the DH ESP is partition 8 and was
  not mounted for this inventory.
- The existing DH initramfs activation record identifies SHA256
  `0975d93693f047898df858100864c4a7af4079a51c45ee7d0794441590c8b912`.
  This reads the previous activation record, not a new verification of every
  on-disk boot artifact.

The subsequent native V2 diagnostic has now supplied an owner-transcribed
entry report: EL2, SCTLR `0x30900180` and MMFR0 `0x110012120f100003`.
Architectural granule decoding reports 4 KiB and 16 KiB support, no 64 KiB
support. The image and DTB placement from that run are recorded in
`apple-silicon-console.md`; one framebuffer-base transcription needs
verification. Linux's running state still does not prove the loader contract
for every payload. The diagnostic has not been installed as a persistent
boot target.
