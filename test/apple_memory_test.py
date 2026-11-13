#!/usr/bin/env python3
"""Execute report-only V4 after its real EL1/4K transition in QEMU."""
from pathlib import Path
import ctypes as C
import struct

from apple_probe_test import run_case
from boot_memory_test import Plan, Failure, PAGE

BUILD = Path("build/appleprobe-v4").resolve()


def check_case(el2, high=False, refuse=False, range_refusal=False, placeholder=None):
    image = 0x10000200000 if high else 0x40200000
    dtb = 0x10003000000 if high else 0x43000000
    arena = 0x10004000000 if high else 0x44000000
    extra = [(0x41000003, 0x5001), (0x42000000, 0x10000),
             (0x10002000000, 0x4000)]

    def prepare(path):
        text = path.read_text().replace("/dts-v1/;", """/dts-v1/;
/memreserve/ 0x41000003 0x5001;
/memreserve/ 0x10002000000 0x4000;""")
        if range_refusal:
            text = text.replace("0x10002000000 0x4000", "0x1000000000000 0x4000")
        text = text.replace("    chosen {", """
    reserved-memory {
        #address-cells = <2>; #size-cells = <2>; ranges;
        firmware@42000000 { reg = <0 0x42000000 0 0x10000>; no-map; };
        %s
    };
    chosen {
        linux,initrd-start = <0 0x42800003>;
        linux,initrd-end = <0 0x42807001>;
""" % ('dynamic { size = <0 0x4000>; };' if refuse else ""))
        if placeholder:
            text = text.replace('firmware@42000000 {', f"""
        empty@30 {{ reg = <0 0x30 0 0>; status = "{placeholder}"; }};
        firmware@42000000 {{""")
        path.write_text(text)

    def check(command, tmp, syms, report, text):
        destination = tmp / "memory-report"
        command("pmemsave", val=image + syms["apple_probe_memory_report"],
                size=C.sizeof(Plan), filename=str(destination))
        plan = Plan.from_buffer_copy(destination.read_bytes())
        command("pmemsave", val=image + syms["apple_probe_memory_failure"],
                size=C.sizeof(Failure), filename=str(tmp / "failure-report"))
        failure = Failure.from_buffer_copy((tmp / "failure-report").read_bytes())
        assert "AEGIS V4 - RESERVATION-AWARE MEMORY REPORT\n" in text
        assert "HALTED - MMU ON / CACHES OFF / DAIF MASKED\n" in text
        active_empty = placeholder == "okay"
        if refuse or range_refusal or active_empty:
            assert plan.error == (3 if range_refusal or active_empty else 5)
            assert bytes(plan)[4:] == bytes(C.sizeof(plan) - 4)
            assert "NO CANDIDATES - NO ALLOCATOR\n" in text
            if range_refusal:
                blob = (tmp / "test.dtb").read_bytes()
                offset = struct.unpack_from(">I", blob, 16)[0] + 16
                assert (failure.source, failure.reason, failure.offset, failure.index) == (2, 2, offset, 1)
                limit = 1 << (32, 36, 40, 42, 44, 48)[report[3] & 15]
                assert (failure.base, failure.size, failure.limit) == (1 << 48, 0x4000, limit)
                for label, value in (
                    ("FAILURE SOURCE", 2), ("FAILURE REASON", 2),
                    ("DTB BYTE OFFSET", offset), ("TUPLE INDEX", 1),
                    ("RAW BASE", 1 << 48), ("RAW SIZE", 0x4000),
                    ("PHYSICAL LIMIT EXCLUSIVE", limit),
                ):
                    assert f"{label}=0X{value:016X}\n" in text
            elif active_empty:
                blob = (tmp / "test.dtb").read_bytes()
                offset = blob.index(struct.pack(">4I", 0, 0x30, 0, 0))
                assert (failure.source, failure.reason, failure.offset, failure.index) == (4, 1, offset, 0)
                limit = 1 << (32, 36, 40, 42, 44, 48)[report[3] & 15]
                assert (failure.base, failure.size, failure.limit) == (0x30, 0, limit)
                assert "FAILURE SOURCE=0X0000000000000004\n" in text
                assert "FAILURE REASON=0X0000000000000001\n" in text
            else:
                assert bytes(failure) == bytes(C.sizeof(Failure))
            return
        assert plan.error == 0
        assert bytes(failure) == bytes(C.sizeof(Failure))
        assert "CANDIDATES ONLY - NO ALLOCATOR OR RECLAIM\n" in text
        # Interval subtraction oracle: unlike the guest it neither parses FDT
        # nor uses fixed-capacity arrays. Large advertised banks stay intervals.
        banks = [(0x40000000, 0x50000000),
                 (0x10001fac000, 0x1045b434000)]
        exclusions = [*extra, (0x42800003, 0x6ffe),
                      (image, syms["apple_probe_end"]),
                      (dtb, len((tmp / "test.dtb").read_bytes())),
                      (arena + 64, 160 * 1280)]
        wanted = banks[:]
        for base, size in exclusions:
            begin, end = base & -PAGE, (base + size + PAGE - 1) & -PAGE
            result = []
            for left, right in wanted:
                if end <= left or begin >= right:
                    result.append((left, right))
                else:
                    if left < begin: result.append((left, begin))
                    if end < right: result.append((end, right))
            wanted = result
        actual = [(r.begin, r.end) for r in plan.candidates[:plan.candidate_count]]
        assert actual == wanted, (actual, wanted)
        assert plan.bank_bytes == sum(b - a for a, b in banks)
        assert plan.candidate_bytes == sum(b - a for a, b in wanted)
        assert plan.excluded_bytes == plan.bank_bytes - plan.candidate_bytes
        assert not plan.banks[plan.bank_count].end
        assert not plan.candidates[plan.candidate_count].end

    failed = refuse or range_refusal or placeholder == "okay"
    run_case(image, build=BUILD, el2=el2, version=4, stage=11 if failed else 10,
             post_check=check, prepare_tree=prepare, dtb_address=dtb,
             arena_address=arena, sparse_high_ram=high)


if __name__ == "__main__":
    for el2 in (False, True):
        check_case(el2)
        check_case(el2, refuse=True)
        check_case(el2, range_refusal=True)
        check_case(el2, placeholder="disabled")
        check_case(el2, placeholder="okay")
    check_case(True, high=True)
