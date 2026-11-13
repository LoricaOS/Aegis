#!/usr/bin/env python3
"""Host checks of real reservation-aware intake; no physical RAM is touched."""
import ctypes as C
from pathlib import Path
import os
import random
import shlex
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PAGE = 4096


def u32(n):
    return struct.pack(">I", n)


def u64(n):
    return struct.pack(">Q", n)


def reg(ranges, ac=2, sc=2):
    return b"".join((u64(a) if ac == 2 else u32(a)) +
                    (u64(s) if sc == 2 else u32(s)) for a, s in ranges)


def node(name, props=(), children=()):
    return name, list(props), list(children)


def memory(ranges, extra=(), name="memory@10000", ac=2, sc=2):
    return node(name, [("device_type", b"memory\0"), ("reg", reg(ranges, ac, sc)), *extra])


def reserved(children, extra=()):
    return node("reserved-memory", [
        ("#address-cells", u32(2)), ("#size-cells", u32(2)), ("ranges", b""), *extra,
    ], children)


def tree(children=(), reservations=(), root_extra=(), reserve_last=False, cells=2):
    names = bytearray()
    offsets = {}

    def encode(n):
        name, props, children = n
        b = bytearray(u32(1) + name.encode() + b"\0")
        b += bytes(-len(b) % 4)
        for key, value in props:
            if key not in offsets:
                offsets[key] = len(names)
                names.extend(key.encode() + b"\0")
            b += u32(3) + u32(len(value)) + u32(offsets[key]) + value
            b += bytes(-len(b) % 4)
        for child in children:
            b += encode(child)
        return b + u32(2)

    block = encode(node("", [("#address-cells", u32(cells)),
                              ("#size-cells", u32(cells)), *root_extra], children)) + u32(9)
    rsv = reg(reservations) + bytes(16)
    if reserve_last:
        st, ns = 40, 40 + len(block)
        rs = (ns + len(names) + 7) & -8
        data = block + names + bytes(rs - ns - len(names)) + rsv
    else:
        rs, st = 40, 40 + len(rsv)
        ns = st + len(block)
        data = rsv + block + names
    header = struct.pack(">10I", 0xd00dfeed, 40 + len(data), st, ns, rs,
                         17, 16, 0, len(names), len(block))
    return header + data


class Range(C.Structure):
    _fields_ = [("begin", C.c_uint64), ("end", C.c_uint64)]


class Request(C.Structure):
    _fields_ = [(n, C.c_uint64) for n in (
        "image", "image_size", "dtb", "fb", "fb_size", "physical_limit")]


class Failure(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in ("source", "reason", "offset", "index")] + [
        (n, C.c_uint64) for n in ("base", "size", "limit")]


class Plan(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in (
        "error", "bank_count", "reserved_count", "candidate_count")] + [
        (n, C.c_uint64) for n in ("bank_bytes", "excluded_bytes", "candidate_bytes")
    ] + [("banks", Range * 32), ("reserved", Range * 128), ("candidates", Range * 192)]


def pages(ranges, reserve):
    result = set()
    for base, size in ranges:
        start = base & -PAGE if reserve else (base + PAGE - 1) & -PAGE
        end = (base + size + PAGE - 1) & -PAGE if reserve else (base + size) & -PAGE
        result.update(range(start, end, PAGE))
    return result


class BootMemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        lib = Path(cls.tmp.name) / "bootmem.so"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
            str(ROOT / "kernel/arch/arm64/boot_memory.c"), "-o", str(lib),
        ], check=True)
        cls.lib = C.CDLL(str(lib))
        cls.lib.boot_memory_plan.argtypes = [
            C.c_void_p, C.c_uint32, C.POINTER(Request), C.POINTER(Plan), C.POINTER(Failure)]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def request(self):
        return Request(0x20000, 4096, 0x30000, 0x40000, 4096, 1 << 42)

    def parse(self, blob, request=None, good=True):
        q = request or self.request()
        data = C.create_string_buffer(bytes(blob))
        out = Plan()
        self.failure = Failure()
        C.memset(C.byref(self.failure), 0xa5, C.sizeof(self.failure))
        C.memset(C.byref(out), 0xa5, C.sizeof(out))
        result = self.lib.boot_memory_plan(data, len(blob), C.byref(q), C.byref(out),
                                           C.byref(self.failure))
        # Diagnostics are optional and must never change acceptance or the plan.
        plain = Plan()
        self.assertEqual(self.lib.boot_memory_plan(
            data, len(blob), C.byref(q), C.byref(plain), None), result)
        self.assertEqual(bytes(plain), bytes(out))
        self.assertEqual(data.raw[:len(blob)], bytes(blob))
        self.assertEqual(bool(result), good, f"error={out.error}")
        if good or out.error not in (3, 4):
            self.assertEqual(bytes(self.failure), bytes(C.sizeof(self.failure)))
        if not good:
            self.assertNotEqual(out.error, 0)
            self.assertEqual(bytes(out)[4:], bytes(C.sizeof(out) - 4))
        return out

    def check_model(self, blob, banks, exclusions, q=None):
        q = q or self.request()
        out = self.parse(blob, q)
        protected = [*exclusions, (q.image, q.image_size), (q.dtb, len(blob))]
        if q.fb_size: protected.append((q.fb, q.fb_size))
        wanted = pages(banks, False) - pages(protected, True)
        actual = pages([(r.begin, r.end - r.begin)
                        for r in out.candidates[:out.candidate_count]], False)
        self.assertEqual(actual, wanted)
        self.assertEqual(out.bank_bytes, len(pages(banks, False)) * PAGE)
        self.assertEqual(out.candidate_bytes, len(wanted) * PAGE)
        self.assertEqual(out.excluded_bytes, out.bank_bytes - out.candidate_bytes)
        for name, count in (("banks", out.bank_count), ("reserved", out.reserved_count),
                            ("candidates", out.candidate_count)):
            previous = None
            for r in getattr(out, name)[:count]:
                self.assertLess(r.begin, r.end)
                self.assertEqual(r.begin % PAGE, 0)
                self.assertEqual(r.end % PAGE, 0)
                if previous is not None: self.assertLess(previous, r.begin)
                previous = r.end
        return out

    def test_all_reservation_sources_and_initrd(self):
        banks = [(0x10000, 0x100000)]
        exclusions = [(0x50000, 0x1000), (0x60123, 0x123), (0x70001, 0x1300)]
        blob = tree([
            memory(banks),
            reserved([node("firmware", [("reg", reg([exclusions[1]])),
                                        ("reusable", b""), ("no-map", b"")])]),
            node("chosen", [("linux,initrd-start", u64(0x70001)),
                             ("linux,initrd-end", u64(0x71301))]),
        ], reservations=exclusions[:1])
        self.check_model(blob, banks, exclusions)

    def test_unsorted_overlapping_adjacent_ranges(self):
        banks = [(0x50000, 0x30000), (0x10000, 0x40000), (0x20000, 0x50000)]
        exclusions = [(0x50100, 0x1000), (0x51000, 0x1000), (0x50000, 0x400)]
        self.check_model(tree([memory(banks)], reservations=exclusions), banks, exclusions)

    def test_inward_ram_outward_exclusion_and_small_banks(self):
        banks = [(0x10001, 0xafff), (0x90001, 2)]
        exclusions = [(0x12fff, 2)]
        self.check_model(tree([memory(banks)], reservations=exclusions), banks, exclusions)

    def test_reservation_map_after_strings(self):
        banks, exclusions = [(0x10000, 0x100000)], [(0x58001, 1)]
        self.check_model(tree([memory(banks)], exclusions, reserve_last=True), banks, exclusions)

    def test_disabled_static_reservations_are_not_reclaimed(self):
        banks, exclusions = [(0x10000, 0x100000)], [(0x50000, 8192)]
        blob = tree([memory(banks), reserved([
            node("disabled-static", [("reg", reg(exclusions)), ("status", b"disabled\0")]),
            node("disabled-dynamic", [("size", u64(4096)), ("status", b"disabled\0")]),
        ])])
        self.check_model(blob, banks, exclusions)

    def test_disabled_empty_static_tuples_have_no_pages(self):
        banks, exclusions = [(0x10000, 0x100000)], [(0x50003, 8192)]
        for cells in (1, 2):
            tuples = [(0x30, 0), exclusions[0], (0, 0), (0x60, 0)]
            blob = tree([memory(banks, ac=cells, sc=cells),
                         node("reserved-memory", [
                             ("#address-cells", u32(cells)), ("#size-cells", u32(cells)),
                             ("ranges", b""),
                         ], [node("arbitrary-name", [
                             ("reg", reg(tuples, cells, cells)), ("status", b"disabled\0"),
                         ])])], cells=cells)
            self.check_model(blob, banks, exclusions)
        # A disabled ancestor also makes the placeholder explicitly inactive.
        blob = tree([memory(banks), reserved([
            node("placeholder", [("reg", reg([(0x30, 0), exclusions[0]])),
                                 ("status", b"okay\0")]),
        ], [("status", b"disabled\0")])])
        self.check_model(blob, banks, exclusions)

    def test_empty_static_tuples_require_explicit_disabled_status(self):
        banks = [(0x10000, 0x100000)]
        for status in (None, b"okay\0", b"ok\0", b"fail\0", b"reserved\0", b"unknown\0"):
            props = [("reg", reg([(0x30, 0)]))]
            if status is not None:
                props.append(("status", status))
            blob = tree([memory(banks), reserved([node("placeholder", props)])])
            self.assertEqual(self.parse(blob, good=False).error, 3)
            self.assertEqual((self.failure.source, self.failure.reason), (4, 1))
        # Unrelated disabled nodes do not authorize an active placeholder.
        blob = tree([memory(banks), reserved([
            node("inactive", [("status", b"disabled\0")]),
            node("active", [("reg", reg([(0x30, 0)]))]),
        ])])
        self.parse(blob, good=False)

    def test_disabled_placeholders_still_validate_shapes_and_bounds(self):
        banks = [(0x10000, 0x100000)]
        for data in (b"", b"bad", reg([(1 << 42, 0)]),
                     reg([((1 << 64) - 1, 0)]), reg([((1 << 42) - 1, PAGE)])):
            blob = tree([memory(banks), reserved([node("placeholder", [
                ("reg", data), ("status", b"disabled\0"),
            ])])])
            self.parse(blob, good=False)
        for children in (
            [memory([(0x30, 0)])],
            [memory(banks), reserved([node("dynamic", [("size", u64(PAGE))])])],
        ):
            self.parse(tree(children), good=False)
        self.parse(tree([memory(banks)], reservations=[(0x30, 0)]), good=False)

    def test_high_addresses_without_materializing_all_pages(self):
        b, n = 0x10001fac000, 0x459488000
        q = Request(0x10007600000, 0xc1000, 0x100076c4000,
                    0x104600a2880, 0x15cd680, 1 << 42)
        blob = tree([memory([(b, n)]), reserved([
            node("firmware", [("reg", reg([(b, 0x10000)]))]),
        ])])
        out = self.parse(blob, q)
        self.assertEqual(out.bank_bytes, n)
        self.assertLess(out.candidate_bytes, n)
        for r in out.candidates[:out.candidate_count]:
            self.assertGreaterEqual(r.begin, b + 0x10000)
            self.assertLessEqual(r.end, b + n)
            self.assertFalse(r.begin < q.image + q.image_size and q.image < r.end)
            self.assertFalse(r.begin < q.dtb + len(blob) and q.dtb < r.end)

    def test_one_cell_width_and_32bit_initrd(self):
        banks, exclusions = [(0x10000, 0x100000)], [(0x50000, 0x1000)]
        blob = tree([memory(banks, ac=1, sc=1),
                     node("chosen@0", [("linux,initrd-start", u32(0x50000)),
                                       ("linux,initrd-end", u32(0x51000))])], cells=1)
        self.check_model(blob, banks, exclusions)

    def test_disabled_memory_is_not_claimed(self):
        banks = [(0x10000, 0x20000)]
        blob = tree([memory(banks), node("memory@90000", [
            ("device_type", b"memory\0"), ("status", b"disabled\0")])])
        self.check_model(blob, banks, [])

    def test_all_ram_reserved_is_valid_but_no_ram_is_not(self):
        banks = [(0x10000, 0x10000)]
        out = self.check_model(tree([memory(banks)], reservations=banks), banks, banks)
        self.assertEqual(out.candidate_count, 0)
        self.parse(tree(), good=False)

    def test_refuses_unresolved_or_nonstandard_reservations(self):
        good = memory([(0x10000, 0x100000)])
        for reservation in (
            reserved([node("dynamic", [("size", u64(4096))])]),
            node("reserved-memory", [], [node("x", [("reg", reg([(0x50000, 4096)]))])]),
            reserved([], [("reg", reg([(0x50000, 4096)]))]),
            reserved([], [("ranges", reg([(0x50000, 4096)]))]),
            reserved([node("x", [("reg", reg([(0x50000, 4096)]))], [node("nested")])]),
        ):
            self.parse(tree([good, reservation]), good=False)

    def test_rejects_restrictive_memory_bindings_instead_of_ignoring_them(self):
        for key in ("linux,usable-memory-range", "linux,elfcorehdr"):
            self.parse(tree([memory([(0x10000, 0x100000)]),
                             node("chosen", [(key, reg([(0x10000, 4096)]))])]), good=False)
        for key in ("linux,usable-memory", "hotpluggable"):
            self.parse(tree([memory([(0x10000, 0x100000)], [(key, b"")])]), good=False)

    def test_bad_initrd_duplicates_cells_and_ranges(self):
        good = memory([(0x10000, 0x100000)])
        for props in (
            [("linux,initrd-start", u32(1))],
            [("linux,initrd-end", u32(1))],
            [("linux,initrd-start", b"bad"), ("linux,initrd-end", u32(2))],
            [("linux,initrd-start", u32(4)), ("linux,initrd-end", u32(3))],
        ):
            self.parse(tree([good, node("chosen", props)]), good=False)
        for extra in ([("reg", reg([(0x10000, 4096)]))],
                      [("status", b"okay\0"), ("status", b"okay\0")],
                      [("status", b"okay")]):
            self.parse(tree([memory([(0x10000, 0x100000)], extra)]), good=False)
        for ranges in ([(0x10000, 0)], [(0xfffffffffffff000, 8192)], [(1 << 42, 4096)]):
            self.parse(tree([memory(ranges)]), good=False)
        self.parse(tree([node("memory@0", [("reg", b"bad")])]), good=False)
        self.parse(tree([memory([(0x10000, 4096)], ac=1, sc=1)], cells=3), good=False)

    def test_capacity_and_failure_clear_all_partial_output(self):
        self.parse(tree([memory([(0x10000 + i * 8192, 4096) for i in range(33)])]), good=False)
        self.parse(tree([memory([(0x10000, 0x100000)])],
                        reservations=[(0x10000 + i * 4096, 4096) for i in range(129)]), good=False)
        blob = tree([memory([(0x10000, 0x100000)])])
        self.parse(blob)
        for data in (b"", bytes(40), blob[:39], blob[:-1]):
            self.parse(data, good=False)
        self.assertEqual(self.lib.boot_memory_plan(None, 0, None, None, None), 0)

    def test_range_failure_sources_offsets_and_raw_values(self):
        limit, bad, size = 1 << 42, (1 << 42) - 16, 4096
        valid = (0x10000, 0x100000)
        fixtures = [
            (tree([memory([valid])], reservations=[(0x50000, 4096), (bad, size)]),
             2, 1, reg([(bad, size)])),
            (tree([memory([valid, (bad, size)])]), 3, 1, reg([(bad, size)])),
            (tree([memory([valid]), reserved([
                node("firmware", [("reg", reg([(0x50000, 4096), (bad, size)]))])])]),
             4, 1, reg([(bad, size)])),
            (tree([memory([valid]), node("chosen", [
                ("linux,initrd-start", u64(bad)), ("linux,initrd-end", u64(bad + size))])]),
             5, 0, u64(bad)),
        ]
        for blob, source, index, encoded in fixtures:
            with self.subTest(source=source):
                self.assertEqual(self.parse(blob, good=False).error, 3)
                f = self.failure
                self.assertEqual((f.source, f.reason, f.offset, f.index),
                                 (source, 3, blob.index(encoded), index))
                self.assertEqual((f.base, f.size, f.limit), (bad, size, limit))

    def test_request_and_explicit_exclusion_failures(self):
        blob = tree([memory([(0x10000, 0x100000)])])
        for field, source, size in (("image", 6, PAGE), ("dtb", 7, len(blob)), ("fb", 8, PAGE)):
            q = self.request()
            setattr(q, field, q.physical_limit - 1)
            self.assertEqual(self.parse(blob, q, good=False).error, 3)
            f = self.failure
            self.assertEqual((f.source, f.reason, f.offset, f.index), (source, 3, 0, 0))
            self.assertEqual((f.base, f.size, f.limit),
                             (q.physical_limit - 1, size, q.physical_limit))
        for field, value, source in (("physical_limit", 0, 1), ("physical_limit", 12345, 1),
                                     ("physical_limit", 1 << 49, 1), ("image", 0, 6),
                                     ("image_size", 0, 6), ("dtb", 0, 7), ("fb_size", 0, 8)):
            q = self.request()
            setattr(q, field, value)
            self.parse(blob, q, good=False)
            self.assertEqual((self.failure.source, self.failure.reason), (source, 5))
            self.assertEqual(self.failure.limit, q.physical_limit)

    def test_range_reason_precedence_and_capacity_context(self):
        for base, size, reason in ((1 << 42, 0, 1), (1 << 42, PAGE, 2),
                                   ((1 << 64) - 1, PAGE, 2), ((1 << 42) - 1, PAGE, 3)):
            blob = tree([memory([(base, size)])])
            self.parse(blob, good=False)
            self.assertEqual((self.failure.source, self.failure.reason), (3, reason))
            self.assertEqual((self.failure.base, self.failure.size), (base, size))
        ranges = [(0x10000 + i * 8192, PAGE) for i in range(33)]
        blob = tree([memory(ranges)])
        self.assertEqual(self.parse(blob, good=False).error, 4)
        f = self.failure
        self.assertEqual((f.source, f.reason, f.offset, f.index),
                         (3, 4, blob.index(reg([ranges[-1]])), 32))
        self.assertEqual((f.base, f.size), ranges[-1])

    def test_corrupt_header_and_structure(self):
        data = tree([memory([(0x10000, 0x100000)])])
        for offset, value in ((0, 0), (4, 0xffffffff), (8, 0xfffffffc),
                              (12, 40), (16, 0), (20, 16), (36, 0xfffffffc)):
            blob = bytearray(data)
            struct.pack_into(">I", blob, offset, value)
            self.parse(blob, good=False)
        fields = struct.unpack_from(">10I", data)
        for blob in (
            data[:fields[2]] + u32(123) + data[fields[2] + 4:],
            data[:fields[2] + fields[9] - 4] + u32(4) + data[fields[2] + fields[9]:],
        ):
            self.parse(blob, good=False)
        self.parse(tree([node("bad/name")]), good=False)
        self.parse(tree([node("")]), good=False)
        self.parse(tree([node("chosen"), node("chosen")]), good=False)
        self.parse(tree([reserved([]), reserved([])]), good=False)

    def test_reservation_map_missing_terminator_or_zero_size(self):
        good = memory([(0x10000, 0x100000)])
        data = bytearray(tree([good], reservations=[(0x50000, 4096)]))
        struct.pack_into(">QQ", data, 56, 0x60000, 4096)  # overwrite terminator
        self.parse(data, good=False)
        self.parse(tree([good], reservations=[(0x50000, 0)]), good=False)

    def test_page_set_model_randomized(self):
        rng = random.Random(0x6030)
        for _ in range(200):
            banks = [(rng.randrange(1, 128) * PAGE + rng.randrange(8),
                      rng.randrange(1, 24) * PAGE + rng.randrange(8))
                     for _ in range(rng.randrange(1, 8))]
            exclusions = [(rng.randrange(1, 160) * PAGE + rng.randrange(8),
                           rng.randrange(1, 8) * PAGE + rng.randrange(8))
                          for _ in range(rng.randrange(12))]
            blob = tree([memory(banks)], reservations=exclusions)
            if not pages(banks, False):
                self.assertEqual(self.parse(blob, good=False).error, 6)
            else:
                self.check_model(blob, banks, exclusions)


if __name__ == "__main__":
    unittest.main()
