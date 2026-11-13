#!/usr/bin/env python3
"""Host tests of the diagnostic's real bounded page-table builder."""
import ctypes as C
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PAGE, MASK = 4096, 0x0000fffffffff000
AF, RO, PXN, UXN = 1 << 10, 1 << 7, 1 << 53, 1 << 54
NORMAL = AF | (3 << 8) | UXN
DEVICE = AF | (2 << 8) | (1 << 2) | PXN | UXN


class Request(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in (
        "image", "text_end", "ro_end", "image_end", "dtb", "dtb_size",
        "fb", "fb_size", "mmfr0", "table_base")]


class Result(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ("root", "tcr", "mair", "tables", "pages")]


class MapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        lib = Path(cls.tmp.name) / "tables.so"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
            str(ROOT / "kernel/arch/arm64/apple/probe_mmu.c"), "-o", str(lib),
        ], check=True)
        cls.lib = C.CDLL(str(lib))
        cls.lib.probe_map_build.argtypes = [C.POINTER(Request), C.POINTER(Result)]
        cls.lib.probe_map_pool.restype = C.POINTER(C.c_uint64)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def request(self):
        base = 0x10008000000
        return Request(base, base + 0x8000, base + 0xc000, base + 0x100000,
                       base + 0x101230, 211269, 0x104600a2880, 22861440,
                       0x110012120f100003, base + 0x20000)

    def leaves(self, q, r):
        pool, leaves, seen = self.lib.probe_map_pool(), {}, set()

        def walk(page, level, prefix):
            self.assertNotIn(page, seen)
            seen.add(page)
            self.assertLess(page, r.tables)
            for i in range(512):
                value = pool[page * 512 + i]
                if not value:
                    continue
                self.assertEqual(value & 3, 3)  # no block or invalid descriptors
                va = prefix | (i << (39 - level * 9))
                if level < 3:
                    child = value & MASK
                    self.assertGreaterEqual(child, q.table_base)
                    walk((child - q.table_base) // PAGE, level + 1, va)
                else:
                    self.assertEqual(value & MASK, va)
                    leaves[va] = value & ~MASK

        walk(0, 0, 0)
        self.assertEqual(len(seen), r.tables)
        self.assertLessEqual(r.tables, 48)
        return leaves

    def check_map(self, q):
        r = Result()
        self.assertEqual(self.lib.probe_map_build(C.byref(q), C.byref(r)), 1)
        actual = self.leaves(q, r)
        expected = {}
        for base, end, attrs in (
            (q.image, q.text_end, NORMAL | RO),
            (q.text_end, q.ro_end, NORMAL | RO | PXN),
            (q.ro_end, q.image_end, NORMAL | PXN),
            (q.dtb, q.dtb + q.dtb_size, NORMAL | RO | PXN),
            (q.fb, q.fb + q.fb_size, DEVICE),
        ):
            for address in range(base & -PAGE, (end + PAGE - 1) & -PAGE, PAGE):
                expected[address] = attrs | 3
        self.assertEqual(actual, expected)  # no whole-RAM or unrelated mappings
        self.assertEqual(r.pages, len(expected))
        self.assertEqual(r.root, q.table_base)
        self.assertEqual((r.tcr >> 32) & 7, q.mmfr0 & 15)
        self.assertEqual(r.tcr & 63, 16)
        self.assertEqual((r.tcr >> 8) & 15, 0)  # noncacheable walks
        self.assertTrue(r.tcr & (1 << 23))       # TTBR1 disabled
        self.assertEqual(r.mair, 0x44)
        self.assertNotIn(0, actual)
        self.assertNotIn(0x10001fac000, actual)  # advertised RAM is not mapped
        for attrs in actual.values():
            self.assertFalse(attrs & (1 << 6))  # no EL0 authority
            self.assertTrue(attrs & UXN)
            self.assertTrue((attrs & RO) or (attrs & PXN))
        return actual

    def test_high_physical_addresses_and_exact_permissions(self):
        self.check_map(self.request())

    def test_rebuild_does_not_retain_old_mappings(self):
        q = self.request()
        old = self.check_map(q)
        q.fb += 0x10000000
        new = self.check_map(q)
        self.assertNotIn(0x104600a2000, new)
        self.assertNotEqual(old, new)

    def test_maximum_framebuffer_and_padded_dtb(self):
        q = self.request()
        q.fb_size = 64 * 1024 * 1024
        q.dtb_size = 2 * 1024 * 1024
        self.check_map(q)

    def test_rejects_invalid_requests_and_clears_result(self):
        cases = (
            ("mmfr0", 0xf0000003), ("mmfr0", 6), ("mmfr0", 0x20000003),
            ("image", 0), ("image", self.request().image + 4096),
            ("text_end", self.request().text_end + 1),
            ("ro_end", self.request().image),
            ("table_base", self.request().image),
            ("table_base", self.request().image_end - PAGE),
            ("table_base", self.request().table_base + 1),
            ("dtb", 0), ("dtb_size", 0), ("fb_size", 0),
            ("fb", self.request().image),
            ("fb", 0xfffffffffffffff0),
            ("fb_size", 64 * 1024 * 1024 + 1),
            ("dtb_size", 2 * 1024 * 1024 + 1),
            ("fb", 1 << 42),
        )
        for name, value in cases:
            with self.subTest(name=name, value=value):
                q = self.request()
                setattr(q, name, value)
                r = Result(1, 2, 3, 4, 5)
                self.assertEqual(self.lib.probe_map_build(C.byref(q), C.byref(r)), 0)
                self.assertEqual(list(bytes(r)), [0] * C.sizeof(r))
        self.assertEqual(self.lib.probe_map_build(None, None), 0)

    def test_disjoint_bytes_cannot_share_conflicting_page_attributes(self):
        q = self.request()
        q.dtb, q.dtb_size, q.fb, q.fb_size = 0x2001001, 16, 0x2001100, 16
        r = Result()
        self.assertEqual(self.lib.probe_map_build(C.byref(q), C.byref(r)), 0)
        self.assertEqual(r.root, 0)


if __name__ == "__main__":
    unittest.main()
