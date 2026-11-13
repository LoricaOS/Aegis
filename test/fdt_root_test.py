#!/usr/bin/env python3
"""Host checks of the real FDT root-identity reader; no hardware required."""
import ctypes
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def word(value):
    return struct.pack(">I", value)


def prop(value, name=0):
    return word(3) + word(len(value)) + word(name) + value + bytes(-len(value) % 4)


def blob(properties=b"", children=b"", suffix=None):
    tree = word(1) + bytes(4) + properties + children
    tree += word(2) + word(9) if suffix is None else suffix
    names = b"compatible\0model\0"
    # Header, reserve-map terminator, then aligned structure and strings.
    header = struct.pack(">10I", 0xd00dfeed, 56 + len(tree) + len(names),
                         56, 56 + len(tree), 40, 17, 16, 0, len(names), len(tree))
    return header + bytes(16) + tree + names


class RootIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        lib = Path(cls.tmp.name) / "fdt.so"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
            "-DFDT_HOSTTEST", str(ROOT / "kernel/arch/arm64/fdt.c"), "-o", str(lib),
        ], check=True)
        cls.fdt = ctypes.CDLL(str(lib))
        cls.fdt.fdt_ingest.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        cls.fdt.fdt_ingest.restype = ctypes.c_uint32
        cls.fdt.fdt_root_compatible.argtypes = [ctypes.c_char_p]
        cls.fdt.fdt_root_compatible.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def matches(self, data, wanted=b"apple,t6030"):
        source = ctypes.create_string_buffer(data)
        self.fdt.fdt_ingest(source, len(data))
        return bool(self.fdt.fdt_root_compatible(wanted))

    def test_model_and_soc_list(self):
        data = blob(prop(b"apple,j514s\0apple,t6030\0apple,arm-platform\0"))
        self.assertTrue(self.matches(data))
        self.assertTrue(self.matches(data, b"apple,j514s"))
        self.assertFalse(self.matches(data, b"apple,t603"))
        self.assertFalse(self.matches(data, b"apple,j516s"))

    def test_child_cannot_identify_machine(self):
        child = word(1) + b"gpu\0" + prop(b"apple,t6030\0") + word(2)
        self.assertFalse(self.matches(blob(prop(b"linux,dummy-virt\0"), child)))
        self.assertFalse(self.matches(blob(children=child)))

    def test_other_properties_and_nops(self):
        self.assertTrue(self.matches(blob(word(4) + prop(b"MacBook\0", 11) +
                                          prop(b"apple,t6030\0") + word(4))))

    def test_bad_lists_and_duplicate_properties(self):
        for value in (b"", b"\0", b"apple,t6030", b"apple,t6030\0truncated",
                      b"\0apple,t6030\0", b"apple,t6030\0\0"):
            with self.subTest(value=value):
                self.assertFalse(self.matches(blob(prop(value))))
        self.assertFalse(self.matches(blob(prop(b"apple,t6030\0") * 2)))

    def test_bad_bounds_tokens_and_names(self):
        for properties in (word(3) + word(0xfffffff0) + word(0),
                           prop(b"apple,t6030\0", 1000), word(123)):
            with self.subTest(properties=properties):
                self.assertFalse(self.matches(blob(properties)))
        self.assertFalse(self.matches(blob(prop(b"apple,t6030\0"), suffix=b"")))
        data = bytearray(blob(prop(b"apple,t6030\0")))
        data[60] = ord("x")              # nonempty root name
        self.assertFalse(self.matches(bytes(data)))

    def test_failed_ingest_does_not_reuse_old_identity(self):
        self.assertTrue(self.matches(blob(prop(b"apple,t6030\0"))))
        for data in (b"", bytes(40), blob()[:30]):
            self.assertFalse(self.matches(data))
        self.assertFalse(self.matches(blob(prop(b"apple,t6030\0")), b""))
        self.assertFalse(self.matches(blob(prop(b"apple,t6030\0")), None))

    def test_loader_expansion_and_bounded_capacity(self):
        # Exercise meaningful structure size, not just totalsize padding.
        # The live Mac tree was 211269 bytes; the old 128 KiB buffer rejected it.
        data = blob(prop(b"apple,t6030\0") + prop(bytes(220000), 11))
        self.assertTrue(self.matches(data))
        self.assertFalse(self.matches(blob(prop(bytes(530000), 11))))
        self.assertFalse(self.fdt.fdt_available())


if __name__ == "__main__":
    unittest.main()
