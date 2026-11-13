#!/usr/bin/env python3
"""Decode the exact packaged kernel with the pinned stage-2 gzip implementation.

Host-only: builds upstream tinf sources without modifying/copying them into
the project. No target requests, firmware blobs, disk or boot-entry operations.
"""
import argparse
import ctypes as C
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("linux", type=Path)
parser.add_argument("run", type=Path)
args = parser.parse_args()
monitor = args.linux.resolve() / ".build/aurora/m1n1"
revision = subprocess.check_output(
    ["git", "-C", str(monitor), "rev-parse", "HEAD"], text=True).strip()
assert revision == "ba130ffbeeadaa35215ed88b07ebcee3199d0be7"
manifest = json.loads((args.run / "manifest.json").read_bytes())
assert manifest["kernel_encoding"] == "gzip" and manifest["diagnostic_version"] in (5, 6, 7, 8, 9, 10)
payload = (args.run / "payload.bin").read_bytes()
assert hashlib.sha256(payload).hexdigest() == manifest["payload_sha256"]
offset = sum(source["bytes"] for source in manifest["sources"][1:]) + len(manifest["config"].encode())
compressed = payload[offset:]
assert len(compressed) == manifest["kernel_encoded_bytes"]
image = Path(manifest["sources"][0]["path"]).read_bytes()
assert hashlib.sha256(image).hexdigest() == manifest["sources"][0]["sha256"]
expected = image + bytes(manifest["image_memory_bytes"] - len(image))
assert gzip.decompress(compressed) == expected
assert hashlib.sha256(expected).hexdigest() == manifest["kernel_padded_sha256"]

with tempfile.TemporaryDirectory(prefix="aegis-tinf-") as directory:
    library = Path(directory) / "tinf.so"
    source = monitor / "src/tinf"
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                    *(str(source / name) for name in ("tinfgzip.c", "tinflate.c", "crc32.c")),
                    "-o", str(library)], check=True)
    decode = C.CDLL(str(library)).tinf_gzip_uncompress
    decode.argtypes = [C.c_void_p, C.POINTER(C.c_uint), C.c_void_p, C.POINTER(C.c_uint)]
    decode.restype = C.c_int
    for known_size in (False, True):
        # Stage 2 scans inline payloads with source length zero. Also check
        # bounded decoding, consumed length, and untouched destination guards.
        data = C.create_string_buffer(compressed + bytes(4))
        output = C.create_string_buffer(bytes([0xa5]) * (len(expected) + 64))
        size = C.c_uint(len(expected))
        consumed = C.c_uint(len(compressed) if known_size else 0)
        assert decode(output, C.byref(size), data, C.byref(consumed)) == 0
        assert size.value == len(expected) and consumed.value == len(compressed)
        assert output.raw[:len(expected)] == expected
        assert output.raw[len(expected):len(expected) + 64] == bytes([0xa5]) * 64
    print(f"PASS: pinned tinf restores all {len(expected):#x} Image bytes from "
          f"{len(compressed):#x} gzip bytes; both source-length modes and guards checked")
    print(f"Packed Stage 1 transfer: {len(payload):#x} bytes; no overlap guard changed")
