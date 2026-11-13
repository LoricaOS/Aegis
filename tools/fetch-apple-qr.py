#!/usr/bin/env python3
"""Fetch pinned MIT-licensed Nayuki QR sources into ignored build output."""
import hashlib
import os
from pathlib import Path
import tempfile
import urllib.request

REV = "bcfe1b018cec5f1f91b5705eca5bb4cdd34e9f8d"
FILES = {
    "qrcodegen.c": "6a2b9cc65176f2345dde260c74b6d352627e8a0a6385d086ae0e9c5d0913c70c",
    "qrcodegen.h": "e82df4bff37d18b5863b9e7486fe6bda1b6cda8c3b9ecebfec473907265cb589",
}
out = Path("build/applekernel/qr")
out.mkdir(parents=True, exist_ok=True)


def write(path, data):
    # Loader and kernel submakes may fetch concurrently. Readers must only
    # ever see complete, hash-checked public source files.
    with tempfile.NamedTemporaryFile(dir=out, delete=False) as temporary:
        temporary.write(data)
        name = temporary.name
    os.chmod(name, 0o644)
    os.replace(name, path)


for name, digest in FILES.items():
    path = out / name
    data = path.read_bytes() if path.exists() else b""
    if hashlib.sha256(data).hexdigest() != digest:
        with urllib.request.urlopen(
            f"https://raw.githubusercontent.com/nayuki/QR-Code-generator/{REV}/c/{name}",
            timeout=30,
        ) as response:
            data = response.read(128 * 1024)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"QR source hash mismatch: {name}")
        write(path, data)
source = (out / "qrcodegen.c").read_text()
for header in ("assert.h", "limits.h", "stdlib.h", "string.h"):
    include = f"#include <{header}>"
    assert source.count(include) == 1
    source = source.replace(include, "")
source = ('/* Freestanding include adapter; upstream algorithms and MIT notice unchanged. */\n'
          '#include "qr_compat.h"\n' + source)
adapted = out / "qrcodegen.freestanding.c"
if not adapted.exists() or adapted.read_text() != source:
    write(adapted, source.encode())
