#!/usr/bin/env python3
"""Record fixed diagnostic ELF PCs for narrowly validated fault recovery."""
from pathlib import Path
import subprocess
import sys

build = Path(sys.argv[1])
symbols = {}
for line in subprocess.check_output(["aarch64-linux-gnu-nm", str(build / "user.elf")],
                                    text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        symbols[fields[2]] = int(fields[0], 16)
names = ("_start", "user_svc_pid", "user_svc_uid", "user_svc_uname",
         "user_svc_badptr", "user_svc_socket", "user_kernel_read",
         "user_text_write", "user_nx_resume", "user_done", "user_fail")
data = "".join(f"#define APPLE_USER_{name.upper().lstrip('_')} 0x{symbols[name]:x}ULL\n"
               for name in names).encode()
assert all(0x400000 <= symbols[name] < 0x401000 for name in names)
path = build / "apple_user_layout.h"
if not path.exists() or path.read_bytes() != data:
    path.write_bytes(data)
