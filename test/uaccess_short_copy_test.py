#!/usr/bin/env python3
"""Static regression check for fail-closed fault-contained user copies."""

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = (ROOT / "kernel/mm/uaccess_user.h").read_text()
POLL = (ROOT / "kernel/syscall/sys_poll.c").read_text()
DIR = (ROOT / "kernel/syscall/sys_dir.c").read_text()

# The fixed-size wrappers must reject a non-zero residual from the underlying
# fault-contained copy, not merely rely on the preceding page-table walk.
assert re.search(r"if \(copy_from_user\(.*?\) != 0\).*?EFAULT", HEADER, re.S)
assert re.search(r"if \(copy_to_user\(.*?\) != 0\).*?EFAULT", HEADER, re.S)
assert re.search(r"return copy_from_user\(.*?\) == 0;", HEADER, re.S)
assert re.search(r"return copy_to_user\(.*?\) == 0;", HEADER, re.S)

# sys_poll/select can block between validation and access. Every direct copy in
# this translation unit therefore has to consume the residual. A bare call at
# statement level is the vulnerable form.
ignored = re.findall(r"(?m)^\s*copy_(?:from|to)_user\s*\(", POLL)
assert not ignored, f"sys_poll.c has {len(ignored)} ignored user-copy result(s)"

# getdents must commit its record and descriptor offset only after a complete
# copy. On a fault it returns EFAULT before any record, or the prior short count.
getdents = DIR.split("sys_getdents64(", 1)[1].split("\n}\n", 1)[0]
copy_check = getdents.index("if (copy_to_user(")
written_commit = getdents.index("written += reclen")
offset_commit = getdents.index("next_offset++")
assert copy_check < written_commit < offset_commit
assert "copy_fault && written == 0" in getdents
assert "fd_table_unpin(&pin)" in getdents
assert not re.findall(r"(?m)^\s*copy_to_user\s*\(", getdents)

print("uaccess short-copy checks: ok")
