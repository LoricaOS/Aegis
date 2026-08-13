#!/usr/bin/env python3
"""Focused source-level guard for descriptor lifetime regression fixes."""

from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
file_src = (root / "kernel/syscall/sys_file.c").read_text()
dir_src = (root / "kernel/syscall/sys_dir.c").read_text()
exec_src = (root / "kernel/syscall/sys_exec.c").read_text()


def body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^)]*\)\s*\{{", source)
    assert match, f"missing {name}"
    start = match.end()
    depth = 1
    pos = start
    while depth:
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
        pos += 1
    return source[start : pos - 1]


for function, source in (
    ("sys_fstat", file_src),
    ("sys_lseek", file_src),
    ("sys_getdents64", dir_src),
):
    text = body(source, function)
    assert "fd_table_pin(" in text, f"{function} must pin before callbacks"
    assert "fd_table_unpin(" in text, f"{function} must release its pin"

assert "fd_table_set_offset(" in body(file_src, "sys_lseek"), (
    "lseek must publish through the identity-checked table helper"
)
assert "fd_table_advance_offset(" in body(dir_src, "sys_getdents64"), (
    "getdents must publish through the identity-checked table helper"
)

dup_low = body(file_src, "fd_dup_lowest")
dup_exact = body(file_src, "fd_dup_exact")
for function, text in (("fd_dup_lowest", dup_low), ("fd_dup_exact", dup_exact)):
    lock = text.index("spin_lock_irqsave")
    ref = text.index("source.ops->dup(source.priv)")
    install = text.index("table->fds[newfd] = source")
    unlock = text.index("spin_unlock_irqrestore", install)
    assert lock < ref < install < unlock, (
        f"{function} must reference and install the source under one table lock"
    )

assert dup_exact.index("source.ops->dup(source.priv)") < dup_exact.index(
    "replaced_ops  = table->fds[newfd].ops"
), "dup2 must retain the source before detaching an aliasing target"

dup3 = body(file_src, "sys_dup3")
assert "flags & ~0x80000ULL" in dup3, "dup3 must reject unsupported flags"
assert "fd_dup_exact" in dup3, "dup3 CLOEXEC installation must be atomic"

open_body = body(file_src, "sys_open")
open_build = open_body.index("vfs_file_t opened")
open_lock = open_body.index("spin_lock_irqsave(&proc->fd_table->lock)", open_build)
open_install = open_body.index("proc->fd_table->fds[fd] = opened", open_lock)
open_unlock = open_body.index("spin_unlock_irqrestore", open_install)
assert open_build < open_lock < open_install < open_unlock
assert open_body.index("opened.kflags", open_build) < open_lock
assert open_body.index("opened.flags", open_build) < open_lock
assert open_body.index("opened.ops->close(opened.priv)", open_unlock) > open_unlock

pipe2 = body(file_src, "sys_pipe2")
pipe_lock = pipe2.index("spin_lock_irqsave(&proc->fd_table->lock)")
read_install = pipe2.index("proc->fd_table->fds[rfd] = read_end")
write_install = pipe2.index("proc->fd_table->fds[wfd] = write_end")
pipe_unlock = pipe2.index("spin_unlock_irqrestore", write_install)
assert pipe_lock < read_install < write_install < pipe_unlock
assert pipe2.index("g_pipe_read_ops.close(p)", pipe_unlock) > pipe_unlock
assert pipe2.index("g_pipe_write_ops.close(p)", pipe_unlock) > pipe_unlock

execve = body(exec_src, "sys_execve")
cloexec = execve.split("Close all O_CLOEXEC", 1)[1].split(
    "Redirect return to new ELF", 1
)[0]
assert "spin_lock_irqsave(&proc->fd_table->lock)" in cloexec
assert cloexec.index("__builtin_memset(slot") < cloexec.index(
    "spin_unlock_irqrestore"
) < cloexec.index("ops->close(priv)")

spawn = body(exec_src, "sys_spawn")
stdio = spawn.split("File descriptor table", 1)[1].split(
    "Add child to scheduler", 1
)[0]
parent_lock = stdio.index("spin_lock_irqsave(&parent->fd_table->lock)")
first_ref = stdio.index("source.ops->dup(source.priv)")
parent_unlock = stdio.index("spin_unlock_irqrestore(&parent->fd_table->lock")
child_install = stdio.index("child->fd_table->fds[fd_i] = source")
assert parent_lock < first_ref < parent_unlock < child_install

print("fd lifetime static checks: PASS")
