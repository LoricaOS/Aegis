#!/usr/bin/env python3
"""Static regression guard for atomic descriptor-slot installation."""

from pathlib import Path
import re


root = Path(__file__).resolve().parents[1]


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


for path, function in (
    ("kernel/fs/eventfd.c", "sys_eventfd2"),
    ("kernel/fs/memfd.c", "memfd_open_fd"),
    ("kernel/net/epoll.c", "epoll_open_fd"),
):
    text = body((root / path).read_text(), function)
    build = text.index("vfs_file_t file = {")
    lock = text.index("spin_lock_irqsave(&proc->fd_table->lock)")
    find = text.index("!proc->fd_table->fds[fd].ops") if "[fd]" in text else text.index("!proc->fd_table->fds[i].ops")
    install = text.index("= file;", find)
    unlock = text.index("spin_unlock_irqrestore(&proc->fd_table->lock", install)
    assert build < lock < find < install < unlock, function

eventfd = body((root / "kernel/fs/eventfd.c").read_text(), "sys_eventfd2")
assert eventfd.index("spin_unlock_irqrestore", eventfd.index("= file;")) < eventfd.index("return (uint64_t)fd")
assert "eventfd_close_fn(e);" in eventfd

print("fd install static checks: PASS")
