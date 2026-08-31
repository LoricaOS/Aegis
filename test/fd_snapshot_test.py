#!/usr/bin/env python3
"""Static regression checks for close-safe descriptor dispatch."""

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]
TABLE = (ROOT / "kernel/fs/fd_table.c").read_text()
IO = (ROOT / "kernel/syscall/sys_io.c").read_text()
POLL = (ROOT / "kernel/syscall/sys_poll.c").read_text()
EPOLL = (ROOT / "kernel/net/epoll.c").read_text()
WAITQ = (ROOT / "kernel/syscall/fd_waitq.c").read_text()
RAMFS = (ROOT / "kernel/fs/ramfs.c").read_text()
META = (ROOT / "kernel/syscall/sys_meta.c").read_text()
MEMORY = (ROOT / "kernel/syscall/sys_memory.c").read_text()
FILE = (ROOT / "kernel/syscall/sys_file.c").read_text()
SOCKET_SYSCALLS = (ROOT / "kernel/syscall/sys_socket.c").read_text()
SOCKET = (ROOT / "kernel/net/socket.c").read_text()
UNIX_SOCKET = (ROOT / "kernel/net/unix_socket.c").read_text()

pin_body = TABLE.split("fd_table_pin(fd_table_t", 1)[1].split("\n}\n", 1)[0]
assert "spin_lock_irqsave(&t->lock)" in pin_body
assert "file.ops->dup(file.priv)" in pin_body
assert pin_body.index("spin_lock_irqsave") < pin_body.index("file.ops->dup")
assert pin_body.index("file.ops->dup") < pin_body.index("spin_unlock_irqrestore")
assert "ops->close(priv);" in TABLE.split("fd_table_unpin", 1)[1]

for name in ("sys_write", "sys_writev", "sys_read", "sys_pread64", "sys_pwrite64"):
    body = re.search(rf"\n{name}\([^)]*\)\n\{{(.*?)(?=\n\}}\n)", IO, re.S)
    assert body, name
    text = body.group(1)
    assert "fd_table_pin(" in text, name
    assert "fd_table_unpin(" in text, name

assert "proc->fd_table->fds[pfd.fd]" not in POLL
assert "proc->fd_table->fds[pf[i].fd]" not in POLL
assert "fd_table_pin(proc->fd_table, (int)fd" in EPOLL
assert "fd_table_pin(proc->fd_table, fd, &out->file)" in WAITQ
assert ".dup     = ramfs_dup_fn" in RAMFS
assert ".dup     = ramfs_dir_dup_fn" in RAMFS

for name in ("sys_fchmod", "sys_fchown"):
    body = re.search(rf"\n{name}\([^)]*\)\n\{{(.*?)(?=\n\}}\n)", META, re.S)
    assert body, name
    text = body.group(1)
    assert "fd_table_pin(" in text, name
    assert "vfs_file_t *f = &pin.file" in text, name
    assert "fd_table_unpin(&pin)" in text, name

mmap = MEMORY.split("sys_mmap_impl(", 1)[1].split("\n}\n\nuint64_t\nsys_mmap", 1)[0]
assert "proc->fd_table->fds" not in mmap
assert "backing->kflags & VFS_KF_AUTH_GATED" in mmap
assert "g_rootfs->ino_of(backing->ops, backing->priv)" in mmap
assert "const vfs_file_t *f = backing" in mmap
assert "f->ops->read(f->priv" in mmap
mmap_entry = MEMORY.split("\nsys_mmap(uint64_t", 1)[1].split("\n}\n", 1)[0]
assert "fd_table_pin(" in mmap_entry
assert "fd_table_unpin(&pin)" in mmap_entry

assert "sock_id_from_fd(" not in SOCKET_SYSCALLS
assert "unix_sock_id_from_fd(" not in SOCKET_SYSCALLS
assert "cleanup(fd_table_unpin)" in SOCKET_SYSCALLS
assert "sock_id_from_file(&pin->file)" in SOCKET_SYSCALLS
assert "unix_sock_id_from_file(&pin->file)" in SOCKET_SYSCALLS
assert "sock_id_from_file(const vfs_file_t *file)" in SOCKET
assert "unix_sock_id_from_file(const vfs_file_t *file)" in UNIX_SOCKET
assert "f->kflags & VFS_KF_CAP_CONFINED" in SOCKET_SYSCALLS
assert "staged[count].file = *f;" in SOCKET_SYSCALLS
assert "vfs_file_t incoming = take[i].file;" in UNIX_SOCKET
for source, signature in (
    (SOCKET, "sock_open_fd(uint32_t sock_id"),
    (UNIX_SOCKET, "unix_sock_open_fd(uint32_t sock_id"),
):
    install = source.split(signature, 1)[1].split("\n}", 1)[0]
    assert "spin_lock_irqsave(&proc->fd_table->lock)" in install
    assert "proc->fd_table->fds" in install
    assert "spin_unlock_irqrestore(&proc->fd_table->lock" in install

pair_install = UNIX_SOCKET.split("unix_sock_open_pair_fds(", 1)[1].split("\n}", 1)[0]
assert "spin_lock_irqsave(&proc->fd_table->lock)" in pair_install
assert "proc->fd_table->fds[fd0] = file" in pair_install
assert "proc->fd_table->fds[fd1] = file" in pair_install

socketpair = SOCKET_SYSCALLS.split("sys_socketpair(uint64_t", 1)[1].split("\n}", 1)[0]
assert "unix_sock_open_pair_fds(" in socketpair
assert "copy_to_user(" in socketpair and "!= 0" in socketpair
assert "detach_unix_fd(" in socketpair
accept4 = SOCKET_SYSCALLS.split("sys_accept4(uint64_t", 1)[1].split("\n}", 1)[0]
assert "fd_table->fds" not in accept4
assert "return do_accept(fd, addr, addrlen, flags);" in accept4

for name in ("sys_ioctl", "sys_fcntl"):
    body = re.search(rf"\n{name}\([^)]*\)\n\{{(.*?)(?=\n\}}\n)", FILE, re.S)
    assert body, name
    text = body.group(1)
    assert "fd_table_pin(" in text, name
    assert "fd_table_update_flags(" in text, name
    assert "sock_id_from_fd(" not in text, name
    assert "unix_sock_id_from_fd(" not in text, name

ftruncate = MEMORY.split("sys_ftruncate(uint64_t", 1)[1].split("\n}", 1)[0]
assert "fd_table_pin(" in ftruncate
assert "pin.file.ops != &g_memfd_ops" in ftruncate
assert "pin.file.priv" in ftruncate
assert "proc->fd_table->fds" not in ftruncate

print("fd snapshot checks: ok")
