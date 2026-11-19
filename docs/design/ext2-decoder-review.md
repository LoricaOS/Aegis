# ext2 decoder review

Two focused reviews of the ext2 on-disk structure decoder, split into directory
entries/path resolution and inode/block-mapping/mount metadata. Input model: the
filesystem image is untrusted — it is boot media or an OS-shipped root image,
or a volume a raw writer can change. `ext2` is mounted once, at boot, as root;
there is no runtime mount of an ext2 image.

## Result

**No memory-safety defect in either half.** Every on-disk-derived index is
bounded, every read is bounded, and each failure path fails closed. Under
crafted images, UBSan reported nothing.

The defects that were found are logic and API-width, all fixed in 1.6.1:

| Area | Defect | Consequence |
|---|---|---|
| Directory scan | `ext2_descends_from` bounded its 32-bit cursor with raw `i_size`; above `0xFFFFF000` with no `..` entry the cursor wrapped to 0 and the scan restarted under `ext2_lock` | Whole filesystem stopped making progress |
| File size | `file_size` was `int`; inodes of 2 GiB or more came back negative and callers clamped to 0 | Append wrote from offset 0, `SEEK_END` returned 0, stat failed, lazy mmap zero-filled |
| Block mapping | An unreadable indirect pointer block returned the same 0 as a hole | Read errors delivered as 4096 zero bytes |
| Path creation | The parent resolver never required a directory | A directory entry written into a regular file; inode leaked |

## Would a Rust rewrite have prevented these?

**No.** The cursor wrap is defined behaviour in Rust release builds (`u32`
arithmetic wraps), and a straight port reproduces it; the missing parent-type
check and the `int` return type are logic and API-width, which the type system
does not see. Rust would help with the memory-side class — indexing a shared
4 KiB buffer instead of raw pointer arithmetic — which the C already handles via
a load-bearing inode-size check and a recursive lock discipline.

So the Rust migration of this decoder is a structural-safety investment, not a
remediation. Nothing here argues for haste.

## Deliberately not fixed in 1.6.1

- **`ext2_write` maps blocks through the hole-tolerant path**, so an unreadable
  indirect pointer block is read as "no block" and the allocator can take an
already-mapped position. Same root cause as the read fix, different call site.
  Writes should probably fail closed there too.
- **`..` is trusted from the on-disk entry.** A modified image can point `..`
  out of a confined subtree, so a capability-confined directory descriptor can
  reach outside its root. The walker validates `..` only at the confinement
  root. Resolving `..` from the walked parent, or requiring it to match the
  inode the walk descended from, would close it — a behaviour change worth its
  own change.
- **`ext2_mount` accepts images whose group descriptors are unusable** (root
  inode is not read at mount), so a dead root filesystem surfaces on first use
  rather than at mount.
- **Group-count arithmetic overflows** for `s_blocks_count` near 2^32, yielding
  a mount with zero groups.
- **`ext2_free_inode_blocks`** walks up to ~1M entries under `ext2_lock` for a
  crafted double-indirect inode — bounded, but tens of milliseconds of stalled
  filesystem.

## Coverage

Regression tests: `test/fs_security_test.py` (crafted directory scan, unreadable
indirect block, hole semantics), `test/ext2_parent_type_test.py` (parent type,
unchanged file contents after a rejected creation), `test/ext2_filesize_test.py`
(wide sizes through the VFS open/stat/append paths). Each was checked by undoing
the fix and confirming the test fails.
