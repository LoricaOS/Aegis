#!/usr/bin/env python3
"""Static regression guard for /dev/audio descriptor reference lifetime."""

from pathlib import Path
import re


source = (Path(__file__).resolve().parents[1] / "kernel/fs/initrd.c").read_text()


def body(name: str) -> str:
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


ops = source.split("static const vfs_ops_t s_audio_ops", 1)[1].split("};", 1)[0]
assert ".dup     = audio_ref_fn" in ops

open_body = body("initrd_open")
assert "e->file == &s_audio_file" in open_body
assert "audio_ref_fn(out->priv)" in open_body

close_body = body("audio_close_fn")
assert close_body.index("s_audio_refs--") < close_body.index("s_audio_refs != 0")
assert close_body.index("s_audio_refs != 0") < close_body.index("hda_audio_close()")
assert "spin_lock_irqsave(&s_audio_ref_lock)" in close_body
assert close_body.rindex("spin_unlock_irqrestore") > close_body.index("hda_audio_close()")

print("audio lifetime static checks: PASS")
