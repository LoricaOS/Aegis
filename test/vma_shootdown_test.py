#!/usr/bin/env python3
"""Guard VMA-operation waits against SMP TLB-shootdown deadlock."""

from pathlib import Path

src = (Path(__file__).resolve().parents[1] / "kernel/mm/vma.c").read_text()
body = src.split("irqflags_t vma_op_lock", 1)[1].split("void vma_op_unlock", 1)[0]

assert "spin_trylock" in body
assert "tlb_poll_incoming();" in body
assert body.index("spin_trylock") < body.index("tlb_poll_incoming();")

print("VMA/TLB shootdown lock check: PASS")
