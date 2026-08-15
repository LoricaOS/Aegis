#!/usr/bin/env python3
"""Guard the bare-metal x86 INIT-SIPI-SIPI startup contract."""

from pathlib import Path


root = Path(__file__).resolve().parents[1]
lapic = (root / "kernel/arch/x86_64/lapic.c").read_text()
smp = (root / "kernel/arch/x86_64/smp.c").read_text()

assert lapic.index("0x0000C500") < lapic.index("0x00008500")
assert lapic.index("0x00008500") < lapic.index("0x00004600 | vector")
assert "lapic_startup_delay_us(10000)" in lapic
assert "lapic_startup_delay_us(300)" in lapic
assert "started[MAX_CPUS]" not in smp
assert "lapic_start_ap(apic_id, 0x08)" in smp
poll = smp.split("while (!g_ap_online[i]", 1)[1].split("if (g_ap_online[i])", 1)[0]
assert "tlb_poll_incoming();" in poll

print("x86 SMP startup checks: ok")
