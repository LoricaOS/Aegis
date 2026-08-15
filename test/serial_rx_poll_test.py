#!/usr/bin/env python3
"""Guard serial polling against absent or permanently-ready UARTs."""

from pathlib import Path


serial = (Path(__file__).resolve().parents[1] / "kernel/arch/x86_64/serial.c").read_text()
handler = serial.split("void serial_rx_handler(void)", 1)[1]

assert "n < SERIAL_RX_BUDGET" in handler
assert handler.index("lsr == 0xff") < handler.index("LSR_DATAREADY")

print("serial RX polling checks: ok")
