#!/usr/bin/env python3
"""Host protocol checks and real EL1 guest execution under a test-only EL2 stub.

QEMU validates the guest/BRK protocol, not Apple HV firmware or USB transport.
No disk, network, Apple firmware or attached target is used.
"""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("apple_debug", ROOT / "tools/apple-debug-usb.py")
debug = importlib.util.module_from_spec(spec)
spec.loader.exec_module(debug)
BUILD = ROOT / "build/appledebug"
SYMS = debug.symbols(BUILD / "guest.elf")
ESR = (0x3c << 26) | (1 << 25) | 0x4242
REPORT = struct.pack("<4Q", 2, 4, 5, 0x30d00800)


class ProtocolTests(unittest.TestCase):
    def session(self, text=debug.MESSAGE, report=REPORT):
        self.reads, self.saved = [], {}

        def read(offset, count):
            self.reads.append((offset, count))
            return text if offset == SYMS["debug_transport_message"] else report

        return debug.Session(SYMS, read, self.saved.__setitem__)

    def event(self, phase):
        if phase == 0:
            return [ESR, debug.IPA + SYMS["debug_transport_log_trap"],
                    [1, debug.IPA + SYMS["debug_transport_message"], len(debug.MESSAGE)]]
        return [ESR, debug.IPA + SYMS["debug_transport_exit_trap"],
                [2, debug.IPA + debug.PAGE, 32]]

    def test_complete_and_extra_event(self):
        session = self.session()
        self.assertFalse(session.event(*self.event(0)))
        self.assertTrue(session.event(*self.event(1)))
        self.assertEqual(self.saved, {"guest-console.txt": debug.MESSAGE,
                                     "guest-report.bin": REPORT})
        with self.assertRaises(ValueError):
            session.event(*self.event(1))
        self.assertEqual(len(self.reads), 2)

    def test_reject_before_read(self):
        for phase in (0, 1):
            for field in range(5):
                with self.subTest(phase=phase, field=field):
                    session = self.session()
                    if phase:
                        session.event(*self.event(0))
                    self.reads.clear()
                    esr, pc, regs = self.event(phase)
                    if field == 0:
                        esr ^= 1
                    elif field == 1:
                        pc += 4
                    else:
                        regs[field - 2] += 1
                    with self.assertRaises(ValueError):
                        session.event(esr, pc, regs)
                    self.assertEqual(self.reads, [])
        session = self.session()
        with self.assertRaises(ValueError):
            session.event(*self.event(1))
        self.assertEqual(self.reads, [])

    def test_reject_wrong_exception_class(self):
        session = self.session()
        _, pc, regs = self.event(0)
        with self.assertRaises(ValueError):
            session.event((0x24 << 26) | 0x4242, pc, regs)
        self.assertEqual(self.reads, [])

    def test_reject_message(self):
        session = self.session(text=b"x" * len(debug.MESSAGE))
        with self.assertRaises(ValueError):
            session.event(*self.event(0))
        self.assertEqual(self.saved, {})

    def test_reject_report(self):
        for stage, el, sctlr in ((1, 4, 0), (2, 8, 0), (2, 4, 1),
                                 (2, 4, 4), (2, 4, 0x1000)):
            with self.subTest(stage=stage, el=el, sctlr=sctlr):
                session = self.session(report=struct.pack("<4Q", stage, el, 5, sctlr))
                session.event(*self.event(0))
                with self.assertRaises(ValueError):
                    session.event(*self.event(1))
                self.assertNotIn("guest-report.bin", self.saved)

    def test_layout(self):
        image = (BUILD / "guest.bin").read_bytes()
        self.assertEqual(len(image), debug.PAGE + 32)
        self.assertEqual(SYMS["debug_transport_start"], 0)
        self.assertEqual(SYMS["debug_transport_report"], debug.PAGE)
        self.assertEqual(image[debug.PAGE:], bytes(32))
        start = SYMS["debug_transport_message"]
        self.assertEqual(image[start:start + len(debug.MESSAGE)], debug.MESSAGE)
        reloc = subprocess.check_output(
            ["aarch64-linux-gnu-readelf", "-r", str(BUILD / "guest.elf")], text=True)
        self.assertIn("There are no relocations", reloc)


def qemu_guest():
    with tempfile.TemporaryDirectory(prefix="aegis-debug-") as directory:
        tmp = Path(directory)
        # Test-only monitor: trap two EL1 BRKs, record raw ESR/PC/x0..2,
        # resume after the first and park at EL2 after the second.
        (tmp / "monitor.S").write_text("""
.text
.global _start
_start:
    mov x12, #0x41000000
    mov sp, x12
    adr x12, vectors
    msr vbar_el2, x12
    mov x12, #0x80000000
    msr hcr_el2, x12
    mov x12, #0x100
    msr mdcr_el2, x12
    ldr x12, =0x30d00800
    msr sctlr_el1, x12
    mov x12, #0x80000000
    msr elr_el2, x12
    mov x12, #0x3c5
    msr spsr_el2, x12
    isb
    eret
.balign 2048
vectors:
.rept 8
    b failed
    .balign 128
.endr
    b synchronous
    .balign 128
.rept 7
    b failed
    .balign 128
.endr
synchronous:
    adr x12, records
    ldr x13, [x12, #80]
    cmp x13, #2
    b.hs failed
    mov x14, #40
    madd x14, x13, x14, x12
    mrs x15, esr_el2
    mrs x16, elr_el2
    stp x15, x16, [x14]
    stp x0, x1, [x14, #16]
    str x2, [x14, #32]
    add x13, x13, #1
    str x13, [x12, #80]
    cmp x13, #2
    b.eq parked
    add x16, x16, #4
    msr elr_el2, x16
    eret
failed:
    adr x12, records
    mov x13, #255
    str x13, [x12, #80]
parked:
    dsb sy
    wfe
    b parked
.balign 8
.global records
records:
    .zero 88
""")
        subprocess.run(["aarch64-linux-gnu-gcc", "-c", str(tmp / "monitor.S"),
                        "-o", str(tmp / "monitor.o")], check=True)
        subprocess.run(["aarch64-linux-gnu-ld", "-Ttext=0x40200000",
                        str(tmp / "monitor.o"), "-o", str(tmp / "monitor.elf")], check=True)
        subprocess.run(["aarch64-linux-gnu-objcopy", "-O", "binary",
                        str(tmp / "monitor.elf"), str(tmp / "monitor.bin")], check=True)
        records = debug.symbols(tmp / "monitor.elf")["records"]
        args = ["qemu-system-aarch64", "-machine", "virt,virtualization=on",
                "-cpu", "cortex-a72", "-m", "2G", "-nodefaults", "-display", "none",
                "-serial", "none", "-monitor", "none", "-S", "-no-reboot",
                "-qmp", f"unix:{tmp / 'qmp'},server=on,wait=off",
                "-device", f"loader,file={tmp / 'monitor.bin'},addr=0x40200000,cpu-num=0,force-raw=on",
                "-device", f"loader,file={BUILD / 'guest.bin'},addr={debug.IPA},force-raw=on"]
        with (tmp / "qemu.log").open("w+") as log:
            proc = subprocess.Popen(args, stdout=log, stderr=log)
            sock = socket.socket(socket.AF_UNIX)
            sock.settimeout(5)
            try:
                deadline = time.monotonic() + 10
                while not (tmp / "qmp").exists():
                    if proc.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("QEMU failed to open QMP")
                    time.sleep(0.02)
                sock.connect(str(tmp / "qmp"))
                stream = sock.makefile("rwb")
                json.loads(stream.readline())

                def command(name, **arguments):
                    stream.write((json.dumps({"execute": name, "arguments": arguments}) + "\n").encode())
                    stream.flush()
                    while True:
                        response = json.loads(stream.readline())
                        if "error" in response:
                            raise RuntimeError(response)
                        if "return" in response:
                            return response["return"]

                def read(address, count):
                    command("pmemsave", val=address, size=count, filename=str(tmp / "read.bin"))
                    return (tmp / "read.bin").read_bytes()

                command("qmp_capabilities")
                command("cont")
                while True:
                    count, = struct.unpack("<Q", read(records + 80, 8))
                    if count >= 2:
                        break
                    if time.monotonic() > deadline:
                        raise TimeoutError("guest did not complete two traps")
                    time.sleep(0.02)
                command("stop")
                assert count == 2, count
                captured = struct.unpack("<10Q", read(records, 80))
                saved = {}
                session = debug.Session(SYMS, lambda off, n: read(debug.IPA + off, n),
                                        saved.__setitem__)
                assert not session.event(captured[0], captured[1], captured[2:5])
                assert session.event(captured[5], captured[6], captured[7:10])
                report = read(debug.IPA + debug.PAGE, 32)
                assert saved["guest-report.bin"] == report
                print("QEMU EL1 execution: two BRKs, exact fixed log, completed RAM report:",
                      debug.validate_report(report))
                stream.close()
            finally:
                sock.close()
                proc.terminate()
                proc.wait(timeout=5)
                if proc.returncode not in (0, -15):
                    log.seek(0)
                    print(log.read())


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    qemu_guest()
