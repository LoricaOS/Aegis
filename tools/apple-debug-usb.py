#!/usr/bin/env python3
"""Explicit, debug-only resident-m1n1 USB experiment. --check sends no requests."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REVISION = "ba130ffbeeadaa35215ed88b07ebcee3199d0be7"
IPA, PAGE, REGION = 0x80000000, 0x4000, 0xc000
MESSAGE = b"AEGIS DEBUG: resident m1n1 USB transport\n"
IMAGE_SHA256 = "c8f35b7dd54e6662196b8a791b2a7ab56ed9c3893771799527437f4ebb13a20d"


class Session:
    """Two fixed messages, not a guest-chosen host-memory read primitive."""
    def __init__(self, symbols, read, save):
        self.symbols, self.read, self.save = symbols, read, save
        self.phase = 0
        self.failed = False

    def event(self, esr, pc, regs):
        if esr >> 26 != 0x3c or esr & 0xffff != 0x4242:
            raise ValueError("unexpected guest exception")
        if self.phase == 0:
            expected = (IPA + self.symbols["debug_transport_log_trap"], 1,
                        IPA + self.symbols["debug_transport_message"], len(MESSAGE))
        elif self.phase == 1:
            expected = (IPA + self.symbols["debug_transport_exit_trap"], 2,
                        IPA + PAGE, 32)
        else:
            raise ValueError("unexpected extra guest event")
        if (pc, *regs[:3]) != expected:
            raise ValueError("guest message address, length, order or PC mismatch")
        if self.phase == 0:
            text = self.read(self.symbols["debug_transport_message"], len(MESSAGE))
            if text != MESSAGE:
                raise ValueError("guest message mismatch")
            self.save("guest-console.txt", text)
            print(text.decode("ascii"), end="", flush=True)
        else:
            report = self.read(PAGE, 32)
            validate_report(report)
            self.save("guest-report.bin", report)
        self.phase += 1
        return self.phase == 2


def validate_report(report):
    stage, el, mmfr0, sctlr = struct.unpack("<4Q", report)
    if stage != 2 or el != 4 or sctlr & 0x1005:
        raise ValueError("guest did not complete with EL1/MMU/cache-off state")
    return {"stage": stage, "el": el >> 2, "mmfr0": hex(mmfr0), "sctlr": hex(sctlr)}


def symbols(path):
    text = subprocess.check_output(["aarch64-linux-gnu-nm", "-n", str(path)], text=True)
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3:
            result[parts[2]] = int(parts[0], 16)
    return result


def run(args):
    monitor = args.linux.resolve() / ".build/aurora/m1n1"
    rev = subprocess.check_output(["git", "-C", str(monitor), "rev-parse", "HEAD"],
                                  text=True).strip()
    if rev != REVISION:
        raise ValueError("unqualified proxyclient revision")
    build = ROOT / "build/appledebug"
    image = (build / "guest.bin").read_bytes()
    if hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("unqualified debug image")
    syms = symbols(build / "guest.elf")
    if len(image) != PAGE + 32 or syms["debug_transport_report"] != PAGE:
        raise ValueError("unexpected debug layout")
    os.environ.setdefault("USE_CLANG", "1")
    os.environ.setdefault("ARCH", "aarch64-linux-gnu")
    os.environ.setdefault("M1N1DEVICE", "/dev/m1n1")
    # No setup module, UartInterface instance or target requests in --check.
    sys.path.insert(0, str(monitor / "proxyclient"))
    from m1n1.proxy import M1N1Proxy, UartInterface, START, EXC, EXC_RET, ExcInfo
    from m1n1.proxyutils import ProxyUtils, bootstrap_port
    from m1n1.sysreg import SCTLR_EL12, MDCR_EL2, HCR_EL2
    from m1n1.asm import ARMAsm
    if ARMAsm("ret", 0x10000).data != bytes.fromhex("c0035fd6"):
        raise ValueError("proxy assembler check failed")
    print("Offline debug image/proxy/assembler checks passed; no target requests sent.", flush=True)
    if not args.arm:
        return
    if os.geteuid() != 0:
        raise ValueError("--arm requires root for the established debug device/lock")
    if not 1 <= args.wait <= 600:
        raise ValueError("wait must be 1..600 seconds")
    with (args.linux / ".build/aurora/boot-test.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_dir = build / f"usb-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
        run_dir.mkdir(mode=0o700)
        def save(name, data):
            (run_dir / name).write_bytes(data)
        save("manifest.json", (json.dumps({
            "mode": "resident-monitor-transport-only", "proxyclient_revision": rev,
            "image_sha256": IMAGE_SHA256, "guest_ipa": hex(IPA),
            "guest_region_bytes": REGION, "firmware": "existing USB-debug entry; not replaced",
        }, indent=2) + "\n").encode())
        deadline = time.monotonic() + args.wait
        print(f"ARMED DEBUG: waiting {args.wait}s for Fedora USB-debug entry.", flush=True)
        while not Path("/dev/m1n1").exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("no debug device; no target request sent")
            time.sleep(0.1)
        iface = UartInterface()
        p = M1N1Proxy(iface)
        bootstrap_port(iface, p)
        u = ProxyUtils(p, heap_size=16 * 1024 * 1024)
        target = u.adt.target_type
        if isinstance(target, bytes):
            target = target.rstrip(b"\0").decode("ascii")
        if p.get_chipid() != 0x6030 or target.lower() != "j514s":
            raise ValueError("unexpected target; refusing HV init")
        print("J514s/T6030 identified. Initializing resident monitor.", flush=True)
        active = p.iodev_whoami()
        from m1n1.proxy import IODEV
        for device in IODEV:
            if device >= IODEV.USB0 and device != active:
                p.iodev_set_usage(device, 0)
        p.hv_init()
        # Use the monitor's real allocator, not an unreserved physical address.
        physical = p.memalign(PAGE, REGION)
        if not physical or physical % PAGE:
            raise ValueError("monitor allocation failed")
        p.memset8(physical, 0, REGION)
        iface.writemem(physical, image)
        if iface.readmem(physical, len(image)) != image:
            raise ValueError("guest upload readback mismatch")
        # Guest data accesses are uncached. Publish to PoC and discard host
        # cache copies before entry, rather than cleaning only to PoU.
        p.dc_civac(physical, REGION)
        p.ic_ivau(physical, PAGE)
        # Three pages only: RO executable code, RW/XN report and stack.
        attrs = (1 << 10) | (3 << 8) | (15 << 2) | 1
        for offset, flags in ((0, 1 << 6), (PAGE, (3 << 6) | (1 << 54)),
                              (2 * PAGE, (3 << 6) | (1 << 54))):
            p.hv_map(IPA + offset, (physical + offset) | attrs | flags, PAGE, 1)
            # The monitor walker strips bits 13:2 from hardware leaves.
            # Verify PA, hardware-page type and upper attributes (including XN).
            # hv_translate cannot do this: it returns the IPA with stage 1 off.
            expected = (physical + offset) | (flags & ~0x3ffc) | 3
            if p.hv_pt_walk(IPA + offset) != expected:
                raise ValueError("stage-2 mapping readback failed")
        # Guest EL1 stage 1 stays off; debug BRKs route to resident EL2.
        u.msr(SCTLR_EL12, 0x30d00800)
        u.msr(MDCR_EL2, (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11))
        hcr = u.mrs(HCR_EL2)
        u.msr(HCR_EL2, (hcr | (1 << 3)) & ~(1 << 4))  # FMO on, IMO off

        def read_guest(offset, count):
            if offset == PAGE:
                # No host writes after upload; discard stale copies of data
                # written by the cache-off guest before reading its report.
                p.dc_ivac(physical + PAGE, PAGE)
            return iface.readmem(physical + offset, count)

        session = Session(syms, read_guest, save)

        def exception(reason, code, info):
            ctx = None
            try:
                if reason != START.EXCEPTION_LOWER or code != EXC.SYNC:
                    raise ValueError("unexpected monitor event")
                ctx = ExcInfo.parse(iface.readmem(info, ExcInfo.sizeof()))
                done = session.event(ctx.esr.value, ctx.elr, ctx.regs)
                if not done:
                    ctx.elr += 4
                    iface.writemem(info, ExcInfo.build(ctx))
                result = EXC_RET.EXIT_GUEST if done else EXC_RET.HANDLED
            except Exception as error:
                session.failed = True
                save("failure.txt", (repr(error) + "\n").encode())
                if ctx is not None:
                    save("exception.bin", ExcInfo.build(ctx))
                result = EXC_RET.EXIT_GUEST
            # A transport failure here must not trigger a second exit request.
            p.exit(result)

        for reason in (START.EXCEPTION_LOWER, START.EXCEPTION):
            for code in EXC:
                iface.set_handler(reason, code, exception)
        # m1n1 HV event IDs 1..7; unexpected events exit rather than open a shell.
        for code in range(1, 8):
            iface.set_handler(START.HV, code, exception)
        iface.dev.timeout = 15
        print(f"Starting isolated EL1 debug guest. Evidence: {run_dir}", flush=True)
        p.hv_start(IPA, 0, 0, 0, 0)
        if session.failed or session.phase != 2:
            raise ValueError(f"debug guest failed; inspect {run_dir}")
        report = read_guest(PAGE, 32)
        if report != (run_dir / "guest-report.bin").read_bytes():
            raise ValueError("report changed after guest exit")
        p.nop()
        save("result.json", (json.dumps(validate_report(report), indent=2) + "\n").encode())
        # Keep the guest region reserved until power-off; no reuse after failed
        # or incompletely joined sessions. No retry, reset or fallback boot.
        print("PASS: USB message + RAM report + return to responsive m1n1 proxy.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--arm", action="store_true")
    parser.add_argument("linux", type=Path)
    parser.add_argument("--wait", type=int, default=600)
    args = parser.parse_args()
    os.umask(0o077)
    run(args)
