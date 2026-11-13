#!/usr/bin/env python3
"""Execute the diagnostic on synthetic QEMU RAM, not Apple hardware.

Uses a test-only entry stub to supply x0, fake board identity and a RAM pixel
arena. Checks relocated execution and every framebuffer byte, including guards.
No disks, network devices, firmware blobs or Mac access are used.
"""
import argparse
import array
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
DTB = 0x43000000
ARENA = 0x44000000
WIDTH, HEIGHT, STRIDE = 320, 160, 1280
GUARD = 64
SIZE = STRIDE * HEIGHT
SYMBOLS = {}


def symbols_for(build):
    if build not in SYMBOLS:
        text = subprocess.check_output(
            [os.environ.get("NM", "aarch64-linux-gnu-nm"), str(build / "probe.elf")],
            text=True)
        SYMBOLS[build] = {
            fields[2]: int(fields[0], 16) for line in text.splitlines()
            if len(fields := line.split()) == 3
        }
    return SYMBOLS[build]


def tree(path, board, fmt, base, width=WIDTH, height=HEIGHT, stride=STRIDE,
         size=SIZE, status="okay", duplicate=False):
    framebuffer = f"""
        framebuffer@{base:x} {{
            compatible = "apple,simple-framebuffer", "simple-framebuffer";
            reg = <{base >> 32} {base & 0xffffffff} {size >> 32} {size & 0xffffffff}>;
            width = <{width}>; height = <{height}>; stride = <{stride}>;
            format = "{fmt}"; status = "{status}";
        }};
"""
    if duplicate:
        framebuffer += framebuffer.replace("framebuffer@", "second-framebuffer@")
    path.write_text(f"""/dts-v1/;
/ {{
    compatible = "{board}", "apple,t6030";
    #address-cells = <2>; #size-cells = <2>;
    memory@40000000 {{
        device_type = "memory";
        reg = <0 0x40000000 0 0x10000000 0x100 0x01fac000 4 0x59488000>;
    }};
    chosen {{
        #address-cells = <2>; #size-cells = <2>;
        {framebuffer}
    }};
}};
""")


def check_panel(pixels, original, width, height, stride, white, qr=False, qr_modules=97):
    assert pixels[:GUARD] == original[:GUARD]
    assert pixels[-GUARD:] == original[-GUARD:]
    pw, ph = min(width - 32, 1400), min(height - 32, 1100)
    if qr:
        # Only the explicit bridge may paint the separately bounded QR box.
        # Its actual contents are decoded independently by apple_kernel_test.
        x0, extent, zoom = 16 + pw + 32, qr_modules + 8, 8
        while zoom >= 2 and (extent * zoom > width - 16 - x0 or extent * zoom > ph):
            zoom -= 1
        if zoom >= 2:
            baseline = bytearray(original)
            for y in range(16, 16 + extent * zoom):
                left = GUARD + y * stride + x0 * 4
                right = left + extent * zoom * 4
                values = array.array("I", pixels[left:right])
                assert all(v in (0, white) for v in values), "invalid QR pixel"
                baseline[left:right] = pixels[left:right]
            original = baseline
    lit = 0
    for y in range(height):
        start = GUARD + y * stride
        row = pixels[start:start + stride]
        before = original[start:start + stride]
        if 16 <= y < 16 + ph:
            left, right = 16 * 4, (16 + pw) * 4
            assert row[:left] == before[:left] and row[right:] == before[right:]
            values = array.array("I", row[left:right])
            if os.sys.byteorder != "little":
                values.byteswap()
            assert all(v in (0, white) for v in values), "bad format or out-of-panel store"
            lit += sum(v == white for v in values)
        else:
            assert row == before, "store outside console panel"
    assert lit > 0, "no text was drawn"
    # The first visible character is A in both the normal and fault console.
    scale = 4 if width >= 1600 and height >= 900 else 1
    for y, mask in enumerate((14, 17, 17, 31, 17, 17, 17)):
        for x in range(5):
            value = struct.unpack_from("<I", pixels,
                GUARD + (16 + y * scale) * stride + (16 + x * scale) * 4)[0]
            assert value == (white if mask & (1 << (4 - x)) else 0)


def write_preview(pixels, width, height, stride, white, path):
    """Grayscale PNG of actual QEMU console pixels; no imaging dependency."""
    pw, ph = min(width - 32, 1400), min(height - 32, 1100)
    rows = bytearray()
    for y in range(ph):
        start = GUARD + (y + 16) * stride + 16 * 4
        values = array.array("I", pixels[start:start + pw * 4])
        if os.sys.byteorder != "little":
            values.byteswap()
        rows.append(0)
        rows.extend(255 if v == white else 0 for v in values)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + \
            struct.pack(">I", zlib.crc32(kind + data))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" +
        chunk(b"IHDR", struct.pack(">IIBBBBB", pw, ph, 8, 0, 0, 0, 0)) +
        chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def run_case(image_base, board="apple,j514s", fmt="x2r10g10b10", fb_base=None,
             stage=5, build=None, fault=0, el2=False, preview=None, version=2,
             post_check=None, dtb_address=DTB, arena_address=ARENA,
             sparse_high_ram=False, prepare_tree=None, cpu="cortex-a72",
             ready=None, bridge=False, prepare_entry=None, gic_version=None,
             qr_modules=97, **geometry):
    build = build or BUILD
    syms = symbols_for(build)
    if fault:
        stage = 255
    if fb_base is None:
        fb_base = arena_address + GUARD
    with tempfile.TemporaryDirectory(prefix="aegis-probe-") as tmp:
        tmp = Path(tmp)
        tree(tmp / "test.dts", board, fmt, fb_base, **geometry)
        if prepare_tree:
            prepare_tree(tmp / "test.dts")
        subprocess.run(["dtc", "-I", "dts", "-O", "dtb", "-o",
                        str(tmp / "test.dtb"), str(tmp / "test.dts")], check=True)
        # ldr x0, literal; ldr x1, literal; br x1; nop; DTB; image address.
        (tmp / "entry.bin").write_bytes(struct.pack(
            "<IIIIQQ", 0x58000080, 0x580000a1, 0xd61f0020, 0xd503201f, dtb_address, image_base))
        if prepare_entry:
            prepare_entry(tmp, dtb_address, image_base, el2)
        painted = stage in (5, 8, 10, 11, 255)
        arena_size = geometry.get("size", SIZE) if painted else SIZE
        arena_stride = geometry.get("stride", STRIDE) if painted else STRIDE
        original = bytes([0xa5]) * (arena_size + 2 * GUARD)
        (tmp / "arena.bin").write_bytes(original)
        qmp_path = tmp / "qmp"
        machine = "virt,virtualization=on" if el2 else "virt"
        if gic_version is not None:
            machine += f",gic-version={gic_version}"
        args = [
            "qemu-system-aarch64", "-machine",
            machine, "-cpu", cpu,
            "-m", "1026G" if sparse_high_ram else "256M",
            "-nodefaults", "-display", "none", "-serial", "none",
            "-monitor", "none", "-S", "-no-reboot",
            "-qmp", f"unix:{qmp_path},server=on,wait=off",
            "-device", f"loader,file={tmp / 'entry.bin'},addr=0x40100000,force-raw=on,cpu-num=0",
            "-device", f"loader,file={build / 'Image'},addr={image_base},force-raw=on",
            "-device", f"loader,file={tmp / 'test.dtb'},addr={dtb_address},force-raw=on",
            "-device", f"loader,file={tmp / 'arena.bin'},addr={arena_address},force-raw=on",
        ]
        if sparse_high_ram:
            # Anonymous, demand-backed RAM; explicitly do not reserve/preallocate
            # a TiB of host memory. No ACPI hotplug or firmware dependency.
            args[2] += ",memory-backend=high"
            args += ["-object", "memory-backend-ram,id=high,size=1026G,reserve=off"]
        with (tmp / "qemu.log").open("w+") as log:
            proc = subprocess.Popen(args, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + (45 if bridge else 10)
                sock = socket.socket(socket.AF_UNIX)
                sock.settimeout(5)
                while True:
                    try:
                        sock.connect(str(qmp_path))
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        if time.monotonic() > deadline or proc.poll() is not None:
                            log.seek(0)
                            raise AssertionError(log.read())
                        time.sleep(0.02)
                with sock, sock.makefile("rwb", buffering=0) as wire:
                    assert "QMP" in json.loads(wire.readline())

                    def command(name, **arguments):
                        wire.write(json.dumps({"execute": name, "arguments": arguments}).encode() + b"\n")
                        while True:
                            reply = json.loads(wire.readline())
                            if "event" not in reply:
                                assert "return" in reply, reply
                                return reply["return"]

                    command("qmp_capabilities")
                    command("cont")
                    while True:
                        command("pmemsave", val=image_base + syms["apple_probe_report"], size=72,
                                filename=str(tmp / "report"))
                        report = struct.unpack("<9Q", (tmp / "report").read_bytes())
                        if report[0] == stage and (ready is None or ready(command, tmp, syms)):
                            break
                        if time.monotonic() > deadline:
                            command("stop")
                            command("pmemsave", val=image_base + syms["apple_probe_console_text"],
                                    size=8192, filename=str(tmp / "timeout-text"))
                            print((tmp / "timeout-text").read_bytes().split(b"\0", 1)[0].decode())
                            raise AssertionError(f"entry did not reach stage {stage}: {report}")
                        time.sleep(0.02)
                    command("stop")
                    command("pmemsave", val=arena_address, size=len(original),
                            filename=str(tmp / "pixels"))
                    pixels = (tmp / "pixels").read_bytes()
                    assert report[1] == (2 if el2 else 1) and report[4] == dtb_address, report
                    if painted:
                        check_panel(pixels, original, geometry.get("width", WIDTH),
                                    geometry.get("height", HEIGHT), arena_stride,
                                    0x3fffffff if fmt == "x2r10g10b10" else 0xffffff,
                                    qr=bridge, qr_modules=qr_modules)
                        command("pmemsave", val=image_base + syms["apple_probe_console_text"],
                                size=8192, filename=str(tmp / "text"))
                        text = (tmp / "text").read_bytes().split(b"\0", 1)[0].decode("ascii")
                        if bridge:
                            assert "AEGIS APPLE KERNEL BRIDGE - PREPARING EL1\n" in text
                            assert "AEGIS V3" not in text
                        else:
                            assert f"AEGIS NATIVE ENTRY DIAGNOSTIC V{version}\n" in text
                        assert f"EL=0X{report[1]:016X}\n" in text
                        assert f"MMFR0=0X{report[3]:016X}\n" in text
                        assert f"IMAGE=0X{image_base:016X}\n" in text
                        assert "RAM 0X0000010001FAC000 SIZE 0X0000000459488000\n" in text
                        assert "RESERVATIONS NOT RECLAIMED - NO ALLOCATOR\n" in text
                        assert report[5] == image_base and report[8] == 2
                        if fault:
                            command("pmemsave", val=image_base + syms["apple_probe_fault_report"],
                                    size=72, filename=str(tmp / "fault"))
                            captured = struct.unpack("<9Q", (tmp / "fault").read_bytes())
                            valid, vector, el, esr, elr, far, spsr, sp, boot_stage = captured
                            assert valid == 1 and vector == 4 and el == report[1], captured
                            assert (esr >> 26) == (0x25 if fault == 2 else 0x3c), captured
                            assert elr == image_base + syms["apple_probe_test_fault"], captured
                            assert spsr & 0xc0 == 0xc0 and boot_stage == 5
                            if fault == 3:
                                assert sp == 0, captured
                            else:
                                assert image_base + syms["apple_probe_stack_bottom"] <= sp < \
                                    image_base + syms["apple_probe_end"], captured
                            if fault == 2:
                                assert far == 0xfffffffffffff000
                            else:
                                assert esr & 0xffff == (0x43 if fault == 3 else 0x41)
                            assert "AEGIS FATAL EXCEPTION\n" in text
                            assert f"ELR=0X{elr:016X}\n" in text
                        elif not post_check:
                            assert "FATAL EXCEPTION" not in text
                        if post_check:
                            post_check(command, tmp, syms, report, text)
                        if preview:
                            write_preview(pixels, geometry.get("width", WIDTH),
                                          geometry.get("height", HEIGHT), arena_stride,
                                          0x3fffffff if fmt == "x2r10g10b10" else 0xffffff,
                                          preview)
                            preview.with_suffix(".txt").write_text(text)
                    else:
                        assert pixels == original, "rejected input changed pixel arena"
                    print(f"PASS base={image_base:#x} format={fmt} stage={stage} incoming_EL={report[1]} fault={fault}")
            except Exception:
                log.seek(0)
                print(log.read())
                raise
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build/appleprobe")
    parser.add_argument("--brk", type=Path, required=True)
    parser.add_argument("--abort", type=Path, required=True)
    parser.add_argument("--badsp", type=Path, required=True)
    parser.add_argument("--preview", type=Path)
    args = parser.parse_args()
    BUILD = args.build.resolve()
    image = (BUILD / "Image").read_bytes()
    code, reserved, offset, size, flags = struct.unpack_from("<IIQQQ", image)
    assert code == 0x14000010 and reserved == offset == flags == 0
    assert image[56:64] == b"ARM\x64" + bytes(4)
    assert len(image) <= size < 2 * 1024 * 1024
    run_case(0x40200000)
    run_case(0x41200000)
    run_case(0x40200000, fmt="x8r8g8b8")
    # Live boot geometry, but still fake QEMU RAM and no Apple display driver.
    run_case(0x40200000, width=3024, height=1890, stride=12096, size=22861440,
             preview=args.preview)
    run_case(0x40200000, board="linux,dummy-virt", stage=2)
    run_case(0x40200000, fmt="unsupported", stage=3)
    run_case(0x40200000, fb_base=0x40200000, stage=3)
    for invalid in (
        {"width": 0}, {"width": 8193}, {"height": 0}, {"stride": 1276},
        {"stride": 1281}, {"size": SIZE - 1}, {"status": "disabled"},
        {"duplicate": True}, {"fb_base": 0}, {"fb_base": 0xfffffffffffffff0},
    ):
        run_case(0x40200000, stage=3, **invalid)
    run_case(0x41200000, el2=True)
    for el2 in (False, True):
        run_case(0x41200000, build=args.brk.resolve(), fault=1, el2=el2)
        run_case(0x41200000, build=args.abort.resolve(), fault=2, el2=el2)
        run_case(0x41200000, build=args.badsp.resolve(), fault=3, el2=el2)
    # A native-sized fault preview also checks that the fatal console remains
    # legible after the longer startup report.
    run_case(0x41200000, build=args.abort.resolve(), fault=2, el2=True,
             width=3024, height=1890, stride=12096, size=22861440,
             preview=args.preview.with_name("fault-preview.png") if args.preview else None)
