#!/usr/bin/env bash
# One-shot RAM chainload using the owner's already-tested pinned stage 2.
# No ESP mounts, installed boot selectors, initramfs, SEP policy or disk writes.
set -euo pipefail
[[ $# == 3 && ( $1 == --check || $1 == --arm || $1 == --check-v3 || $1 == --arm-v3 || $1 == --check-v4 || $1 == --arm-v4 || $1 == --check-kernel || $1 == --arm-kernel || $1 == --check-memory || $1 == --arm-memory || $1 == --check-timer || $1 == --arm-timer || $1 == --check-sched || $1 == --arm-sched || $1 == --check-preempt || $1 == --arm-preempt || $1 == --check-user || $1 == --arm-user ) ]]
MODE=$1
VERSION=2
[[ $MODE != --check-v3 && $MODE != --arm-v3 ]] || VERSION=3
[[ $MODE != --check-v4 && $MODE != --arm-v4 ]] || VERSION=4
[[ $MODE != --check-kernel && $MODE != --arm-kernel ]] || VERSION=5
[[ $MODE != --check-memory && $MODE != --arm-memory ]] || VERSION=6
[[ $MODE != --check-timer && $MODE != --arm-timer ]] || VERSION=7
[[ $MODE != --check-sched && $MODE != --arm-sched ]] || VERSION=8
[[ $MODE != --check-preempt && $MODE != --arm-preempt ]] || VERSION=9
[[ $MODE != --check-user && $MODE != --arm-user ]] || VERSION=10
LABEL="V$VERSION"
[[ $VERSION != 5 ]] || LABEL="real-kernel checkpoint (profile 5)"
[[ $VERSION != 6 ]] || LABEL="owned-memory checkpoint (profile 6)"
[[ $VERSION != 7 ]] || LABEL="one-shot timer FIQ checkpoint (profile 7)"
[[ $VERSION != 8 ]] || LABEL="cooperative scheduler checkpoint (profile 8)"
[[ $VERSION != 9 ]] || LABEL="timer-driven preemption checkpoint (profile 9)"
[[ $VERSION != 10 ]] || LABEL="first EL0 isolation checkpoint (profile 10)"
LINUX=$(CDPATH= cd "$2" && pwd)
PYTHON="$(CDPATH= cd "$(dirname "$3")" && pwd)/$(basename "$3")"
[[ -x $PYTHON ]]
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
M1N1="$LINUX/.build/aurora/m1n1"
STAGE2="$LINUX/.build/dh-linux/m1n1-source"
DTB="$LINUX/.build/dh-linux/touch-id/bundle/t6030-j514s.dtb"
REV=ba130ffbeeadaa35215ed88b07ebcee3199d0be7
[[ $(git -C "$M1N1" rev-parse HEAD) == "$REV" ]]
[[ $(git -C "$STAGE2" rev-parse HEAD) == "$REV" ]]
PROFILE="$ROOT/build/appleprobe"
[[ $VERSION == 2 ]] || PROFILE="$ROOT/build/appleprobe-v$VERSION"
[[ $VERSION != 5 ]] || PROFILE="$ROOT/build/applekernel/shared-init-passed"
[[ $VERSION != 6 ]] || PROFILE="$ROOT/build/applememory/memory-passed"
[[ $VERSION != 7 ]] || PROFILE="$ROOT/build/appletimer/timer-passed"
[[ $VERSION != 8 ]] || PROFILE="$ROOT/build/applesched/scheduler-passed"
[[ $VERSION != 9 ]] || PROFILE="$ROOT/build/applepreempt/preemption-passed"
[[ $VERSION != 10 ]] || PROFILE="$ROOT/build/appleuser/userspace-passed"
RUN="$PROFILE/usb-$(date -u +%Y%m%dT%H%M%SZ)-$$"
umask 077
mkdir -p "$RUN"
python3 - "$PROFILE/Image" "$STAGE2/build/m1n1.bin" "$DTB" "$RUN" "$VERSION" <<'PY'
import hashlib
import gzip
import json
from pathlib import Path
import struct
import sys
image, stage2, dtb, run = map(Path, sys.argv[1:5])
version = int(sys.argv[5])
image_hashes = {
    2: "76a935a8383383c711ed9c96e845700f1f8e075d3da0982a758d050572723d11",
    3: "b0d2fa25c244bc3fa88a3e22064bfe2ef45827208ba62e9dc926bc8439fa0490",
    4: "7404c2c81565159e6546a0814efa350c667ee7ddcfbfb8098ce2d093a47912e3",
    5: "03f5b60d1fcc3e6926253aafc6b23ea2b1c73b10236de17e871aaebc7ee38a2e",
    6: "8982df1254bd3f2b729eefb6c7e3a8782fa7e4a303f0f59fc3b6e5be52e9b269",
    7: "69f81db8e7841d45ed0c8b018dcbaee19c85245235e62827ae983a854ebc30a7",
    8: "ef68539239d7d5be261471b81974e5c80719a99eb916ee719ff41a2b7d5f1edd",
    9: "9c8f1fffaf2967a8ce6bca5ee5ab80e91274396e3b026c1fae6e9e2a6aa8c0e9",
    10: "e357a443634b672ef0cfed1f4ac38e21dbcc893ec6f8518b2b8fceb222a19a18",
}
expected = (
    image_hashes[version],
    "59550fd89d026b27926ce785ca2390f01381a9aa2f480cd765ff3ce307bec2a0",
    "d57b0c45d4fbacc332f3c4984d24ed96594a64fc6a5d45f965979b470ea5c743",
)
parts = []
sources = []
for path, digest in zip((image, stage2, dtb), expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        sys.exit(f"Refusing changed/unqualified input: {path}")
    sources.append({"path": str(path), "sha256": digest, "bytes": len(data)})
    parts.append(data)
code, reserved, offset, size, flags = struct.unpack_from("<IIQQQ", parts[0])
assert code == 0x14000010 and reserved == offset == 0
assert flags == (0 if version == 2 else 2)
assert parts[0][56:64] == b"ARM\x64" + bytes(4)
assert len(parts[0]) <= size < (24 if version >= 5 else 2) * 1024 * 1024
assert struct.unpack_from(">I", parts[2])[0] == 0xd00dfeed
assert struct.unpack_from(">I", parts[2], 4)[0] == len(parts[2])
# An uncompressed final kernel payload is copied using header image_size,
# not the flat file length. Supply the BSS/stack padding explicitly.
kernel = parts[0] + bytes(size - len(parts[0]))
# The real kernel's padded footprint is larger than Stage 1's image window.
# Stage 2's existing gzip decoder allocates a fresh aligned destination. Keep
# Stage 1's live-heap overlap guard intact; compress only this explicit profile.
encoded_kernel = gzip.compress(kernel, compresslevel=9, mtime=0) if version >= 5 else kernel
assert (gzip.decompress(encoded_kernel) if version >= 5 else encoded_kernel) == kernel
# Keep DTB aligned after the raw stage 2; config follows it, then the Image.
# Disable automatic Linux graphics-driver admission; use only boot simplefb.
config = f"chosen.asahi,m3-defaults=0\nchosen.bootargs=aegis.appleprobe={version}\n".encode()
payload = parts[1] + parts[2] + config + encoded_kernel
(run / "payload.bin").write_bytes(payload)
(run / "manifest.json").write_text(json.dumps({
    "diagnostic_version": version,
    "profile": {5: "real-kernel-checkpoint", 6: "owned-memory-checkpoint",
                7: "one-shot-timer-fiq-checkpoint",
                8: "cooperative-scheduler-checkpoint",
                9: "timer-driven-preemption-checkpoint",
                10: "first-el0-isolation-checkpoint"}.get(version, "standalone-probe"),
    "m1n1_revision": "ba130ffbeeadaa35215ed88b07ebcee3199d0be7",
    "sources": sources, "config": config.decode(),
    "image_memory_bytes": size, "payload_bytes": len(payload),
    "kernel_encoding": "gzip" if version >= 5 else "raw",
    "kernel_encoded_bytes": len(encoded_kernel),
    "kernel_padded_sha256": hashlib.sha256(kernel).hexdigest(),
    "payload_sha256": hashlib.sha256(payload).hexdigest(),
}, indent=2) + "\n")
(run / "payload.sha256").write_text(
    hashlib.sha256(payload).hexdigest() + "  payload.bin\n")
PY
cp "$M1N1/LICENSE" "$RUN/LICENSE.m1n1"
[[ $VERSION -lt 5 ]] || cp "$ROOT/docs/licenses/qrcodegen.txt" "$RUN/LICENSE.qrcodegen"
export PATH="$ROOT/build/host-tools/root/usr/bin:$PATH"
export USE_CLANG=1 ARCH=aarch64-linux-gnu M1N1DEVICE=/dev/m1n1
export PYTHONUNBUFFERED=1 PYTHONPATH="$M1N1/proxyclient"
"$PYTHON" - <<'PY'
import asn1, construct, serial
from m1n1.asm import ARMAsm
assert ARMAsm("ret", 0x10000).data == bytes.fromhex("c0035fd6")
print("Offline Python/assembler check passed; no target requests sent.")
PY
(cd "$RUN"; sha256sum -c payload.sha256)
echo "Prepared RAM-only $LABEL (no injected fault): $RUN"
[[ $MODE != --check && $MODE != --check-v3 && $MODE != --check-v4 && $MODE != --check-kernel && $MODE != --check-memory && $MODE != --check-timer && $MODE != --check-sched && $MODE != --check-preempt && $MODE != --check-user ]] || exit 0
[[ $EUID == 0 ]]
exec 9>"$LINUX/.build/aurora/boot-test.lock"
flock --nonblock 9
WAIT_SECONDS=${M1N1_WAIT_SECONDS:-180}
[[ $WAIT_SECONDS =~ ^[0-9]+$ && $WAIT_SECONDS -ge 1 && $WAIT_SECONDS -le 600 ]]
echo "ARMED $LABEL: waiting up to $WAIT_SECONDS seconds for the existing Fedora USB-debug entry."
deadline=$((SECONDS + WAIT_SECONDS))
until [[ -e $M1N1DEVICE ]]; do
    ((SECONDS < deadline)) || { echo "Timed out; no target command sent." >&2; exit 1; }
    sleep 0.1
done
"$PYTHON" - <<'PY'
from m1n1.setup import p, u
assert p.get_chipid() == 0x6030
target = u.adt.target_type
if isinstance(target, bytes):
    target = target.rstrip(b"\0").decode("ascii")
assert target.lower() == "j514s"
assert u.ba.video.width == 3024
assert u.ba.video.height in (1890, 1964)
print("Connected target identity/boot-video checks passed.")
PY
(cd "$RUN"; sha256sum -c payload.sha256)
echo "Sending exactly one RAM chainload. No next-stage proxy probe will be sent."
# The diagnostic is not a USB proxy. Capture loader output without issuing
# the post-chainload nop used for a proxy-to-proxy reload.
exec "$PYTHON" "$M1N1/proxyclient/tools/chainload.py" \
    --raw --vector-only --capture "$RUN/console.bin" --capture-seconds 20 \
    "$RUN/payload.bin"
