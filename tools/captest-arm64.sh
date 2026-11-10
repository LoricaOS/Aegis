#!/usr/bin/env bash
# Aegis arm64 capability/syscall test — the aarch64 twin of tools/captest.sh.
# Boots the test ISO (kernel + minimal rootfs with the aarch64 test-init as
# /bin/vigil) and checks the capability model holds at the syscall boundary.
set -u
ISO="${1:?usage: captest-arm64.sh <aegis-arm64-test.iso>}"
LOG="$(mktemp)"
FW="${QEMU_EFI:-}"
if [ -z "$FW" ]; then
    for f in /usr/share/AAVMF/AAVMF_CODE.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd; do
        [ -f "$f" ] && FW="$f" && break
    done
fi
[ -f "$FW" ] || { echo "[captest-arm64] FAIL: set QEMU_EFI to an AAVMF/QEMU_EFI firmware image"; exit 1; }

timeout "${QEMU_TIMEOUT:-150}" qemu-system-aarch64 -M virt,gic-version=3 -cpu cortex-a72 -smp 4 -m 2048M \
    -bios "$FW" \
    -cdrom "$ISO" \
    -object rng-random,id=rng0,filename=/dev/urandom \
    -global virtio-mmio.force-legacy=false \
    -device virtio-rng-device,rng=rng0 \
    -display none -nodefaults -serial stdio -no-reboot \
    </dev/null > "$LOG" 2>&1 || true

fails=$(grep -c "\[KTEST\] FAIL" "$LOG" || true)

# Match the x86 harness: the fixture must actually attempt both forbidden
# service grants, not merely lack them and pass the denial checks by default.
guards=0
grep -q "refusing service-tier DISK_ADMIN for /bin/exectest" "$LOG" && guards=$((guards+1))
grep -q "refusing service-tier ADMIN_AUTH for /bin/exectest" "$LOG" && guards=$((guards+1))
if [ "$guards" != 2 ]; then
    echo "[captest-arm64] FAIL: service-tier laundering guards did not fire ($guards/2)"
    cat "$LOG"
    rm -f "$LOG"
    exit 1
fi

for marker in \
    "independent child empty and admin-drop cannot regrant" \
    "admin SELF denied + invalid legacy selectors preserve caller/parent authority" \
    "vfork shared VM control and empty authority" \
    "fresh exec policy and persistent spawn ceilings + AT_SECURE" \
    "exit_group-blocked-sibling (unwound)" \
    "exit_group-from-thread (parent woken)" \
    "thread-zombie reap (slots returned)"
do
    if ! grep -Fq "[KTEST] PASS $marker" "$LOG"; then
        echo "[captest-arm64] FAIL: missing ring-3 regression: $marker"
        cat "$LOG"
        rm -f "$LOG"
        exit 1
    fi
done

if grep -q "\[KTEST\] DONE all-pass" "$LOG" &&
   grep -q "\[RNG\] OK: virtio-rng mixed" "$LOG" && [ "$fails" = 0 ]; then
    echo "[captest-arm64] PASS: kernel booted test-init; capability model enforced"
    grep "\[RNG\] OK: virtio-rng" "$LOG" | sed 's/^/  /'
    grep "\[KTEST\]" "$LOG" | sed 's/^/  /'
    rm -f "$LOG"
    exit 0
fi

echo "[captest-arm64] FAIL: test-init did not all-pass (FAIL lines: $fails)"
echo "----- [KTEST] lines + last 30 serial lines -----"
grep -E "\[KTEST\]|\[RNG\]" "$LOG" | sed 's/^/  /'
tail -30 "$LOG"
rm -f "$LOG"
exit 1
