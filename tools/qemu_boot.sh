#!/usr/bin/env bash
# qemu_boot.sh — boot QEMU and stop it as soon as the guest has said the thing
# the caller is waiting for.
#
# Every harness here boots a kernel that HALTS when it is done — `panic_halt()`
# on the smoke ISOs, `[AEGIS] System halted.` at the end of the test suite — and
# QEMU then sits idle until `timeout` kills it. That made the test step almost
# entirely dead wait: measured on a 3-boot x86 run, the suite halts at guest
# t=11.3s but was given 40s, and each smoke boot prints its verdict at t=0.09s
# (under 1s of wall time) but was given 30s — ~87 of 101 seconds spent waiting
# for a timeout.
#
# So: run QEMU in the background with its serial log in a file, poll the log for
# the terminal line, and kill QEMU the moment it appears. The caller's
# QEMU_TIMEOUT stays as the CEILING, so a guest that really does hang is caught
# in the same time as before — the ceiling only has to cover a slow boot now,
# not a whole suite.
#
# The log is a plain file (not a pipe) so the caller can grep it after exit,
# exactly as before; `-serial stdio` writes it through unbuffered, so the
# sentinel is visible while QEMU is still running.
#
# Usage: qemu_boot.sh <logfile> <sentinel> <ceiling> -- <qemu> [args...]
# Exit:  0 = sentinel observed, 124 = ceiling reached, 1 = QEMU exited first.
set -u
LOG="${1:?usage: qemu_boot.sh <logfile> <sentinel> <ceiling> -- <qemu> [args...]}"
SENTINEL="${2:?missing sentinel}"
CEILING="${3:?missing ceiling}"
shift 3
[ "${1:-}" = "--" ] && shift

: > "$LOG"
"$@" </dev/null > "$LOG" 2>&1 &
qpid=$!

deadline=$(( $(date +%s) + CEILING ))
rc=1
while :; do
    if grep -qF -- "$SENTINEL" "$LOG" 2>/dev/null; then rc=0; break; fi
    kill -0 "$qpid" 2>/dev/null || break          # died on its own
    [ "$(date +%s)" -lt "$deadline" ] || { rc=124; break; }
    sleep 0.1
done

kill -9 "$qpid" 2>/dev/null || true
wait "$qpid" 2>/dev/null || true
exit "$rc"
