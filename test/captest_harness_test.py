#!/usr/bin/env python3
"""Check both real boot harnesses reject missing evidence without running QEMU."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
MARKERS = (
    "independent child empty and admin-drop cannot regrant",
    "admin SELF denied + invalid legacy selectors preserve caller/parent authority",
    "vfork shared VM control and empty authority",
    "fresh exec policy and persistent spawn ceilings + AT_SECURE",
    "exit_group-blocked-sibling (unwound)",
    "exit_group-from-thread (parent woken)",
    "thread-zombie reap (slots returned)",
)
GUARDS = (
    "[CAP_POLICY] refusing service-tier DISK_ADMIN for /bin/exectest",
    "[CAP_POLICY] refusing service-tier ADMIN_AUTH for /bin/exectest",
)
DONE = "[KTEST] DONE all-pass"


with tempfile.TemporaryDirectory(prefix="aegis-captest-harness-") as tmp:
    tmp = Path(tmp)
    timeout = tmp / "timeout"
    # Replace only the VM invocation. The actual shell harness parses its
    # captured log, including all success and failure conditions.
    timeout.write_text('#!/bin/sh\nexec cat "$CAPTEST_FIXTURE"\n')
    timeout.chmod(0o755)
    firmware = tmp / "firmware.fd"
    firmware.touch()
    fixture = tmp / "serial.log"
    env = dict(os.environ, PATH=f"{tmp}{os.pathsep}{os.environ['PATH']}",
               TMPDIR=str(tmp), QEMU_EFI=str(firmware),
               CAPTEST_FIXTURE=str(fixture))
    cases = 0
    for script, readiness in (
        ("tools/captest.sh", "[NET6] OK"),
        ("tools/captest-arm64.sh", "[RNG] OK: virtio-rng mixed 64 bytes"),
    ):
        lines = [*GUARDS, *(f"[KTEST] PASS {m}" for m in MARKERS),
                 readiness, DONE]
        variants = [("complete evidence", lines, True)]
        variants += [(f"missing {line}", [s for s in lines if s != line], False)
                     for line in lines]
        variants.append(("explicit failed test", [*lines, "[KTEST] FAIL example"], False))
        for label, content, success in variants:
            fixture.write_text("\n".join(content) + "\n")
            result = subprocess.run(
                ["bash", str(ROOT / script), "unused-test.iso"],
                env=env, cwd=ROOT, capture_output=True, text=True, timeout=5,
            )
            if (result.returncode == 0) != success:
                raise AssertionError(
                    f"{script}: {label}: exit {result.returncode}\n"
                    f"{result.stdout}{result.stderr}"
                )
            cases += 1
    print(f"captest harness: {cases} cross-architecture evidence checks passed")
