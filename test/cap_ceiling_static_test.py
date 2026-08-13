#!/usr/bin/env python3
"""Static guard for one-way cap-mask attenuation at admin elevation."""

from pathlib import Path

source = (Path(__file__).resolve().parents[1] /
          "kernel/syscall/sys_cap.c").read_text()
function = source.split("sys_admin_session(uint64_t on)", 1)[1].split(
    "sys_install_commit", 1
)[0]

drop = function.index("if (!on)")
drop_return = function.index("return 0;", drop)
ceiling_reject = function.index("parent->cap_ceiling_active")
elevate = function.index("parent->admin_session = 1u")

# Dropping authority must remain reachable regardless of the ceiling.
assert drop < drop_return < ceiling_reject
# Elevation must reject an attenuated target before either direct-authority
# session flag is written.
assert ceiling_reject < elevate
condition = function[function.rfind("if (", 0, ceiling_reject):elevate]
assert "return SYS_ERR(EPERM)" in condition

print("cap ceiling admin-session checks: PASS")
