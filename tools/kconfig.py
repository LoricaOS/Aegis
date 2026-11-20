"""Public Kconfig backend for the build when kconf is not installed."""

import os
import sys
from pathlib import Path

try:
    import kconfiglib
except ImportError:
    sys.exit("Kconfig requires kconf or kconfiglib. Install kconfiglib in a "
             "Python 3 environment and set PYTHON to its interpreter (see README.md).")


def main():
    mode, *args, source = sys.argv[1:]
    config = os.environ.get("KCONFIG_CONFIG", ".config")
    kconf = kconfiglib.Kconfig(source)

    if mode == "defconfig":
        kconf.load_config(args[0])
    elif mode in ("allnoconfig", "allyesconfig"):
        enable = 2 if mode == "allyesconfig" else 0
        for sym in kconf.unique_defined_syms:
            if sym.orig_type in (kconfiglib.BOOL, kconfiglib.TRISTATE):
                sym.set_value(enable if enable else sym.is_allnoconfig_y * 2)
        kconf.load_allconfig(mode)
    elif mode in ("oldconfig", "syncconfig"):
        kconf.load_config(config)
    else:
        sys.exit(f"Unsupported Kconfig operation: {mode}")

    if mode != "syncconfig":
        kconf.write_config(config)
        return

    header = Path(os.environ["KCONFIG_AUTOHEADER"])
    make_vars = Path(os.environ["KCONFIG_AUTOCONF"])
    kconf.write_autoconf(str(header))
    kconf.write_config(str(make_vars), save_old=False)
    # kconfiglib skips identical writes. Mark both outputs current so make
    # doesn't keep regenerating them after a Kconfig prerequisite changes.
    header.touch()
    make_vars.touch()


if __name__ == "__main__":
    main()
