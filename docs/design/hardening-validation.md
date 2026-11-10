# Hardening validation

Status: full kernel builds and QEMU test targets passed for x86-64 and
AArch64. This is kernel/test-fixture validation, not LoricaOS integration
approval. Nothing was published.

## Environment

- Host: macOS, ARM64.
- Cross compilers: `x86_64-elf-gcc` and `aarch64-elf-gcc`, both GCC 16.2.0.
- Cross binutils: 2.47; NASM 3.02; GNU Make 4.4.1.
- QEMU: 11.0.2.
- Limine: the repository's pinned `v11.4.1-binary`.
- Configuration: `configs/full_defconfig`, generated with kconfiglib 14.1.0
  using the same procedure as `.github/workflows/build.yml`.

The missing host tools were obtained from checksum-verified public Homebrew
bottles and staged under ignored `build/local-tools/`. No global packages
were installed. That local staging directory is disposable, not a supported
or automatically replicated toolchain distribution.

## Commands and results

With the required tools on `PATH`, configuration was generated as follows:

```sh
python3 -m venv build/local-tools/kconfig-venv
build/local-tools/kconfig-venv/bin/pip install kconfiglib==14.1.0
mkdir -p build/generated
build/local-tools/kconfig-venv/bin/python - <<'PY'
import kconfiglib
kc = kconfiglib.Kconfig("Kconfig", warn_to_stderr=False)
kc.load_config("configs/full_defconfig")
kc.write_config(".config")
kc.write_config("build/auto.conf")
kc.write_autoconf("build/generated/autoconf.h")
PY
touch .config build/auto.conf build/generated/autoconf.h
```

This substitutes CI's public configuration generator for the unavailable
private `kconf` tool. It does not validate `kconf` itself.

### x86-64

```sh
make -j4
make test
make dist
```

All passed. The test target booted the freestanding test init with four
virtual CPUs and required `[KTEST] DONE all-pass`, the IPv6 initialization
marker, both service-tier privilege-laundering refusals, and seven specific
authority/lifecycle regression markers.

Both kernel-only smoke ISOs passed:

- Limine protocol.
- Multiboot2 protocol.

The expected smoke endpoint is the no-init panic; it is not a failed boot.

### AArch64

```sh
make -f Makefile.arm64 \
    CC=aarch64-elf-gcc LD=aarch64-elf-ld \
    NM=aarch64-elf-nm OBJCOPY=aarch64-elf-objcopy -j4

QEMU_EFI=/opt/homebrew/share/qemu/edk2-aarch64-code.fd QEMU_TIMEOUT=90 \
make -f Makefile.arm64 \
    CC=aarch64-elf-gcc LD=aarch64-elf-ld \
    NM=aarch64-elf-nm OBJCOPY=aarch64-elf-objcopy test
```

Both passed. These commands explicitly substitute the bare-metal
`aarch64-elf` toolchain for the Makefile's default `aarch64-linux-gnu`
toolchain. Set `QEMU_EFI` to the firmware image installed on the test host;
the path above records this run, not a cross-platform default.

The ring-3 suite reached all-pass, observed virtio-rng initialization, and
required both service-tier laundering refusals and the same seven authority
and lifecycle markers as the x86-64 harness. `test/captest_harness_test.py`
checks that both real shell harnesses reject logs missing any required
evidence, as well as logs containing an explicit failed test.
The separate UEFI/Limine kernel-only smoke boot also reached no-init.

## What the boot tests now exercise

- Independent fork/vfork children have empty usable capability tables.
- Capability-gated operations are denied before fresh policy issuance.
- Repeated no-op admin drops cannot restore grants in empty children.
- Fresh exec and unmasked spawn issue destination policy, not inherited
  parent sessions.
- Masked spawn and later descendants retain persistent ceilings.
- Same-policy exec and confined descendants produce the expected `AT_SECURE`
  values; unconfined startup is always secure.
- Thread lifecycle tests first exec a fresh image, rather than depending on
  inherited thread-creation authority.
- Exit-group teardown, parent wakeup, and 100 rounds of thread-zombie reaping
  complete. Expected child status is checked so a setup/exec failure cannot
  masquerade as successful teardown.

The test fixture's service `CAP_DELEGATE` grant exists only in the minimal
test rootfs. It is not a new production bootstrap or ambient grant.

## Harness portability changes

Rootfs recipes resolve `MKE2FS` and `DEBUGFS` through overridable Make
variables instead of hardcoding Linux `/sbin` paths. Headless QEMU runners
disconnect stdin so serial stdio cannot inherit an interactive terminal.
ARM runners accept `QEMU_EFI`; all four smoke/capability runners accept
`QEMU_TIMEOUT`, retaining their prior default deadlines.

Generated `.config` and `.config.old` are ignored alongside build products.

## Remaining boundary

These boots use the in-tree freestanding test init, not a deployed LoricaOS
userland. They do not establish:

- Compatibility of LoricaOS init, libc child-side setup, login, elevated-shell,
  installer, first-boot, or desktop launch flows.
- Whether the deployed dynamic loader honors `AT_SECURE`, or the exact
  environment-variable compatibility impact.
- Physical-hardware behavior or exhaustive SMP/interleaving correctness.
- Complete socket ABI conformance, stream-byte association of UNIX ancillary
  rights, or preservation of consumed stream suffixes after usercopy faults.

The blocked-sibling lifecycle case still uses a scheduling delay rather than
a deterministic kernel-blocked-state handshake. Its passing result does not
prove that every intended blocked-state interleaving occurred.

The next integration step is to attach the LoricaOS repository, adapt its
launchers to the explicit authority rules, and run real OS boots. Do not
weaken capability inheritance to make an old userland pass.

See [process authority inheritance](process-authority-inheritance.md) for the
required migration and [secure startup](../audits/capability-secure-start.md)
for the kernel/loader contract.
