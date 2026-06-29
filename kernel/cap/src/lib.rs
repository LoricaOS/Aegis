#![no_std]

extern "C" {
    // C declaration: void serial_write_string(const char *s)
    // On x86-64 with GCC, `char` is signed 8-bit and `u8` is unsigned 8-bit.
    // Both are 1 byte with identical ABI representation — safe to call with
    // a Rust byte-string literal (*const u8) on this target.
    fn serial_write_string(s: *const u8);
}

#[repr(C)]
pub struct CapSlot {
    pub kind:   u32,   /* CAP_KIND_* — 0 means empty */
    pub rights: u32,   /* CAP_RIGHTS_* bitfield */
}

// ENOCAP — must match the C definition in kernel/include/aegis_errno.h, which
// aliases it to EPERM (1) so cap-gate denials reach userspace as a real POSIX
// errno (musl has no strerror for the old 130). cap_grant/cap_check return
// -ENOCAP only as an internal "nonzero on failure" signal; every C caller tests
// != 0 / < 0 / >= 0, never equality to a specific value. Keeping this in sync
// with the C constant avoids a latent leak if a caller ever returns the raw
// value to userspace.
const ENOCAP: u32 = 1;
// CAP_KIND_PROC_READ = 10 — defined in cap.h; Rust validates generically.

/* Must match CAP_TABLE_SIZE in kernel/cap/cap.h */
const CAP_TABLE_SIZE: u32 = 64;

/// Initialize the capability subsystem.
///
/// Phase 11: prints status line, returns immediately.
/// cap_grant and cap_check are now live.
///
/// Note: writes directly to serial rather than through printk because no
/// `printk` Rust FFI wrapper exists yet. This means CAP output does not
/// appear on VGA. Revisit when a printk wrapper is designed.
#[no_mangle]
pub extern "C" fn cap_init() {
    // SAFETY: serial_init() is called in arch_init() before cap_init() is
    // called in kernel_main, so the serial port is fully initialized.
    // serial_write_string is a simple polling write with no shared mutable
    // state and no re-entrancy concerns at this point in boot.
    // The pointer is to a valid C string literal (null-terminated) in read-only data.
    // `char` and `u8` have identical 8-bit ABI representation on x86-64/GCC.
    unsafe {
        serial_write_string(
            c"[CAP] OK: capability subsystem initialized\n".as_ptr() as *const u8
        );
    }
}

/// Write (kind, rights) into the first empty slot of table[0..n).
///
/// Returns the slot index on success, or -(ENOCAP) if all slots are occupied.
//
// clippy::not_unsafe_ptr_arg_deref — this is a C-ABI FFI entry point
// (#[no_mangle] extern "C"); it MUST take a raw pointer and cannot be `unsafe fn`
// (C callers have no notion of it). The dereference is guarded by the null/len
// checks below and the SAFETY block; the pointer contract is documented there.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn cap_grant(
    table: *mut CapSlot,
    n: u32,
    kind: u32,
    rights: u32,
) -> i32 {
    // Guard against NULL pointer — UB to pass null to from_raw_parts_mut.
    if table.is_null() || n == 0 {
        return -(ENOCAP as i32);
    }
    /* Clamp n to CAP_TABLE_SIZE so from_raw_parts_mut never reads past the
     * statically-allocated caps[] array, even if the caller passes a wrong value. */
    let n = n.min(CAP_TABLE_SIZE);
    // SAFETY: `table` is non-null (checked above) and `n` is clamped to
    // CAP_TABLE_SIZE above, so the slice spans at most CAP_TABLE_SIZE slots.
    // Every C caller passes `<proc>->caps` — the fixed-size
    // `cap_slot_t caps[CAP_TABLE_SIZE]` array embedded in the PCB
    // (kernel/proc/proc.h) — with `n = CAP_TABLE_SIZE`, so the slice covers
    // exactly that array, in bounds and correctly aligned (cap_slot_t is
    // #[repr(C)] CapSlot, two u32s). The PCB outlives the call. Callers are
    // the process-creation paths (proc_spawn_init in kernel/proc/proc.c, the
    // execve/spawn/fork cap setup in kernel/syscall/sys_exec.c) and the
    // runtime delegation syscall sys_cap_grant_runtime (363) in
    // kernel/syscall/sys_cap.c — the last of which grants into an
    // already-running target process, so the "before run queue" assumption is
    // NOT relied upon. Soundness rests only on no live Rust reference aliasing
    // the same array: each call materializes the slice and drops it before
    // returning, and the kernel is the sole writer of caps[] (single-core
    // scheduling). On SMP any C-level contention is the caller's concern; it
    // is not Rust-reference aliasing and does not make this slice unsound.
    let slots = unsafe { core::slice::from_raw_parts_mut(table, n as usize) };
    for (i, slot) in slots.iter_mut().enumerate() {
        if slot.kind == 0 {
            slot.kind   = kind;
            slot.rights = rights;
            return i as i32;
        }
    }
    -(ENOCAP as i32)
}

/// Return 0 if table[0..n) contains a slot with matching kind and at least
/// the requested rights; return -(ENOCAP) otherwise.
//
// clippy::not_unsafe_ptr_arg_deref — C-ABI FFI entry point (see cap_grant): must
// take a raw pointer, cannot be `unsafe fn`. Dereference guarded by the
// null/len checks and the SAFETY block below.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn cap_check(
    table: *const CapSlot,
    n: u32,
    kind: u32,
    rights: u32,
) -> i32 {
    // Guard against NULL pointer — UB to pass null to from_raw_parts.
    if table.is_null() || n == 0 {
        return -(ENOCAP as i32);
    }
    /* Clamp n to CAP_TABLE_SIZE so from_raw_parts never reads past the
     * statically-allocated caps[] array, even if the caller passes a wrong value. */
    let n = n.min(CAP_TABLE_SIZE);
    // SAFETY: `table` is non-null (checked above) and `n` is clamped to
    // CAP_TABLE_SIZE above, so the slice spans at most CAP_TABLE_SIZE slots.
    // Every C caller passes `<proc>->caps` — the fixed-size
    // `cap_slot_t caps[CAP_TABLE_SIZE]` array embedded in the PCB
    // (kernel/proc/proc.h) — with `n = CAP_TABLE_SIZE`, so the slice covers
    // exactly that array, in bounds and correctly aligned. The PCB outlives
    // the call. This is the cap-gate read path: it is called from many syscall
    // handlers (sys_disk/sys_io/sys_socket/sys_dir/sys_file/sys_meta/sys_time/
    // sys_signal/sys_identity/sys_hostname/sys_cap/...), the VFS DAC check
    // (kernel/fs/vfs.c), the TTY (kernel/tty/tty.c) and procfs
    // (kernel/fs/procfs.c). The slice is read-only (from_raw_parts) and is
    // materialized and dropped within this call, so it creates no aliasing
    // Rust reference. The kernel is the sole mutator of caps[]; a concurrent
    // C-side writer on SMP is a caller-level concern, not Rust-reference UB.
    let slots = unsafe { core::slice::from_raw_parts(table, n as usize) };
    for slot in slots {
        if slot.kind == kind && (slot.rights & rights) == rights {
            return 0;
        }
    }
    -(ENOCAP as i32)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
