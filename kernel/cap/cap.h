#ifndef CAP_H
#define CAP_H

#include <stdint.h>

/* cap_slot_t — one entry in a per-process capability table.
 * kind == CAP_KIND_NULL means the slot is empty.
 * Laid out as #[repr(C)] in Rust; size = 8 bytes. */
typedef struct {
    uint32_t kind;    /* CAP_KIND_* */
    uint32_t rights;  /* CAP_RIGHTS_* bitfield */
} cap_slot_t;

#define CAP_TABLE_SIZE   64u

/* Capability kinds */
#define CAP_KIND_NULL      0u   /* empty slot */
#define CAP_KIND_VFS_OPEN  1u   /* permission to call sys_open */
#define CAP_KIND_VFS_WRITE 2u   /* permission to call sys_write */
#define CAP_KIND_VFS_READ  3u   /* permission to call sys_read */
#define CAP_KIND_AUTH      4u   /* may open /etc/shadow for reading */
#define CAP_KIND_CAP_GRANT 5u   /* may delegate caps to child processes (reserved) */
#define CAP_KIND_SETUID    6u   /* may call sys_setuid / sys_setgid */
#define CAP_KIND_NET_SOCKET 7u   /* may call sys_socket / socket syscalls */
#define CAP_KIND_NET_ADMIN  8u   /* may call sys_netcfg (set IP/mask/gw) */
#define CAP_KIND_THREAD_CREATE 9u /* may call clone(CLONE_VM) */
#define CAP_KIND_PROC_READ  10u  /* may read /proc/[other-pid] */
#define CAP_KIND_DISK_ADMIN 11u  /* may perform raw block device I/O */
#define CAP_KIND_FB         12u  /* may map framebuffer into userspace */
#define CAP_KIND_CAP_DELEGATE 13u  /* may restrict caps on spawn via cap_mask */
#define CAP_KIND_CAP_QUERY    14u  /* may introspect any process's capability set */
#define CAP_KIND_IPC          15u  /* may create AF_UNIX sockets and memfd objects */
#define CAP_KIND_POWER        16u  /* may call sys_reboot (shutdown/reboot) */
#define CAP_KIND_INSTALL      17u  /* may mutate /apps and /etc/aegis (herald package manager) */
#define CAP_KIND_NET_LISTEN   18u  /* may bind/listen on a privileged TCP port (<1024) */
#define CAP_KIND_ADMIN_AUTH   19u  /* may call sys_admin_session to ELEVATE a session to an admin
                                    * session (sudo-style). Held ONLY by /bin/login, which verifies
                                    * the separate admin credential first (reusing its libauth/crypt
                                    * machinery, like login + CAP_KIND_AUTH). The shell delegates to
                                    * login -elevate; no shell holds this cap. */

/* CAP_KIND_MAX — highest DEFINED capability kind. Used to reject undefined kinds
 * (e.g. the sys_spawn cap_mask delegation path) without hardcoding a specific
 * kind that goes stale when a new one is added. MUST be bumped whenever a
 * CAP_KIND_* above is added — a stale bound silently makes the newest cap
 * undelegatable (exactly the bug that left NET_LISTEN undelegatable when the
 * check still read `> CAP_KIND_INSTALL`). */
#define CAP_KIND_MAX          CAP_KIND_ADMIN_AUTH

/* Compile-time invariants for the cap-kind space (T4 cap-enum guards). These
 * turn the prose contract above into build errors:
 *   - CAP_KIND_NULL must be 0: empty-slot detection (slot.kind == 0) relies on
 *     it throughout cap.c / cap_policy.c.
 *   - CAP_KIND_MAX must stay within the cap table so a kind value is always a
 *     sane, addressable identifier and the delegation range check is bounded.
 * The companion coverage assert lives in cap_policy.c (cap_name_to_kind): it
 * forces the policy-name table to list every kind 1..CAP_KIND_MAX, so adding a
 * CAP_KIND_* without bumping CAP_KIND_MAX — or without giving it a policy name —
 * fails the build instead of silently mis-granting at runtime. */
_Static_assert(CAP_KIND_NULL == 0u,
               "CAP_KIND_NULL must be 0 — empty-slot detection depends on it");
_Static_assert(CAP_KIND_MAX < CAP_TABLE_SIZE,
               "CAP_KIND_MAX must stay below CAP_TABLE_SIZE");

/* Policy tiers — controls when caps from /etc/aegis/caps.d/ are granted.
 * NOTE: CAP_KIND_INSTALL and CAP_KIND_DISK_ADMIN are special-cased in
 * cap_apply_policy — even at ADMIN tier they are granted only for an ADMIN
 * SESSION (proc->admin_session, set by the sudo-style stsh `admin` flow /
 * `login -elevate`), not mere login. DISK_ADMIN (raw whole-disk I/O) is gated
 * because it bypasses every fs-layer defense. See cap_apply_policy(). */
#define CAP_TIER_SERVICE  1u  /* granted unconditionally at exec */
#define CAP_TIER_ADMIN    2u  /* granted only if proc->authenticated */

/* Maximum caps per policy entry and max policy entries */
#define CAP_POLICY_MAX_CAPS    16u
#define CAP_POLICY_MAX_ENTRIES 64u   /* must exceed the caps.d file count (was 32; the
                                      * desktop rootfs ships ~40 → the tail was silently
                                      * dropped, so netman/editor/… lost their caps) */

/* One capability in a policy entry */
typedef struct {
    uint32_t kind;    /* CAP_KIND_* */
    uint32_t rights;  /* CAP_RIGHTS_* */
    uint32_t tier;    /* CAP_TIER_SERVICE or CAP_TIER_ADMIN */
} cap_policy_cap_t;

/* A single policy entry — maps a binary basename to its caps */
typedef struct {
    char             name[64];  /* binary basename, e.g. "httpd" */
    cap_policy_cap_t caps[CAP_POLICY_MAX_CAPS];
    uint32_t         count;     /* number of valid caps[] entries */
} cap_policy_entry_t;

/* Load all policy files from /etc/aegis/caps.d/ at boot.
 * Must be called after vfs_init() + console_init(). */
void cap_policy_load(void);

/* Look up the policy for a binary by full exe_path.
 * Extracts basename (everything after last '/') and compares.
 * Returns pointer to entry, or NULL if no policy found. */
const cap_policy_entry_t *cap_policy_lookup(const char *exe_path);

/* cap_apply_policy — reset `caps` (CAP_TABLE_SIZE slots) and grant the baseline
 * caps plus the per-binary policy caps for `path` (SERVICE-tier always,
 * ADMIN-tier only when `authenticated`, EXCEPT CAP_KIND_INSTALL and
 * CAP_KIND_DISK_ADMIN which require `admin_session` — the sudo-style elevated
 * session). The single source of truth
 * used by execve, sys_spawn, and proc_spawn. */
void cap_apply_policy(cap_slot_t *caps, const char *path, int authenticated,
                      int admin_session);

/* Returns 1 if `path` is under the install-protected trees
 * (/apps/ or /etc/aegis/), else 0. */
int cap_path_is_protected(const char *path);

/* cap_anchor_audit — boot-time check that every trusted-for-granting anchor is
 * also install-protected (anchor ⊆ protected). WARNs (never panics) on drift.
 * MUST be called after ext2 mount + ext2_anchors_reload() so the protected
 * inode set is populated. */
void cap_anchor_audit(void);

/* Capability rights (bitfield) */
#define CAP_RIGHTS_READ   (1u << 0)
#define CAP_RIGHTS_WRITE  (1u << 1)
#define CAP_RIGHTS_EXEC   (1u << 2)

/* ENOCAP — Aegis-internal name for "no matching capability found".
 * Aliased to EPERM (1) so cap-gate denials reach userspace as a real POSIX
 * errno (musl has no strerror for the old 130). Defined without the 'u' suffix
 * so that -ENOCAP is an unambiguous signed expression; callers test `>= 0` /
 * `!= 0`, never equality to a specific value. Single-sourced in aegis_errno.h. */
#include "../include/aegis_errno.h"

/* cap_init — initialize the capability subsystem.
 * Prints [CAP] OK line. Called from kernel_main before sched_init. */
void cap_init(void);

/* cap_grant — write (kind, rights) into the first empty slot of table[0..n).
 * Returns the slot index on success.
 * Returns -ENOCAP if all slots are occupied. */
int cap_grant(cap_slot_t *table, uint32_t n, uint32_t kind, uint32_t rights);

/* cap_check — return 0 if table[0..n) contains a slot with matching kind
 * and at least the requested rights; return -ENOCAP otherwise. */
int cap_check(const cap_slot_t *table, uint32_t n, uint32_t kind, uint32_t rights);

#endif /* CAP_H */
