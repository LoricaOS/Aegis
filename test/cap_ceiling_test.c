/* Host regression test for exec-persistent cap-mask ceilings.
 * Build: cc -std=c11 -Ikernel/cap test/cap_ceiling_test.c kernel/cap/cap.c */
#include "cap.h"
#include <assert.h>

void serial_write_string(const char *s) { (void)s; }

int
main(void)
{
    cap_slot_t masked[CAP_TABLE_SIZE] = {0};
    cap_slot_t rederived[CAP_TABLE_SIZE] = {0};
    uint32_t ceiling[CAP_KIND_MAX + 1u];

    assert(cap_grant(masked, CAP_TABLE_SIZE,
                     CAP_KIND_VFS_OPEN, CAP_RIGHTS_READ) >= 0);
    assert(cap_grant(masked, CAP_TABLE_SIZE,
                     CAP_KIND_AUTH, CAP_RIGHTS_READ) >= 0);
    cap_ceiling_from_table(ceiling, masked);

    /* Simulate a later authenticated/admin exec deriving broader policy. */
    assert(cap_grant(rederived, CAP_TABLE_SIZE, CAP_KIND_VFS_OPEN,
                     CAP_RIGHTS_READ) >= 0);
    assert(cap_grant(rederived, CAP_TABLE_SIZE, CAP_KIND_AUTH,
                     CAP_RIGHTS_READ | CAP_RIGHTS_WRITE) >= 0);
    assert(cap_grant(rederived, CAP_TABLE_SIZE, CAP_KIND_INSTALL,
                     CAP_RIGHTS_READ | CAP_RIGHTS_WRITE) >= 0);
    cap_apply_ceiling(rederived, ceiling);

    assert(cap_check(rederived, CAP_TABLE_SIZE,
                     CAP_KIND_VFS_OPEN, CAP_RIGHTS_READ) == 0);
    assert(cap_check(rederived, CAP_TABLE_SIZE,
                     CAP_KIND_AUTH, CAP_RIGHTS_READ) == 0);
    assert(cap_check(rederived, CAP_TABLE_SIZE,
                     CAP_KIND_AUTH, CAP_RIGHTS_WRITE) != 0);
    assert(cap_check(rederived, CAP_TABLE_SIZE,
                     CAP_KIND_INSTALL, CAP_RIGHTS_READ) != 0);
    return 0;
}
