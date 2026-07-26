/* hyperv_stub.c — compiled only when CONFIG_HYPERV is off (see Makefile).
 *
 * The arch timekeeping code (pit.c, lapic.c) probes for the Hyper-V reference
 * TSC page as a clock source. With Hyper-V support compiled out we are, by
 * definition, not a Hyper-V guest: report absent and no reference clock. */
#include <stdint.h>
#include "hyperv.h"

int      hyperv_present(void)  { return 0; }
uint64_t hyperv_ref_time(void) { return 0; }
