#ifndef CONSOLE_H
#define CONSOLE_H

#include "vfs.h"

/* console_init — initialize the console VFS device.
 * Called from kernel_main after vfs_init(). Silent — no boot line. */
void console_init(void);

/* console_open — return a pointer to the static console vfs_file_t.
 * Used by proc_spawn to pre-populate fd 1 (stdout). */
vfs_file_t *console_open(void);

#endif /* CONSOLE_H */
