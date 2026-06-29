/* kernel/fs/procfs.h — /proc virtual filesystem */
#ifndef AEGIS_PROCFS_H
#define AEGIS_PROCFS_H

#include "vfs.h"

void procfs_init(void);
int  procfs_open(const char *path, int flags, vfs_file_t *out);
int  procfs_stat(const char *path, k_stat_t *out);

#endif /* AEGIS_PROCFS_H */
