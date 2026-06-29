/* kernel/fs/fd_table.h — shared, refcounted file descriptor table */
#ifndef FD_TABLE_H
#define FD_TABLE_H

#include "vfs.h"

typedef struct {
    vfs_file_t fds[PROC_MAX_FDS];
    uint32_t   refcount;
} fd_table_t;

fd_table_t *fd_table_alloc(void);
void fd_table_ref(fd_table_t *t);
void fd_table_unref(fd_table_t *t);
fd_table_t *fd_table_copy(fd_table_t *src);

#endif /* FD_TABLE_H */
