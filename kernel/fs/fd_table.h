/* kernel/fs/fd_table.h — shared, refcounted file descriptor table */
#ifndef FD_TABLE_H
#define FD_TABLE_H

#include "vfs.h"

typedef struct {
    vfs_file_t fds[PROC_MAX_FDS];
    uint32_t   refcount;
    /* Liveness marker, checked on every ref/unref. A freed table is stamped
     * with FD_TABLE_POISON, so touching one after it is gone is caught at the
     * point of misuse instead of silently walking whatever now owns those
     * pages — which is how the arm64 shutdown corruption presented: a garbage
     * but non-NULL fds[].ops dereferenced in fd_table_unref. */
    uint32_t   magic;
} fd_table_t;

#define FD_TABLE_MAGIC   0xFD7AB1EEu
#define FD_TABLE_POISON  0xDEADFD7Au

fd_table_t *fd_table_alloc(void);
void fd_table_ref(fd_table_t *t);
void fd_table_unref(fd_table_t *t);
fd_table_t *fd_table_copy(fd_table_t *src);

#endif /* FD_TABLE_H */
