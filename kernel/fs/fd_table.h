/* kernel/fs/fd_table.h — shared, refcounted file descriptor table */
#ifndef FD_TABLE_H
#define FD_TABLE_H

#include "vfs.h"
#include "spinlock.h"

typedef struct {
    vfs_file_t fds[PROC_MAX_FDS];
    uint32_t   refcount;
    /* Liveness marker, checked on every ref/unref. A freed table is stamped
     * with FD_TABLE_POISON, so touching one after it is gone is caught at the
     * point of misuse instead of silently walking whatever now owns those
     * pages — which is how the arm64 shutdown corruption presented: a garbage
     * but non-NULL fds[].ops dereferenced in fd_table_unref. */
    uint32_t   magic;
    /* Serialises SLOT MUTATION against fd_table_copy. Slots were mutated with
     * no lock at all: sys_close cleared fds[i] and then called ops->close,
     * while fd_table_copy ran two separate passes — copy every slot, then walk
     * the copy calling ops->dup. A sibling sharing this table (CLONE_FILES)
     * closing between those passes drops the object's last reference, and the
     * dup pass then calls ->dup on freed memory.
     *
     * LOCK ORDER: fd_table.lock > any object lock. Callers take this, capture
     * or install the slot, and RELEASE IT before calling ops->close — close
     * paths do real work (unix_sock_free re-enters unix_lock, pipe close does a
     * TLB-shootdown kva_free_pages) and running them under a spinlock is the
     * deadlock this codebase already hit once. ops->dup IS called under it: it
     * is a refcount increment, and the ordering above holds. */
    spinlock_t lock;
} fd_table_t;

#define FD_TABLE_MAGIC   0xFD7AB1EEu
#define FD_TABLE_POISON  0xDEADFD7Au

fd_table_t *fd_table_alloc(void);
void fd_table_ref(fd_table_t *t);
void fd_table_unref(fd_table_t *t);
fd_table_t *fd_table_copy(fd_table_t *src);

#endif /* FD_TABLE_H */
