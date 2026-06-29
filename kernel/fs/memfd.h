/* kernel/fs/memfd.h — anonymous shared memory file descriptors */
#ifndef MEMFD_H
#define MEMFD_H

#include "vfs.h"
#include "../lib/refcount.h"
#include <stdint.h>

/* phys_pages is now a DYNAMIC kva-backed array (allocated on first grow,
 * freed on close), so each slot costs ~64B of BSS instead of 16KB. That
 * lets MEMFD_MAX be large without blowing the 8MB kernel BSS ceiling.
 * Ladybird (WebContent+Compositor) holds many shareable bitmaps at once
 * under a heavy page’s repaint loop — 48 was far too few. */
#define MEMFD_MAX        256
#define MEMFD_PAGES_MAX  2048   /* 8MB max per memfd */
#define MEMFD_PHYS_ARR_PAGES  ((MEMFD_PAGES_MAX * 8 + 4095) / 4096)  /* kva pages for phys_pages[] */

typedef struct {
    uint8_t   in_use;
    refcount_t refcount;
    char      name[32];
    uint64_t *phys_pages;    /* dynamic, MEMFD_PAGES_MAX entries; NULL until first grow */
    uint32_t  page_count;    /* allocated pages */
    uint64_t  size;          /* logical size in bytes */
} memfd_t;

/* VFS ops for memfd fds */
extern const vfs_ops_t g_memfd_ops;

/* Allocate a memfd. Returns slot index or -1. */
int memfd_alloc(const char *name);

/* Get memfd_t by slot index. Returns NULL if invalid. */
memfd_t *memfd_get(uint32_t id);

/* Get the memfd_t from a VFS fd (returns NULL if not a memfd). */
memfd_t *memfd_from_fd(int fd, void *proc);

/* Set memfd size (allocates/frees physical pages). Returns 0 or -errno. */
int memfd_truncate(uint32_t id, uint64_t size);

/* Open an fd backed by a memfd. Returns fd or -1. */
int memfd_open_fd(uint32_t id, void *proc);

#endif /* MEMFD_H */
