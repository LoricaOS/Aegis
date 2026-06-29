/* blkdev.c — Block device registration table */
#include "blkdev.h"
#include "spinlock.h"
#include <stddef.h>

static blkdev_t *s_devices[BLKDEV_MAX];
static int        s_count = 0;
static spinlock_t blkdev_lock = SPINLOCK_INIT;

int blkdev_register(blkdev_t *dev)
{
    irqflags_t fl = spin_lock_irqsave(&blkdev_lock);
    if (s_count >= BLKDEV_MAX || dev == NULL) {
        spin_unlock_irqrestore(&blkdev_lock, fl);
        return -1;
    }
    s_devices[s_count++] = dev;
    spin_unlock_irqrestore(&blkdev_lock, fl);
    return 0;
}

blkdev_t *blkdev_get(const char *name)
{
    irqflags_t fl = spin_lock_irqsave(&blkdev_lock);
    int i;
    for (i = 0; i < s_count; i++) {
        const char *a = s_devices[i]->name;
        const char *b = name;
        while (*a && *a == *b) { a++; b++; }
        if (*a == *b) {
            blkdev_t *dev = s_devices[i];
            spin_unlock_irqrestore(&blkdev_lock, fl);
            return dev;
        }
    }
    spin_unlock_irqrestore(&blkdev_lock, fl);
    return NULL;
}

int blkdev_count(void)
{
    return s_count;
}

blkdev_t *blkdev_get_index(int i)
{
    irqflags_t fl = spin_lock_irqsave(&blkdev_lock);
    if (i < 0 || i >= s_count) {
        spin_unlock_irqrestore(&blkdev_lock, fl);
        return NULL;
    }
    blkdev_t *dev = s_devices[i];
    spin_unlock_irqrestore(&blkdev_lock, fl);
    return dev;
}

void blkdev_unregister_children(const char *parent_prefix)
{
    irqflags_t fl = spin_lock_irqsave(&blkdev_lock);
    int plen = 0;
    while (parent_prefix[plen]) plen++;
    int dst = 0;
    int i;
    for (i = 0; i < s_count; i++) {
        /* Check if name starts with prefix + 'p' */
        int match = 1;
        int j;
        for (j = 0; j < plen; j++) {
            if (s_devices[i]->name[j] != parent_prefix[j]) { match = 0; break; }
        }
        if (match && s_devices[i]->name[plen] == 'p') {
            /* Skip this device (unregister) */
            continue;
        }
        s_devices[dst++] = s_devices[i];
    }
    s_count = dst;
    spin_unlock_irqrestore(&blkdev_lock, fl);
}
