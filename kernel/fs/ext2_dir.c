/* ext2_dir.c — ext2 directory entry helpers: lookup_parent, add_entry, remove_entry */
#include "ext2_internal.h"

/* ext2_lookup_parent — split "/path/to/file" into parent inode and basename.
 * On success, *parent_ino_out and *basename_out are set; returns 0.
 * Returns -1 if the parent directory cannot be opened. */
int ext2_lookup_parent(const char *path, uint32_t *parent_ino_out,
                       const char **basename_out)
{
    const char *last_slash = path;
    const char *p = path;
    while (*p) {
        if (*p == '/')
            last_slash = p;
        p++;
    }
    if (last_slash == path) {
        /* file sits directly in root */
        *parent_ino_out = EXT2_ROOT_INODE;
        *basename_out = path + 1; /* skip leading '/' */
    } else {
        char parent_path[256];
        uint32_t plen = (uint32_t)(last_slash - path);
        if (plen == 0)
            plen = 1; /* "/" */
        if (plen >= sizeof(parent_path))
            return -1;
        uint32_t ci;
        for (ci = 0; ci < plen; ci++)
            parent_path[ci] = path[ci];
        parent_path[plen] = '\0';
        if (ext2_open(parent_path, parent_ino_out) != 0) {
            printk("[EXT2] lookup_parent: ext2_open(%s) failed\n", parent_path);
            return -1;
        }
        *basename_out = last_slash + 1;
    }
    return 0;
}

/* ext2_dir_add_entry — append a directory entry to dir_ino.
 * Reuses a deleted slot or splits an oversized entry before allocating
 * a new block.  Returns 0 on success, -1 on failure. */
int ext2_dir_add_entry(uint32_t dir_ino, uint32_t child_ino,
                       const char *name, uint8_t file_type)
{
    ext2_inode_t dir;
    if (ext2_read_inode(dir_ino, &dir) != 0)
        return -1;

    uint32_t name_len32 = 0;
    while (name[name_len32])
        name_len32++;
    if (name_len32 == 0 || name_len32 > 255) return -ENAMETOOLONG;
    uint8_t name_len = (uint8_t)name_len32;
    uint16_t needed = (uint16_t)(8u + name_len);
    /* round up to 4-byte boundary */
    needed = (uint16_t)((needed + 3u) & ~3u);

    /* scan existing directory blocks looking for a slot */
    uint32_t pos = 0;
    uint32_t file_block_idx = 0;
    while (pos <= dir.i_size) {
        uint32_t blk;
        if (pos == dir.i_size) {
            /* need a new block */
            blk = ext2_alloc_block(0);
            if (blk == 0)
                return -1;
            if (file_block_idx < 12) {
                dir.i_block[file_block_idx] = blk;
            } else {
                return -1; /* indirect not supported for dirs in this impl */
            }
            dir.i_size += s_block_size;
            dir.i_blocks += s_block_size / 512;
            /* zero the new block and write a single spanning entry */
            uint8_t *newdata = cache_get_slot(blk);
            if (!newdata)
                return -1;
            uint32_t zi;
            for (zi = 0; zi < s_block_size; zi++)
                newdata[zi] = 0;
            ext2_dirent_t *de = (ext2_dirent_t *)newdata;
            de->inode = child_ino;
            de->rec_len = (uint16_t)s_block_size;
            de->name_len = name_len;
            de->file_type = file_type;
            uint32_t ni;
            for (ni = 0; ni < name_len; ni++)
                de->name[ni] = name[ni];
            cache_mark_dirty(blk);
            ext2_write_inode(dir_ino, &dir);
            return 0;
        }
        blk = ext2_block_num(&dir, file_block_idx);
        if (blk == 0) {
            pos += s_block_size;
            file_block_idx++;
            continue;
        }
        uint8_t *data = cache_get_slot(blk);
        if (!data)
            return -1;
        uint32_t block_pos = 0;
        while (block_pos < s_block_size) {
            ext2_dirent_t *de = (ext2_dirent_t *)(data + block_pos);
            if (de->rec_len < 8 || block_pos + de->rec_len > s_block_size)
                break;
            /* name_len must fit inside the record (rec_len already validated
             * >= 8 above, so rec_len - 8 can't underflow).  A crafted in-use
             * entry with an oversized name_len is malformed — skip it. */
            if ((uint32_t)de->name_len + 8u > (uint32_t)de->rec_len) {
                block_pos += de->rec_len;
                continue;
            }
            uint16_t actual = (uint16_t)((8u + de->name_len + 3u) & ~3u);
            /* actual is the space the existing entry truly needs.  Only when
             * actual <= rec_len is there a tail to split; computing free_space
             * otherwise would underflow the uint16 and falsely satisfy the
             * free_space >= needed test, writing the new dirent past the block
             * into the adjacent cache slot. */
            if (actual > de->rec_len) {
                block_pos += de->rec_len;
                continue;
            }
            uint16_t free_space = (uint16_t)(de->rec_len - actual);
            if (de->inode == 0) {
                /* unused entry — reuse whole slot */
                if (de->rec_len >= needed) {
                    de->inode = child_ino;
                    de->name_len = name_len;
                    de->file_type = file_type;
                    uint32_t ni;
                    for (ni = 0; ni < name_len; ni++)
                        de->name[ni] = name[ni];
                    cache_mark_dirty(blk);
                    ext2_write_inode(dir_ino, &dir);
                    return 0;
                }
            } else if (free_space >= needed) {
                /* split existing entry */
                uint8_t *next = data + block_pos + actual;
                ext2_dirent_t *nde = (ext2_dirent_t *)next;
                nde->inode = child_ino;
                nde->rec_len = free_space;
                nde->name_len = name_len;
                nde->file_type = file_type;
                uint32_t ni;
                for (ni = 0; ni < name_len; ni++)
                    nde->name[ni] = name[ni];
                de->rec_len = actual;
                cache_mark_dirty(blk);
                ext2_write_inode(dir_ino, &dir);
                return 0;
            }
            block_pos += de->rec_len;
        }
        pos += s_block_size;
        file_block_idx++;
    }
    return -1;
}

/* ext2_dir_remove_entry — zero-out the inode field of the named entry in
 * dir_ino (or merge its rec_len into the previous entry).
 * Returns 0 on success, -1 if the name was not found. */
int ext2_dir_remove_entry(uint32_t dir_ino, const char *name)
{
    ext2_inode_t dir;
    if (ext2_read_inode(dir_ino, &dir) != 0)
        return -1;

    uint8_t name_len = 0;
    while (name[name_len])
        name_len++;

    uint32_t pos = 0;
    uint32_t file_block_idx = 0;
    while (pos < dir.i_size) {
        uint32_t blk = ext2_block_num(&dir, file_block_idx);
        if (blk == 0) {
            pos += s_block_size;
            file_block_idx++;
            continue;
        }
        uint8_t *data = cache_get_slot(blk);
        if (!data)
            return -1;
        uint32_t block_pos = 0;
        ext2_dirent_t *prev = (void *)0;
        while (block_pos < s_block_size) {
            ext2_dirent_t *de = (ext2_dirent_t *)(data + block_pos);
            if (de->rec_len < 8 || block_pos + de->rec_len > s_block_size)
                break;
            /* name_len must fit inside the record (rec_len already validated
             * >= 8 above, so rec_len - 8 can't underflow).  Skip malformed
             * entries to avoid an OOB read past the 4096 cache buffer during
             * the name compare. */
            if ((uint32_t)de->name_len + 8u > (uint32_t)de->rec_len) {
                prev = de;
                block_pos += de->rec_len;
                continue;
            }
            if (de->inode != 0 && de->name_len == name_len) {
                uint32_t ni;
                int match = 1;
                for (ni = 0; ni < name_len; ni++) {
                    if (de->name[ni] != name[ni]) {
                        match = 0;
                        break;
                    }
                }
                if (match) {
                    if (prev) {
                        prev->rec_len = (uint16_t)(prev->rec_len + de->rec_len);
                    } else {
                        de->inode = 0;
                    }
                    cache_mark_dirty(blk);
                    return 0;
                }
            }
            prev = de;
            block_pos += de->rec_len;
        }
        pos += s_block_size;
        file_block_idx++;
    }
    return -1; /* not found */
}
