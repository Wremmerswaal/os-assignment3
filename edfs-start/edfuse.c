/* EdFS -- An educational file system
 *
 * Copyright (C) 2017,2019  Leiden University, The Netherlands.
 * 
 * Edited by Wouter Remmerswaal (2665050) & Stan van Baarsen (2624672)
 */

#define FUSE_USE_VERSION 26

#include <errno.h>
#include <fuse.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "edfs-common.h"

static inline edfs_image_t *get_edfs_image(void) {
    return (edfs_image_t *)fuse_get_context()->private_data;
}


static bool
allocate_block(edfs_image_t *img, edfs_block_t *block_nr)
{
  char bitmap[img->sb.bitmap_size];
  int bit;
  pread(img->fd, bitmap, img->sb.bitmap_size, img->sb.bitmap_start);

  for (int i = 0; i < img->sb.bitmap_size; i++){
    for (int j = 0; j < 8; j++){
      bit = bitmap[i] >> j;
      if (bit & 1UL) continue;

      *block_nr = i * 8 + j;
      edfs_block_t block_offset = img->sb.bitmap_start + *block_nr / 8;
      char new_byte = 0;

      pread(img->fd, &new_byte, 1, block_offset);
      new_byte += 1 << j;
      pwrite(img->fd, &new_byte, 1, block_offset);
      return true;
    }
  }
  
  return false;
}


static bool
deallocate_block(edfs_image_t *img, edfs_block_t block_nr)
{
    char bitmap[img->sb.bitmap_size];
    pread(img->fd, bitmap, img->sb.bitmap_size, img->sb.bitmap_start);
    int byte_index = block_nr / 8;
    int bit_index = block_nr % 8;
    bitmap[byte_index] &= ~(1 << bit_index);
    pwrite(img->fd, bitmap, img->sb.bitmap_size, img->sb.bitmap_start);
    return true;
}

/* Searches the file system hierarchy to find the inode for
 * the given path. Returns true if the operation succeeded.
 */
static bool edfs_find_inode(edfs_image_t *img, const char *path,
                            edfs_inode_t *inode) {
    if (strlen(path) == 0 || path[0] != '/') return false;

    edfs_inode_t current_inode;
    edfs_read_root_inode(img, &current_inode);

    while (path && (path = strchr(path, '/'))) {
        /* Ignore path separator */
        while (*path == '/') path++;

        /* Find end of new component */
        char *end = strchr(path, '/');
        if (!end) {
            int len = strnlen(path, PATH_MAX);
            if (len > 0)
                end = (char *)&path[len];
            else {
                /* We are done: return current entry. */
                *inode = current_inode;
                return true;
            }
        }

        /* Verify length of component is not larger than maximum allowed
         * filename size.
         */
        int len = end - path;
        if (len >= EDFS_FILENAME_SIZE) return false;

        /* Within the directory pointed to by parent_inode/current_inode,
         * find the inode number for path, len.
         */
        edfs_dir_entry_t direntry = {
            0,
        };
        strncpy(direntry.filename, path, len);
        direntry.filename[len] = 0;
        if (direntry.filename[0] != 0) {
            // TODOR: Hier 1 functie van maken en gebruiken bij zowel find_inode als readdir
            const int DIR_SIZE = edfs_get_n_dir_entries_per_block(&img->sb);
            bool found = false;
            for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
                if (current_inode.inode.blocks[i] == 0) continue;
                off_t offset = edfs_get_block_offset(&img->sb, current_inode.inode.blocks[i]);
                edfs_dir_entry_t dir[DIR_SIZE];
                pread(img->fd, dir, img->sb.block_size, offset);

                for (int j = 0; j < DIR_SIZE; j++) {
                    if (strcmp(dir[j].filename, direntry.filename) || dir[j].inumber == 0) continue;
                    direntry.inumber = dir[j].inumber;
                    found = true;
                }
            }


            if (found) {
                /* Found what we were looking for, now get our new inode. */
                current_inode.inumber = direntry.inumber;
                edfs_read_inode(img, &current_inode);
            } else return false;
        }

        path = end;
    }

    *inode = current_inode;

    return true;
}

static inline void drop_trailing_slashes(char *path_copy) {
    int len = strlen(path_copy);
    while (len > 0 && path_copy[len - 1] == '/') {
        path_copy[len - 1] = 0;
        len--;
    }
}

/* Return the parent inode, for the containing directory of the inode (file or
 * directory) specified in @path. Returns 0 on success, error code otherwise.
 *
 * (This function is not yet used, but will be useful for your
 * implementation.)
 */
static int edfs_get_parent_inode(edfs_image_t *img, const char *path,
                                 edfs_inode_t *parent_inode) {
    int res;
    char *path_copy = strdup(path);

    drop_trailing_slashes(path_copy);

    if (strlen(path_copy) == 0) {
        res = -EINVAL;
        goto out;
    }

    /* Extract parent component */
    char *sep = strrchr(path_copy, '/');
    if (!sep) {
        res = -EINVAL;
        goto out;
    }

    if (path_copy == sep) {
        /* The parent is the root directory. */
        edfs_read_root_inode(img, parent_inode);
        res = 0;
        goto out;
    }

    /* If not the root directory for certain, start a usual search. */
    *sep = 0;
    char *dirname = path_copy;

    if (!edfs_find_inode(img, dirname, parent_inode)) {
        res = -ENOENT;
        goto out;
    }

    res = 0;

out:
    free(path_copy);

    return res;
}

/* Separates the basename (the actual name of the file) from the path.
 * The return value must be freed.
 *
 * (This function is not yet used, but will be useful for your
 * implementation.)
 */
static char *edfs_get_basename(const char *path) {
    char *res = NULL;
    char *path_copy = strdup(path);

    drop_trailing_slashes(path_copy);

    if (strlen(path_copy) == 0) {
        res = NULL;
        goto out;
    }

    /* Find beginning of basename. */
    char *sep = strrchr(path_copy, '/');
    if (!sep) {
        res = NULL;
        goto out;
    }

    res = strdup(sep + 1);

out:
    free(path_copy);

    return res;
}

/*
 * Implementation of necessary FUSE operations.
 */

static int edfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info *fi) {
    edfs_image_t *img = get_edfs_image();
    edfs_inode_t inode = {0};
    if (!edfs_find_inode(img, path, &inode)) return -ENOENT;

    if (!edfs_disk_inode_is_directory(&inode.inode)) return -ENOTDIR;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    /* TODO: traverse all valid directory entries of @inode and call
     * the filler function (as done above) for each entry. The second
     * argument of the filler function is the filename you want to add.
     */

    const int DIR_SIZE = edfs_get_n_dir_entries_per_block(&img->sb);

    for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
        if (inode.inode.blocks[i] == 0) continue;
        offset = edfs_get_block_offset(&img->sb, inode.inode.blocks[i]);
        edfs_dir_entry_t dir[DIR_SIZE];
        pread(img->fd, dir, img->sb.block_size, offset);

        for (int j = 0; j < DIR_SIZE; j++) {
            if (dir[j].inumber == 0) continue;
            char* filename = dir[j].filename;
            filler(buf, filename, NULL, 0);
        }
    }

    return 0;
}

static int check_filename(const char *filename) {
    // filenames are restricted to 59 bytes (excluding null-terminator) and may only contain: A-Z,
    // a-z, 0-9, spaces (“ ”) and dots (“.”).
    if (strlen(filename) >= EDFS_FILENAME_SIZE) return -ENAMETOOLONG;
    for (int i = 0; i < strlen(filename); i++) {
        if (filename[i] == ' ' || filename[i] == '.' || (filename[i] >= 'A' && filename[i] <= 'Z') || (filename[i] >= 'a' && filename[i] <= 'z') || (filename[i] >= '0' && filename[i] <= '9')) continue;
        return -EINVAL;
    }
    return 0;
}

static int edfuse_mkdir(const char *path, mode_t mode) {
    edfs_image_t *img = get_edfs_image();
    char *dirname = edfs_get_basename(path);

    edfs_inode_t parent_inode = {0};
    int err = edfs_get_parent_inode(img, path, &parent_inode);
    if(err) return err;

    if (!edfs_disk_inode_is_directory(&parent_inode.inode)) return -ENOTDIR;

    int filename_check = check_filename(dirname);
    if (filename_check) return filename_check;


    edfs_inode_t inode = {0};
    
    
    const int DIR_SIZE = edfs_get_n_dir_entries_per_block(&img->sb);
    edfs_dir_entry_t dir[DIR_SIZE];
    edfs_dir_entry_t dir_entry;
    off_t offset;

    for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++){
        if (parent_inode.inode.blocks[i] == 0) {
            if (!allocate_block(img, &parent_inode.inode.blocks[i])) return -ENOSPC;
            edfs_write_inode(img, &parent_inode);
        }
        offset = edfs_get_block_offset(&img->sb, parent_inode.inode.blocks[i]);
        pread(img->fd, dir, img->sb.block_size, offset);
        for (int j = 0; j < DIR_SIZE; j++){
            if (dir[j].inumber != 0) continue;

            err = edfs_new_inode(img, &inode, EDFS_INODE_TYPE_DIRECTORY);
            printf("err is %d", err);
            if (err) return err;
            strncpy(dir_entry.filename, dirname, strlen(dirname) + 1);
            dir_entry.inumber = inode.inumber;
            offset = edfs_get_block_offset(&img->sb, parent_inode.inode.blocks[i]) + sizeof(edfs_dir_entry_t) * j;
            pwrite(img->fd, &dir_entry, sizeof(edfs_dir_entry_t), offset);

            edfs_block_t new_blocks[EDFS_INODE_N_BLOCKS];
            for (int k = 0; k < EDFS_INODE_N_BLOCKS; k++){
                if (!allocate_block(img, &new_blocks[k])) return -ENOSPC;
                new_blocks[k] = 0;
            }
            memcpy(inode.inode.blocks, new_blocks, EDFS_INODE_N_BLOCKS * sizeof(edfs_block_t));
            edfs_write_inode(img, &inode);
            return 0;
        }
    }

    return -ENOSPC;
}

static int edfuse_rmdir(const char *path) {
    edfs_image_t *img = get_edfs_image();
    edfs_inode_t inode = {0};
    if (!edfs_find_inode(img, path, &inode)) return -ENOENT;

    if (!edfs_disk_inode_is_directory(&inode.inode)) return -ENOTDIR;

    for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
        if (inode.inode.blocks[i] != 0) return -ENOTEMPTY;
    }
    edfs_inode_t parent_inode = {0};
    edfs_get_parent_inode(img, path, &parent_inode);

    bool found = false;
    off_t offset;
    const int DIR_SIZE = edfs_get_n_dir_entries_per_block(&img->sb);
    edfs_dir_entry_t dir[DIR_SIZE];


    for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
        if (parent_inode.inode.blocks[i] == 0) continue;
        offset = edfs_get_block_offset(&img->sb, parent_inode.inode.blocks[i]);
        pread(img->fd, dir, img->sb.block_size, offset);

        for (int j = 0; j < DIR_SIZE; j++) {
            if (dir[j].inumber == inode.inumber && dir[j].inumber != 0) {
                edfs_dir_entry_t found_dir_entry;
                found_dir_entry.inumber = 0;
                offset = edfs_get_block_offset(&img->sb, parent_inode.inode.blocks[i]) + sizeof(edfs_dir_entry_t) * j;
                memset(&found_dir_entry, 0, sizeof(edfs_dir_entry_t));
                pwrite(img->fd, &found_dir_entry, sizeof(edfs_dir_entry_t), offset);
                found = true;
            }
        }
    }
    if (found){
        edfs_clear_inode(img, &inode);
        inode.inumber = 0;
        inode.inode.type = EDFS_INODE_TYPE_FREE;
        for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) inode.inode.blocks[i] = 0;
        edfs_write_inode(img, &inode);
        return 0;
    }

    /* TODO: implement
     *
     * See also Section 4.3 of the Appendices document.
     *
     * Validate @path exists and is a directory; remove directory entry
     * from parent directory; release allocated blocks; release inode.
     */
    return -ENOENT;
}

/* Get attributes of @path, fill @stbuf. At least mode, nlink and
 * size must be filled here, otherwise the "ls" listings appear busted.
 * We assume all files and directories have rw permissions for owner and
 * group.
 */
static int edfuse_getattr(const char *path, struct stat *stbuf) {
    int res = 0;
    edfs_image_t *img = get_edfs_image();

    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return res;
    }

    edfs_inode_t inode;
    if (!edfs_find_inode(img, path, &inode))
        res = -ENOENT;
    else {
        if (edfs_disk_inode_is_directory(&inode.inode)) {
            stbuf->st_mode = S_IFDIR | 0770;
            stbuf->st_nlink = 2;
        } else {
            stbuf->st_mode = S_IFREG | 0660;
            stbuf->st_nlink = 1;
        }
        stbuf->st_size = inode.inode.size;

        /* Note that this setting is ignored, unless the FUSE file system
         * is mounted with the 'use_ino' option.
         */
        stbuf->st_ino = inode.inumber;
    }

    return res;
}

/* Open file at @path. Verify it exists by finding the inode and
 * verify the found inode is not a directory. We do not maintain
 * state of opened files.
 */
static int edfuse_open(const char *path, struct fuse_file_info *fi) {
    edfs_image_t *img = get_edfs_image();

    edfs_inode_t inode;
    if (!edfs_find_inode(img, path, &inode)) return -ENOENT;

    /* Open may only be called on files. */
    if (edfs_disk_inode_is_directory(&inode.inode)) return -EISDIR;

    return 0;
}

static int edfuse_create(const char *path, mode_t mode,
                         struct fuse_file_info *fi) {
    edfs_image_t *img = get_edfs_image();
    char *filename = edfs_get_basename(path);

    edfs_inode_t parent_inode = {0};

    int err = edfs_get_parent_inode(img, path, &parent_inode);
    if(err) return err;

    if (!edfs_disk_inode_is_directory(&parent_inode.inode)) return -ENOTDIR;

    int filename_check = check_filename(filename);
    if (filename_check) return filename_check;

    edfs_inode_t inode = {0};

    const int DIR_SIZE = edfs_get_n_dir_entries_per_block(&img->sb);
    edfs_dir_entry_t dir[DIR_SIZE];
    edfs_dir_entry_t dir_entry;
    off_t offset;

    for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++){
        if (parent_inode.inode.blocks[i] == 0) {
            if (!allocate_block(img, &parent_inode.inode.blocks[i])) return -ENOSPC;
            edfs_write_inode(img, &parent_inode);
        }
        offset = edfs_get_block_offset(&img->sb, parent_inode.inode.blocks[i]);
        pread(img->fd, dir, img->sb.block_size, offset);
        for (int j = 0; j < DIR_SIZE; j++){
            if (dir[j].inumber != 0) {
                // compare filename with dir[j].filename
                if (strcmp(dir[j].filename, filename) == 0) return -EEXIST;
                else continue;
            }

            err = edfs_new_inode(img, &inode, EDFS_INODE_TYPE_FILE);
            if (err) return err;
            strncpy(dir_entry.filename, filename, strlen(filename) + 1);
            dir_entry.inumber = inode.inumber;
            offset = edfs_get_block_offset(&img->sb, parent_inode.inode.blocks[i]) + sizeof(edfs_dir_entry_t) * j;
            pwrite(img->fd, &dir_entry, sizeof(edfs_dir_entry_t), offset);

            edfs_block_t new_blocks[EDFS_INODE_N_BLOCKS];
            for (int k = 0; k < EDFS_INODE_N_BLOCKS; k++){
                if (!allocate_block(img, &new_blocks[k])) return -ENOSPC;
                new_blocks[k] = 0;
            }
            memcpy(inode.inode.blocks, new_blocks, EDFS_INODE_N_BLOCKS * sizeof(edfs_block_t));
            edfs_write_inode(img, &inode);
            return 0;
        }
    }

    
    return -ENOSPC;
}

/* Since we don't maintain link count, we'll treat unlink as a file
 * remove operation.
 */
static int edfuse_unlink(const char *path) {
    /* Validate @path exists and is not a directory; remove directory entry
     * from parent directory; release allocated blocks; release inode.
     */

    /* NOTE: Not implemented and not part of the assignment. */
    return -ENOSYS;
}

static int edfuse_read(const char *path, char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi) {
    edfs_image_t *img = get_edfs_image();
    edfs_inode_t inode = {0};

    int bytes_read = 0;

    if (!edfs_find_inode(img, path, &inode)) return -ENOENT;
    if (edfs_disk_inode_is_directory(&inode.inode)) return -EISDIR;

    size_t block_size = img->sb.block_size;
    off_t file_size = inode.inode.size;
    off_t current_offset = 0;
    size_t bytes_to_read = size;

    if (offset + size > file_size) {
        // make sure we don't read past the end of the file
        bytes_to_read = file_size - offset;
    }

    if (!edfs_disk_inode_has_indirect(&inode.inode)) {
        // direct blocks!
        for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
            if (inode.inode.blocks[i] == 0) break;
            if (bytes_to_read <= 0) break;
            off_t block_offset = edfs_get_block_offset(&img->sb, inode.inode.blocks[i]);

            if (current_offset + block_size > offset) {
                size_t read_offset = 0;
                if (current_offset < offset) read_offset = offset - current_offset;
                size_t read_size = block_size - read_offset;
                if (read_size > bytes_to_read) read_size = bytes_to_read;

                pread(img->fd, buf + bytes_read, read_size, block_offset + read_offset);
                bytes_read += read_size;
                bytes_to_read -= read_size;
            }
            current_offset += block_size;
        }
    } else {
        // indirect blocks!
        for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
            if (inode.inode.blocks[i] == 0) continue;
            if (bytes_to_read <= 0) break;

            off_t indirect_block_offset = edfs_get_block_offset(&img->sb, inode.inode.blocks[i]);

            int NR_BLOCKS = edfs_get_n_blocks_per_indirect_block(&img->sb);
            edfs_block_t indirect_blocks[NR_BLOCKS];
            pread(img->fd, indirect_blocks, block_size, indirect_block_offset);


            for (size_t j = 0; j < NR_BLOCKS; j++) {
                if (bytes_to_read <= 0) break;
                if (indirect_blocks[j] == 0) break;
                size_t block_offset = edfs_get_block_offset(&img->sb, indirect_blocks[j]);

                if (current_offset + block_size > offset) {
                    size_t read_offset = 0;
                    if (current_offset < offset) read_offset = offset - current_offset;
                    size_t read_size = block_size - read_offset;
                    if (read_size > bytes_to_read) read_size = bytes_to_read;

                    pread(img->fd, buf + bytes_read, read_size, block_offset + read_offset);
                    bytes_read += read_size;
                    bytes_to_read -= read_size;
                }
                current_offset += block_size;
            }
            // now copy the read data to the buffer
        }
    }
    return bytes_read;
}


static int make_inode_indirect(edfs_image_t *img, edfs_inode_t *inode) {
    edfs_block_t block_nrs[EDFS_INODE_N_BLOCKS];
    for(int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
        block_nrs[i] = inode->inode.blocks[i];
    }

    inode->inode.type = EDFS_INODE_TYPE_INDIRECT;
    if(!allocate_block(img, &inode->inode.blocks[0])) {
        return -ENOSPC;
    }
    if(!allocate_block(img, &inode->inode.blocks[1])) {
        return -ENOSPC;
    }

    inode->inode.blocks[1] = 0;
    int NR_BLOCKS = edfs_get_n_blocks_per_indirect_block(&img->sb);
    edfs_block_t indirect_blocks[NR_BLOCKS];

    for(int i = 0; i < NR_BLOCKS; i++) {
        if (i < EDFS_INODE_N_BLOCKS) {
            indirect_blocks[i] = block_nrs[i];
        } else {
            indirect_blocks[i] = 0;
        }
    }

    pwrite(img->fd, indirect_blocks, img->sb.block_size, edfs_get_block_offset(&img->sb, inode->inode.blocks[0]));
    edfs_write_inode(img, inode);
    return 0;
}

static void make_inode_direct(edfs_image_t *img, edfs_inode_t *inode) {
    // find the first EDFS_INODE_N_BLOCKS in the indirect block
    // deallocate all others
    edfs_block_t block_nrs[EDFS_INODE_N_BLOCKS];
    int NR_BLOCKS = edfs_get_n_blocks_per_indirect_block(&img->sb);
    int blocks_found = 0;
    for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
        edfs_block_t indirect_blocks[NR_BLOCKS];
        pread(img->fd, indirect_blocks, img->sb.block_size, edfs_get_block_offset(&img->sb, inode->inode.blocks[0]));
        for(int j = 0; j < NR_BLOCKS; j++) {
            if (indirect_blocks[j] != 0) {
                if (blocks_found == EDFS_INODE_N_BLOCKS) {
                    deallocate_block(img, indirect_blocks[j]);
                } else {
                    block_nrs[blocks_found] = indirect_blocks[j];
                    blocks_found++;
                }
            }
        }
    }

    if (blocks_found < EDFS_INODE_N_BLOCKS) {
        for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
            block_nrs[i] = 0;
        }
    }


    inode->inode.type = EDFS_INODE_TYPE_FILE;

    for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
        inode->inode.blocks[i] = block_nrs[i];
    }

    edfs_write_inode(img, inode);
    return;
}


static int edfuse_write(const char *path, const char *buf, size_t size,
                        off_t offset, struct fuse_file_info *fi) {
    edfs_image_t *img = get_edfs_image();
    edfs_inode_t inode = {0};

    if (!edfs_find_inode(img, path, &inode)) return -ENOENT;
    if (edfs_disk_inode_is_directory(&inode.inode)) return -EISDIR;

    size_t block_size = img->sb.block_size;
    size_t bytes_to_write = size;
    size_t current_offset = 0;
    size_t bytes_written = 0;

    if (!edfs_disk_inode_has_indirect(&inode.inode)) {
        for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
            if (bytes_to_write <= 0) break;

            if (inode.inode.blocks[i] == 0) {
                if (!allocate_block(img, &inode.inode.blocks[i])) {
                    return -ENOSPC;
                } else {
                    edfs_write_inode(img, &inode);
                }
            }
            off_t block_offset = edfs_get_block_offset(&img->sb, inode.inode.blocks[i]);

            if (current_offset + block_size > offset) {
                size_t write_offset = 0;
                if (current_offset < offset) write_offset = offset - current_offset;
                size_t write_size = block_size - write_offset;
                if (write_size > bytes_to_write) write_size = bytes_to_write;

                pwrite(img->fd, buf + bytes_written, write_size, block_offset + write_offset);
                bytes_written += write_size;
                bytes_to_write -= write_size;
            }
            current_offset += block_size;
        }
        
        if(bytes_to_write > 0) {
            // There is still content left to write after filling up the EDFS_INODE_N_BLOCKS direct blocks...
            // inode needs to be made indirect...
            if(make_inode_indirect(img, &inode) == -ENOSPC) {
                return -ENOSPC;
            }

            offset += bytes_written;
            current_offset = 0;
        }
    }

    if (edfs_disk_inode_has_indirect(&inode.inode)) {
        for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
            if (inode.inode.blocks[i] == 0) continue;
            if (bytes_to_write <= 0) break;

            off_t indirect_block_offset = edfs_get_block_offset(&img->sb, inode.inode.blocks[i]);

            int NR_BLOCKS = edfs_get_n_blocks_per_indirect_block(&img->sb);
            edfs_block_t indirect_blocks[NR_BLOCKS];
            bool has_written_new_blocks = false;
            pread(img->fd, indirect_blocks, block_size, indirect_block_offset);

            for (size_t j = 0; j < NR_BLOCKS; j++) {
                if (bytes_to_write <= 0) break;
                if (indirect_blocks[j] == 0) {
                    if(!allocate_block(img, &indirect_blocks[j])) {
                        return -ENOSPC;
                    }
                    has_written_new_blocks = true;
                }
                off_t block_offset = edfs_get_block_offset(&img->sb, indirect_blocks[j]);

                if (current_offset + block_size > offset) {
                    size_t write_offset = 0;
                    if (current_offset < offset) write_offset = offset - current_offset;
                    size_t write_size = block_size - write_offset;
                    if (write_size > bytes_to_write) write_size = bytes_to_write;

                    pwrite(img->fd, buf + bytes_written, write_size, block_offset + write_offset);
                    bytes_written += write_size;
                    bytes_to_write -= write_size;
                }
                current_offset += block_size;
            }

            if(has_written_new_blocks) {
                pwrite(img->fd, indirect_blocks, block_size, indirect_block_offset);
            }
        }
    }

    if (offset + size > inode.inode.size) {
        inode.inode.size = offset + size;
    }
    edfs_write_inode(img, &inode);

    return bytes_written;
}


static int edfuse_truncate(const char *path, off_t offset) {
    edfs_image_t *img = get_edfs_image();
    edfs_inode_t inode = {0};

    if (!edfs_find_inode(img, path, &inode)) return -ENOENT;
    if (edfs_disk_inode_is_directory(&inode.inode)) return -EISDIR;
    if (offset == inode.inode.size) return 0;


    size_t block_size = img->sb.block_size;
    size_t new_block_count = offset / block_size;
    if (offset % block_size) new_block_count++;

    size_t old_block_count = inode.inode.size / block_size;
    if (inode.inode.size % block_size) old_block_count++;
    int NR_BLOCKS = edfs_get_n_blocks_per_indirect_block(&img->sb);

    if(edfs_disk_inode_has_indirect(&inode.inode)) {
        if(new_block_count < EDFS_INODE_N_BLOCKS) {
            // there are currently indirect blocks, but there is no need for this
            make_inode_direct(img, &inode);
        }
    } else {
        if(new_block_count > EDFS_INODE_N_BLOCKS) {
            // there are currently no indirect blocks, but there should be
            make_inode_indirect(img, &inode);
        }
    }


    if(edfs_disk_inode_has_indirect(&inode.inode)) {
        int blocks_seen = 0;
        for(int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
            if(inode.inode.blocks[i] == 0) continue;

            off_t block_offset = edfs_get_block_offset(&img->sb, inode.inode.blocks[i]);
            edfs_block_t indirect_blocks[NR_BLOCKS];
            pread(img->fd, indirect_blocks, block_size, block_offset);

            for(int j = 0; j < NR_BLOCKS; j++) {
                if(indirect_blocks[j] == 0) continue;
                if(blocks_seen >= new_block_count) {
                    deallocate_block(img, indirect_blocks[j]);
                    indirect_blocks[j] = 0;
                }
                blocks_seen++;
            }
            
            pwrite(img->fd, indirect_blocks, block_size, block_offset);
        }
    } else {
        // we have a direct block, and now with only new_block_count blocks
        edfs_block_t new_last_block = inode.inode.blocks[new_block_count - 1];
        // if offset falls within the last block, we need to cut off the remaining part of it
        if(offset % block_size) {
            // for the remainder of this block, write zeroes
            off_t block_offset = edfs_get_block_offset(&img->sb, new_last_block);

            char zeroes[block_size];
            memset(zeroes, 0, block_size);
            size_t write_size = block_size - (offset % block_size);
            pwrite(img->fd, zeroes, write_size, block_offset + (offset % block_size));
        }


        for(int i = new_block_count; i < EDFS_INODE_N_BLOCKS; i++) {
             deallocate_block(img, inode.inode.blocks[i]);
             inode.inode.blocks[i] = 0;
        }
    }

    inode.inode.size = offset;
    edfs_write_inode(img, &inode);

    return 0;
}


/*
 * FUSE setup
 */

static struct fuse_operations edfs_oper = {
    .readdir = edfuse_readdir,
    .mkdir = edfuse_mkdir,
    .rmdir = edfuse_rmdir,
    .getattr = edfuse_getattr,
    .open = edfuse_open,
    .create = edfuse_create,
    .unlink = edfuse_unlink,
    .read = edfuse_read,
    .write = edfuse_write,
    .truncate = edfuse_truncate,
};

int main(int argc, char *argv[]) {
    /* Count number of arguments without hyphens; excluding execname */
    int count = 0;
    for (int i = 1; i < argc; ++i)
        if (argv[i][0] != '-') count++;

    if (count != 2) {
        fprintf(stderr, "error: file and mountpoint arguments required.\n");
        return -1;
    }

    /* Extract filename argument; we expect this to be the
     * penultimate argument.
     */
    /* FIXME: can't this be better handled using some FUSE API? */
    const char *filename = argv[argc - 2];
    argv[argc - 2] = argv[argc - 1];
    argv[argc - 1] = NULL;
    argc--;

    /* Try to open the file system */
    edfs_image_t *img = edfs_image_open(filename, true);
    if (!img) return -1;

    /* Start fuse main loop */
    int ret = fuse_main(argc, argv, &edfs_oper, img);
    edfs_image_close(img);

    return ret;
}