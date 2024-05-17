/* EdFS -- An educational file system
 *
 * Copyright (C) 2017,2019  Leiden University, The Netherlands.
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

/* Searches the file system hierarchy to find the inode for
 * the given path. Returns true if the operation succeeded.
 *
 * IMPORTANT: TODO: this function is not yet complete, you have to
 * finish it! See below and Section 4.1 of the Appendices PDF.
 */
static bool edfs_find_inode(edfs_image_t *img, const char *path,
                            edfs_inode_t *inode) {
    printf("path: %s\n", path);
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
            // TODOR: Hier 1 functie van maken en gebruiken bij zowel find_inode
            // als readdir
            const int DIR_SIZE = edfs_get_n_dir_entries_per_block(&img->sb);
            bool found = false;
            for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
                if (current_inode.inode.blocks[i] == 0) continue;
                off_t offset = edfs_get_block_offset(
                    &img->sb, current_inode.inode.blocks[i]);
                edfs_dir_entry_t dir[DIR_SIZE];
                pread(img->fd, dir, img->sb.block_size, offset);

                for (int j = 0; j < DIR_SIZE; j++) {
                    if (!strcmp(dir[j].filename, direntry.filename) &&
                        dir[j].inumber != 0) {
                        direntry.inumber = dir[j].inumber;
                        found = true;
                    }
                }
            }

            if (found) {
                /* Found what we were looking for, now get our new inode. */
                current_inode.inumber = direntry.inumber;
                edfs_read_inode(img, &current_inode);
            } else
                return false;
        }

        path = end;
    }

    *inode = current_inode;

    return true;
}
/* TODO: visit the directory entries of parent_inode and look
 * for a directory entry with the same filename as
 * direntry.filename. If found, fill in direntry.inumber with
 * the corresponding inode number.
 *
 * Write a generic function which visits directory entries,
 * you are going to need this more often. Consider implementing
 * a callback mechanism.
 */

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
    edfs_inode_t inode = {
        0,
    };
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
            if (dir[j].inumber != 0) {
                char *filename = dir[j].filename;
                filler(buf, filename, NULL, 0);
            }
        }
    }

    return 0;
}

static int edfuse_mkdir(const char *path, mode_t mode) {
    /* TODO: implement.
     *
     * See also Section 4.3 of the Appendices document.
     *
     * Create a new inode, register in parent directory, write inode to
     * disk.
     */
    return -ENOSYS;
}

static int edfuse_rmdir(const char *path) {
    printf("path: %s\n", path);
    // char* filename = strrchr(path, '/');
    // filename = filename + strlen(filename) - 1;

    edfs_image_t *img = get_edfs_image();
    edfs_inode_t inode = {
        0,
    };
    if (!edfs_find_inode(img, path, &inode)) return -ENOENT;

    if (!edfs_disk_inode_is_directory(&inode.inode)) return -ENOTDIR;

    for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
        if (!inode.inode.blocks[i] == 0) return ENOTEMPTY;
    }
    edfs_inode_t parent_inode;
    edfs_get_parent_inode(img, path, &parent_inode);

    const int DIR_SIZE = edfs_get_n_dir_entries_per_block(&img->sb);

    for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
        if (parent_inode.inode.blocks[i] == 0) continue;
        off_t offset =
            edfs_get_block_offset(&img->sb, parent_inode.inode.blocks[i]);
        edfs_dir_entry_t dir[DIR_SIZE];
        pread(img->fd, dir, img->sb.block_size, offset);

        for (int j = 0; j < DIR_SIZE; j++) {
            if (!strcmp(dir[j].inumber, inode.inumber) && dir[j].inumber != 0) {
                // remove dir[j]
            }
        }
    }
    edfs_clear_inode(&img, &inode);

    /* TODO: implement
     *
     * See also Section 4.3 of the Appendices document.
     *
     * Validate @path exists and is a directory; remove directory entry
     * from parent directory; release allocated blocks; release inode.
     */
    return -ENOSYS;
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
    /* TODO: implement
     *
     * See also Section 4.4 of the Appendices document.
     *
     * Create a new inode, attempt to register in parent directory,
     * write inode to disk.
     */

    // filenames are restricted to 59 bytes (excluding null-terminator) and may
    // only contain: A-Z, a-z, 0-9, spaces (“ ”) and dots (“.”).
    return -ENOSYS;
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
    edfs_inode_t inode = {
        0,
    };

    int bytes_read = 0;

    if (!edfs_find_inode(img, path, &inode)) return -ENOENT;

    if (edfs_disk_inode_is_directory(&inode.inode)) return -EISDIR;

    if (!edfs_disk_inode_has_indirect(&inode.inode)) {
        for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
            if (inode.inode.blocks[i] == 0) break;
            off_t offset =
                edfs_get_block_offset(&img->sb, inode.inode.blocks[i]);
            char text[img->sb.block_size];
            uint64_t bytes_to_read = img->sb.block_size;
            if(offset + bytes_to_read > inode.inode.size) {
                bytes_to_read = inode.inode.size - offset;
            }
            if(bytes_read + bytes_to_read > size) {
                bytes_to_read = size - bytes_read;
            }
            if(bytes_to_read <= 0) {
                break;
            }
            pread(img->fd, buf + bytes_read, bytes_to_read, offset);
            bytes_read += img->sb.block_size;
        }
    } else {
        for (int i = 0; i < EDFS_INODE_N_BLOCKS; i++) {
            if (inode.inode.blocks[i] == 0) continue;
            off_t block_offset =
                edfs_get_block_offset(&img->sb, inode.inode.blocks[i]);

            // In het geval van grote files zijn blocks indirect blocks (check
            // edfs_disk_inode_has_indirect)

            int NR_BLOCKS = edfs_get_n_blocks_per_indirect_block(&img->sb);
            edfs_block_t indirect_blocks[NR_BLOCKS];
            pread(img->fd, indirect_blocks, img->sb.block_size, block_offset);
            // Indirect block bevat een array aan edfs_block_t, dus NR_BLOCKS
            // aantal pointers naar blocks
            for (size_t j = 0; j < NR_BLOCKS; j++) {
                if (indirect_blocks[j] == 0) {
                    break;
                }
                // Lees de j-de text block uit
                block_offset =
                    edfs_get_block_offset(&img->sb, indirect_blocks[j]);
                
                uint16_t bytes_to_read = img->sb.block_size;
                if(offset + bytes_to_read > inode.inode.size) {
                    bytes_to_read = inode.inode.size - offset;
                }
                if(bytes_read + bytes_to_read > size) {
                    bytes_to_read = size - bytes_read;
                }
                if(bytes_to_read <= 0) {
                    break;
                }

                pread(img->fd, buf + bytes_read, bytes_to_read, block_offset);
                bytes_read += img->sb.block_size;
            }
        }
    }
    return bytes_read;
}

static int edfuse_write(const char *path, const char *buf, size_t size,
                        off_t offset, struct fuse_file_info *fi) {
    /* TODO: implement
     *
     * See also Section 4.4 of the Appendices document.
     *
     * Write @size bytes of data from @buf to @path starting at @offset.
     * Allocate new blocks as necessary. You may have to fill holes! Update
     * the file size if necessary.
     */
    return -ENOSYS;
}

static int edfuse_truncate(const char *path, off_t offset) {
    /* TODO: implement
     *
     * See also Section 4.4 of the Appendices document.
     *
     * The size of @path must be set to be @offset. Release now superfluous
     * blocks or allocate new blocks that are necessary to cover offset.
     */
    return -ENOSYS;
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
