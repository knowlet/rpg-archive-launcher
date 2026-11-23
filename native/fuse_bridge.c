/* High-level libfuse 2 bridge. macFUSE owns FSKit transport; the
 * application never assumes an open /dev/fuse descriptor exists. */
#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

struct rpg_metadata { uint64_t size; uint32_t directory; uint32_t permissions; };
typedef int (*rpg_emit)(void *, const char *);
struct rpg_callbacks {
    int (*getattr)(void *, const char *, struct rpg_metadata *);
    int (*readdir)(void *, const char *, void *, rpg_emit);
    int (*access)(void *, const char *, int);
    int (*open)(void *, const char *, int, int, uint64_t *, uint32_t *);
    int (*read)(void *, uint64_t, char *, size_t, int64_t);
    int (*write)(void *, uint64_t, const char *, size_t, int64_t);
    int (*truncate)(void *, const char *, uint64_t, int64_t);
    int (*unlink)(void *, const char *);
    int (*rename)(void *, const char *, const char *);
    int (*fsync)(void *, uint64_t);
    int (*release)(void *, uint64_t);
};
struct rpg_context { void *state; const struct rpg_callbacks *cb; };
static struct rpg_context *rpg_context(void) {
    struct fuse_context *ctx = fuse_get_context();
    /* Do not serve another UID even if a backend ignores allow_other.
     * macOS FSKit credentials require real-host validation. */
    return ctx && ctx->uid == geteuid() ? ctx->private_data : NULL;
}
static int bridge_getattr(const char *path, struct stat *st) {
    struct rpg_context *ctx = rpg_context();
    if (!ctx) return -EACCES;
    struct rpg_metadata meta;
    int rc = ctx->cb->getattr(ctx->state, path, &meta);
    if (rc) return rc;
    if (meta.size > INT64_MAX) return -EOVERFLOW;
    memset(st, 0, sizeof(*st));
    st->st_mode = (meta.directory ? S_IFDIR : S_IFREG) | meta.permissions;
    st->st_nlink = meta.directory ? 2 : 1;
    st->st_uid = geteuid();
    st->st_gid = getegid();
    st->st_size = (off_t)meta.size;
    st->st_blksize = 4096;
    st->st_blocks = (blkcnt_t)((meta.size + 511) / 512);
    return 0;
}
struct rpg_directory_buffer { void *buffer; fuse_fill_dir_t fill; };
static int bridge_emit(void *opaque, const char *name) {
    struct rpg_directory_buffer *output = opaque;
    return output->fill(output->buffer, name, NULL, 0);
}
static int bridge_readdir(const char *path, void *buffer, fuse_fill_dir_t fill,
                          off_t offset, struct fuse_file_info *fi) {
    (void)offset; (void)fi;
    struct rpg_context *ctx = rpg_context();
    if (!ctx) return -EACCES;
    struct rpg_directory_buffer output = { buffer, fill };
    return ctx->cb->readdir(ctx->state, path, &output, bridge_emit);
}
static int bridge_access(const char *path, int mask) {
    struct rpg_context *ctx = rpg_context();
    return ctx ? ctx->cb->access(ctx->state, path, mask) : -EACCES;
}
static int bridge_open_inner(const char *path, struct fuse_file_info *fi, int create) {
    struct rpg_context *ctx = rpg_context();
    if (!ctx) return -EACCES;
    uint64_t handle = 0;
    uint32_t direct = 0;
    int rc = ctx->cb->open(ctx->state, path, fi->flags, create, &handle, &direct);
    if (rc) return rc;
    fi->fh = handle;
    fi->direct_io = direct != 0;
    fi->keep_cache = 0;
    return 0;
}
static int bridge_open(const char *path, struct fuse_file_info *fi) {
    return bridge_open_inner(path, fi, 0);
}
static int bridge_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode;
    return bridge_open_inner(path, fi, 1);
}
static int bridge_read(const char *path, char *buffer, size_t size, off_t offset,
                       struct fuse_file_info *fi) {
    (void)path;
    struct rpg_context *ctx = rpg_context();
    return ctx ? ctx->cb->read(ctx->state, fi->fh, buffer, size, (int64_t)offset) : -EACCES;
}
static int bridge_write(const char *path, const char *buffer, size_t size, off_t offset,
                        struct fuse_file_info *fi) {
    (void)path;
    struct rpg_context *ctx = rpg_context();
    return ctx ? ctx->cb->write(ctx->state, fi->fh, buffer, size, (int64_t)offset) : -EACCES;
}
static int bridge_truncate(const char *path, off_t size) {
    struct rpg_context *ctx = rpg_context();
    return ctx ? ctx->cb->truncate(ctx->state, path, 0, (int64_t)size) : -EACCES;
}
static int bridge_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) {
    struct rpg_context *ctx = rpg_context();
    return ctx ? ctx->cb->truncate(ctx->state, path, fi->fh, (int64_t)size) : -EACCES;
}
static int bridge_unlink(const char *path) {
    struct rpg_context *ctx = rpg_context();
    return ctx ? ctx->cb->unlink(ctx->state, path) : -EACCES;
}
static int bridge_rename(const char *from, const char *to) {
    struct rpg_context *ctx = rpg_context();
    return ctx ? ctx->cb->rename(ctx->state, from, to) : -EACCES;
}
static int bridge_fsync(const char *path, int data_only, struct fuse_file_info *fi) {
    (void)path; (void)data_only;
    struct rpg_context *ctx = rpg_context();
    return ctx ? ctx->cb->fsync(ctx->state, fi->fh) : -EACCES;
}
static int bridge_flush(const char *path, struct fuse_file_info *fi) {
    return bridge_fsync(path, 0, fi);
}
static int bridge_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    struct rpg_context *ctx = rpg_context();
    return ctx ? ctx->cb->release(ctx->state, fi->fh) : -EACCES;
}
int rpg_fuse_main(int argc, char **argv, void *state, const struct rpg_callbacks *cb) {
    struct rpg_context context = { state, cb };
    struct fuse_operations operations;
    memset(&operations, 0, sizeof(operations));
    operations.getattr = bridge_getattr;
    operations.readdir = bridge_readdir;
    operations.access = bridge_access;
    operations.open = bridge_open;
    operations.create = bridge_create;
    operations.read = bridge_read;
    operations.write = bridge_write;
    operations.truncate = bridge_truncate;
    operations.ftruncate = bridge_ftruncate;
    operations.unlink = bridge_unlink;
    operations.rename = bridge_rename;
    operations.fsync = bridge_fsync;
    operations.flush = bridge_flush;
    operations.release = bridge_release;
    return fuse_main(argc, argv, &operations, &context);
}
