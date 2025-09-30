// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <linux/limits.h>
#include <sys/types.h>

#include <category/core/event/event_ring.h>
#include <category/core/event/event_ring_util.h>
#include <category/core/format_err.h>
#include <category/core/path_util.h>
#include <category/core/srcloc.h>

#if !MONAD_EVENT_DISABLE_LIBHUGETLBFS
    #include <category/core/mem/hugetlb_path.h>
#endif

// Defined in event_ring.c, so we can share monad_event_ring_get_last_error()
extern thread_local char _g_monad_event_ring_error_buf[1024];

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        _g_monad_event_ring_error_buf,                                         \
        sizeof(_g_monad_event_ring_error_buf),                                 \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

static char const *g_event_ring_dir_override;

__attribute__((destructor)) static void free_override_dir()
{
    free((void *)g_event_ring_dir_override);
}

// Create MONAD_EVENT_DEFAULT_RING_DIR or override subpaths with with rwxrwxr-x
constexpr mode_t DIR_CREATE_MODE = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;

// libhugetlbfs is always present for Category Labs, but when this is compiled
// by third parties using the SDK, it is optional
#if MONAD_EVENT_DISABLE_LIBHUGETLBFS

static int open_event_ring_default_dir(int *, char *, size_t)
{
    return FORMAT_ERRC(
        ENOSYS,
        "no override event ring dir set, and compiled without libhugetlbfs "
        "support");
}

#else

static int
open_event_ring_default_dir(int *dirfd, char *pathbuf, size_t pathbuf_size)
{
    struct monad_hugetlbfs_resolve_params const params = {
        .page_size = 1UL << 21,
        .path_suffix = MONAD_EVENT_DEFAULT_RING_DIR,
        .create_dirs = true,
        .dir_create_mode = DIR_CREATE_MODE};
    int const rc =
        monad_hugetlbfs_open_dir_fd(&params, dirfd, pathbuf, pathbuf_size);
    if (rc != 0) {
        // Copy the error message directly, since we added nothing interesting
        strlcpy(
            _g_monad_event_ring_error_buf,
            monad_hugetlbfs_get_last_error(),
            sizeof _g_monad_event_ring_error_buf);
    }
    return rc;
}

#endif

int monad_event_ring_init_simple(
    struct monad_event_ring_simple_config const *ring_config, int ring_fd,
    off_t ring_offset, char const *error_name)
{
    struct monad_event_ring_size ring_size;
    int rc = monad_event_ring_init_size(
        ring_config->descriptors_shift,
        ring_config->payload_buf_shift,
        ring_config->context_large_pages,
        &ring_size);
    if (rc != 0) {
        return rc;
    }
    size_t const ring_bytes = monad_event_ring_calc_storage(&ring_size);
    rc = posix_fallocate(ring_fd, ring_offset, (off_t)ring_bytes);
    if (rc != 0) {
        return FORMAT_ERRC(
            rc,
            "posix_fallocate failed for event ring file `%s`, size %lu",
            error_name,
            ring_bytes);
    }
    return monad_event_ring_init_file(
        &ring_size,
        ring_config->content_type,
        ring_config->schema_hash,
        ring_fd,
        ring_offset,
        error_name);
}

int monad_event_ring_check_content_type(
    struct monad_event_ring const *event_ring,
    enum monad_event_content_type content_type, uint8_t const *schema_hash)
{
    if (event_ring == nullptr || event_ring->header == nullptr) {
        return FORMAT_ERRC(EFAULT, "event ring is not mapped");
    }
    if (event_ring->header->content_type != content_type) {
        return FORMAT_ERRC(
            EPROTO,
            "required event ring content type is %hu, file contains %hu",
            content_type,
            event_ring->header->content_type);
    }
    if (memcmp(
            event_ring->header->schema_hash,
            schema_hash,
            sizeof event_ring->header->schema_hash) != 0) {
        return FORMAT_ERRC(EPROTO, "event ring schema hash does not match");
    }
    return 0;
}

int monad_event_open_ring_dir_fd(int *dirfd, char *pathbuf, size_t pathbuf_size)
{
    char local_pathbuf[PATH_MAX];

    if (g_event_ring_dir_override == nullptr) {
        return open_event_ring_default_dir(dirfd, pathbuf, pathbuf_size);
    }

    if (pathbuf == nullptr) {
        pathbuf = local_pathbuf;
        pathbuf_size = sizeof local_pathbuf;
    }
    int const rc = monad_path_open_subdir(
        AT_FDCWD,
        g_event_ring_dir_override,
        DIR_CREATE_MODE,
        dirfd,
        pathbuf,
        pathbuf_size);
    if (rc != 0) {
        return FORMAT_ERRC(
            rc,
            "monad_path_open_subdir of `%s` failed at `%s`",
            g_event_ring_dir_override,
            pathbuf);
    }
    return rc;
}

int monad_event_set_ring_dir_override(char const *value)
{
    char const *new = nullptr;
    if (value != nullptr) {
        new = strdup(value);
        if (new == nullptr) {
            return FORMAT_ERRC(errno, "strdup of %s failed", value);
        }
    }
    char const *old =
        __atomic_exchange_n(&g_event_ring_dir_override, new, __ATOMIC_RELAXED);
    free((void *)old);
    return 0;
}

char const *monad_event_get_ring_dir_override()
{
    return g_event_ring_dir_override;
}

int monad_event_resolve_ring_file(
    char const *event_ring_path, char *pathbuf, size_t pathbuf_size)
{
    int rc;

    if (event_ring_path == nullptr || pathbuf == nullptr) {
        return FORMAT_ERRC(
            EFAULT, "event_ring_path and pathbuf cannot be nullptr");
    }
    if (event_ring_path == pathbuf) {
        return FORMAT_ERRC(EINVAL, "event_ring_path cannot alias pathbuf");
    }
    if (strchr(event_ring_path, '/') != nullptr) {
        // The event ring path contains a '/' character; this is resolved
        // relative to the current working directory
        if (strlcpy(pathbuf, event_ring_path, pathbuf_size) >= pathbuf_size) {
            return FORMAT_ERRC(
                ENAMETOOLONG,
                "event_ring_path %s overflows %zu size pathbuf",
                event_ring_path,
                pathbuf_size);
        }
        return 0;
    }

    // The event ring path does not contain a '/'; we assume this is a file
    // name relative to the default event ring directory, which is returned
    // by the function `monad_event_open_ring_dir_fd`
    rc = monad_event_open_ring_dir_fd(nullptr, pathbuf, pathbuf_size);
    if (rc != 0) {
        return rc;
    }
    size_t const default_dir_len = strlen(pathbuf);
    char *append = pathbuf + default_dir_len;
    pathbuf_size -= default_dir_len;
    rc = monad_path_append(&append, event_ring_path, &pathbuf_size);
    if (rc != 0) {
        return FORMAT_ERRC(
            rc,
            "monad_path_append of %s failed; partial: %s",
            event_ring_path,
            pathbuf);
    }
    return 0;
}
