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
#include <string.h>

#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

#include <category/core/cleanup.h>
#include <category/core/path_help.h>

int monad_path_append(char **dst, char const *src, size_t *size)
{
    if (*dst == nullptr) {
        return 0;
    }
    if (*size == 0) {
        return ERANGE;
    }
    **dst = '/';
    *dst += 1;
    *size -= 1;
    size_t const n = strlcpy(*dst, src, *size);
    if (n >= *size) {
        *dst += *size;
        *size = 0;
        return ERANGE;
    }
    *dst += n;
    *size -= n;
    return 0;
}

int monad_path_open_subdir(
    int const init_dirfd, char const *path_suffix, mode_t mode,
    int *final_dirfd, char *namebuf, size_t namebuf_size)
{
    char *dir_name;
    char *tokctx;
    int rc = 0;
    int curfd = init_dirfd;
    bool const can_create = (mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != 0;
#ifdef O_PATH
    constexpr int OPEN_FLAGS = O_DIRECTORY | O_PATH;
#else
    constexpr int OPEN_FLAGS = O_DIRECTORY;
#endif

    if (final_dirfd != nullptr) {
        // Ensure the caller doesn't accidentally close something (i.e., stdin)
        // if they unconditionally close upon failure
        *final_dirfd = -1;
    }

    char *const path_components [[gnu::cleanup(cleanup_free)]] =
        strdup(path_suffix);
    if (path_components == nullptr) {
        return errno;
    }
    for (dir_name = strtok_r(path_components, "/", &tokctx); dir_name;
         dir_name = strtok_r(nullptr, "/", &tokctx)) {
        // This loop iterates over the path components in a path string; each
        // path component is the name of a directory.
        //
        // Within this loop, `dir_name` refers to the next path component and
        // `curfd` is an open file descriptor to the parent directory of
        // `dir_name`; the "walk" involves:
        //
        //   - appending the `dir_name` to `namebuf`; we do this first so that
        //     the user can tell which path segment an errno(3) code applies to
        //     in case one of the next two operations fails
        //
        //   - creating a directory named `dir_name` if it doesn't exist and
        //     we're allowed to create directories
        //
        //   - opening a file descriptor to `dir_name` as the new `curfd` with
        //     O_DIRECTORY (thereby checking if it is a directory in case we
        //     got EEXIST but it is some other type of file)
        //
        // When we're done, `curfd` is an open file descriptor to the last
        // directory in the path
        int nextfd;
        int lastfd;
        if (namebuf != nullptr) {
            rc = path_append(&namebuf, dir_name, &namebuf_size);
            if (rc != 0) {
                goto Done;
            }
        }
        if (can_create && mkdirat(curfd, dir_name, mode) == -1 &&
            errno != EEXIST) {
            rc = errno;
            goto Done;
        }
        nextfd = openat(curfd, dir_name, OPEN_FLAGS);
        if (nextfd == -1) {
            rc = errno;
            goto Done;
        }
        lastfd = curfd;
        curfd = nextfd;
        (void)close(lastfd);
    }

Done:
    if (final_dirfd != nullptr && rc != 0) {
        *final_dirfd = curfd;
    }
    else if (curfd != init_dirfd) {
        (void)close(curfd);
    }
    return rc;
}
