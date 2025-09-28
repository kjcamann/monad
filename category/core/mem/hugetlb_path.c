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

#include <category/core/cleanup.h> // NOLINT(misc-include-cleaner)
#include <category/core/format_err.h>
#include <category/core/mem/hugetlb_path.h>
#include <category/core/path_help.h>
#include <category/core/srcloc.h>

#include <hugetlbfs.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

thread_local char g_error_buf[PATH_MAX];

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        g_error_buf,                                                           \
        sizeof g_error_buf,                                                    \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

int monad_hugetlbfs_open_dir_fd(
    struct monad_hugetlbfs_resolve_params const *params, int *dirfd,
    char *namebuf, size_t namebuf_size)
{
    size_t resolve_size;
    char const *hugetlbfs_mount_path;
    char local_namebuf[PATH_MAX];
#ifdef O_PATH
    constexpr int OPEN_FLAGS = O_DIRECTORY | O_PATH;
#else
    constexpr int OPEN_FLAGS = O_DIRECTORY;
#endif

    if (params == nullptr) {
        return FORMAT_ERRC(EFAULT, "params cannot be nullptr");
    }
    if (namebuf == nullptr) {
        namebuf = local_namebuf;
        namebuf_size = sizeof local_namebuf;
    }
    if (params->page_size == 0) {
        long default_size = gethugepagesize();
        if (default_size == -1) {
            return FORMAT_ERRC(errno, "no default huge page size configured");
        }
        resolve_size = (size_t)default_size;
    }
    else {
        resolve_size = params->page_size;
    }
    hugetlbfs_mount_path = hugetlbfs_find_path_for_size((long)resolve_size);
    if (hugetlbfs_mount_path == nullptr) {
        return FORMAT_ERRC(
            ENODEV, "no mounted hugetlbfs is accessible to this user");
    }
    if (namebuf != nullptr &&
        strlcpy(&namebuf, hugetlbfs_mount_path, namebuf_size) >= namebuf_size) {
        return FORMAT_ERRC(
            ERANGE, "namebuf cannot hold %s", hugetlbfs_mount_path);
    }
    int const mountfd = open(hugetlbfs_mount_path, OPEN_FLAGS);
    if (mountfd == -1) {
        return FORMAT_ERRC(
            errno, "open of hugetlbfs mount `%s` failed", hugetlbfs_mount_path);
    }
    int const rc = monad_path_open_subdir(
        mountfd,
        params->path_suffix,
        params->create_dirs ? params->dir_create_mode : 0,
        dirfd,
        namebuf,
        namebuf_size);
    if (rc != 0) {
        return FORMAT_ERRC(
            errno,
            "open_subdir of `%s` underneath `%s` failed at `%s`",
            params->path_suffix,
            hugetlbfs_mount_path,
            namebuf);
    }
    (void)close(mountfd);
    return rc;
}

char const *monad_hugetlbfs_get_last_error()
{
    return g_error_buf;
}
