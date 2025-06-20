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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/event/evcap_writer.h>
#include <category/core/event/event_def.h>
#include <category/core/event/event_ring.h>
#include <category/core/format_err.h>
#include <category/core/path_util.h>
#include <category/core/srcloc.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

// Defined in blockcap_builder.c
extern thread_local char _g_monad_bcap_error_buf[1024];

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        _g_monad_bcap_error_buf,                                               \
        sizeof(_g_monad_bcap_error_buf),                                       \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

struct monad_bcap_block_archive
{
    int dirfd;
};

static int format_block_file_path(
    uint64_t block_number, char *path_buf, size_t path_buf_size,
    char const **subdir_end)
{
    int rc;
    char file_name_buf[32];

    // If we're allowed to create the file, then we'll try to create the
    // group directory with mkdirat(2)
    uint64_t const group_number = block_number / MONAD_BCAP_FILES_PER_SUBDIR;
    rc = snprintf(
        path_buf,
        path_buf_size,
        "%lu",
        group_number * MONAD_BCAP_FILES_PER_SUBDIR);
    if (rc < 0) {
        return FORMAT_ERRC(EINVAL, "snprintf error: %d", rc);
    }
    if ((size_t)rc >= path_buf_size) {
        return FORMAT_ERRC(
            ENAMETOOLONG,
            "path buffer size %zu is not large enough",
            path_buf_size);
    }
    // Advance path_buf so we can use monad_path_append with it, and remember
    // when the subdirectory ends
    path_buf += rc;
    path_buf_size -= (size_t)rc;
    if (subdir_end != nullptr) {
        *subdir_end = path_buf;
    }
    (void)sprintf(file_name_buf, "%zu.bcap", block_number);
    rc = monad_path_append(&path_buf, file_name_buf, &path_buf_size);
    if (rc != 0) {
        return FORMAT_ERRC(
            rc, "path append of %s to %s failed", file_name_buf, path_buf);
    }
    return 0;
}

int monad_bcap_block_archive_open(
    struct monad_bcap_block_archive **bca_p, int dirfd, char const *error_name)
{
    int rc;
    struct stat archive_stat;

    struct monad_bcap_block_archive *bca = *bca_p = malloc(sizeof *bca);
    if (bca == nullptr) {
        return FORMAT_ERRC(errno, "malloc of monad_bcap_block_archive failed");
    }
    bca->dirfd = dup(dirfd);
    if (bca->dirfd == -1) {
        rc =
            FORMAT_ERRC(errno, "dup of fd for archive `%s` failed", error_name);
        goto Error;
    }
    if (fstat(bca->dirfd, &archive_stat) == -1) {
        rc = FORMAT_ERRC(errno, "stat of archive `%s` file failed", error_name);
        goto Error;
    }
    if ((archive_stat.st_mode & S_IFDIR) != S_IFDIR) {
        rc = FORMAT_ERRC(ENOTDIR, "path `%s` is not directory", error_name);
        goto Error;
    }
    return 0;

Error:
    monad_bcap_block_archive_close(bca);
    *bca_p = nullptr;
    return rc;
}

void monad_bcap_block_archive_close(struct monad_bcap_block_archive *bca)
{
    if (bca != nullptr) {
        (void)close(bca->dirfd);
        free(bca);
    }
}

int monad_bcap_block_archive_open_block_fd(
    struct monad_bcap_block_archive const *bca, uint64_t const block_number,
    int const open_flags, mode_t const dir_create_mode,
    mode_t const file_create_mode, char *path_buf, size_t path_buf_size,
    int *const fd_out)
{
    char subdir_buf[32];
    char const *subdir_end;
    char local_path_buf[64];
    int fd;
    int rc;

    if (fd_out != nullptr) {
        *fd_out = -1;
    }
    if (path_buf == nullptr) {
        path_buf = local_path_buf;
        path_buf_size = sizeof local_path_buf;
    }

    // If we're allowed to create the file, then we'll try to create the
    // group directory with mkdirat(2)
    rc = format_block_file_path(
        block_number, path_buf, path_buf_size, &subdir_end);
    if (rc != 0) {
        return rc;
    }
    *(char *)mempcpy(subdir_buf, path_buf, (size_t)(subdir_end - path_buf)) =
        '\0';
    if (open_flags & (O_CREAT | O_TMPFILE)) {
        if (mkdirat(bca->dirfd, subdir_buf, dir_create_mode) == -1 &&
            errno != EEXIST) {
            return FORMAT_ERRC(
                errno,
                "unable to create directory %s to write block %lu",
                subdir_buf,
                block_number);
        }
    }
    fd = openat(
        bca->dirfd,
        open_flags & O_TMPFILE ? subdir_buf : path_buf,
        open_flags,
        file_create_mode);
    if (fd == -1) {
        return FORMAT_ERRC(
            errno, "could not open %s [block %lu]", path_buf, block_number);
    }
    if (fd_out != nullptr) {
        *fd_out = fd;
    }
    else {
        (void)close(fd);
    }
    return 0;
}

int monad_bcap_block_archive_open_block_reader(
    struct monad_bcap_block_archive const *bca, uint64_t block_number,
    char *path_buf, size_t path_buf_size, int *fd_out,
    struct monad_evcap_reader **evcap_reader_p,
    struct monad_evcap_section_desc const **event_bundle_sd_p)
{
    int rc;
    int fd;
    char local_path_buf[64];
    struct monad_evcap_section_desc const *sd;

    *evcap_reader_p = nullptr;
    *event_bundle_sd_p = nullptr;
    if (path_buf == nullptr) {
        path_buf = local_path_buf;
        path_buf_size = sizeof local_path_buf;
    }
    rc = monad_bcap_block_archive_open_block_fd(
        bca, block_number, O_RDONLY, 0, 0, path_buf, path_buf_size, &fd);
    if (rc != 0) {
        return rc;
    }

    // Create an event capture reader for the file, and check if the schema
    // is compatible with the current library
    rc = monad_evcap_reader_create(evcap_reader_p, fd, path_buf);
    if (fd_out != nullptr) {
        *fd_out = fd;
    }
    else {
        (void)close(fd);
    }
    if (rc != 0) {
        return FORMAT_ERRC(
            rc,
            "could not open evcap reader for %s; caused by:\n%s",
            path_buf,
            monad_evcap_reader_get_last_error());
    }
    if (monad_evcap_reader_check_schema(
            *evcap_reader_p,
            MONAD_EVENT_RING_HEADER_VERSION,
            MONAD_EVENT_CONTENT_TYPE_EXEC,
            g_monad_exec_event_schema_hash) != 0) {
        return FORMAT_ERRC(
            rc,
            "evcap reader schema check failed for %s; caused by:\n%s",
            path_buf,
            monad_evcap_reader_get_last_error());
    }

    // Find an EVENT_BUNDLE section with the EXEC content type and an explicitly
    // set block number; if there's more than one, it's an error
    sd = nullptr;
    while (monad_evcap_reader_next_section(
        *evcap_reader_p, MONAD_EVCAP_SECTION_EVENT_BUNDLE, &sd)) {
        struct monad_evcap_section_desc const *const schema_sd =
            monad_evcap_reader_load_linked_section_desc(
                *evcap_reader_p, sd->event_bundle.schema_desc_offset);
        if (schema_sd->schema.content_type != MONAD_EVENT_CONTENT_TYPE_EXEC) {
            continue;
        }
        if (sd->event_bundle.block_number == 0) {
            continue;
        }
        if (*event_bundle_sd_p != nullptr) {
            return FORMAT_ERRC(
                EOVERFLOW,
                "duplicate block event bundle sections in %s",
                path_buf);
        }
        *event_bundle_sd_p = sd;
    }

    return 0;
}

int monad_bcap_block_archive_open_block_writer(
    struct monad_bcap_block_archive *bca, uint64_t block_number,
    mode_t dir_create_mode, mode_t file_create_mode, char *path_buf,
    size_t path_buf_size, int *fd_out,
    struct monad_evcap_writer **evcap_writer_p,
    struct monad_evcap_section_desc const **schema_sd_p)
{
    int rc;
    int block_fd;
    char local_path_buf[64];
    struct monad_evcap_section_desc const *schema_sd;

    *evcap_writer_p = nullptr;
    if (path_buf == nullptr) {
        path_buf = local_path_buf;
        path_buf_size = sizeof local_path_buf;
    }
    if (fd_out != nullptr) {
        *fd_out = -1;
    }
    if (schema_sd_p != nullptr) {
        *schema_sd_p = nullptr;
    }

    rc = monad_bcap_block_archive_open_block_fd(
        bca,
        block_number,
        O_RDWR | O_TMPFILE,
        dir_create_mode,
        file_create_mode,
        path_buf,
        path_buf_size,
        &block_fd);
    if (rc != 0) {
        return rc;
    }
    rc = monad_evcap_writer_create(evcap_writer_p, block_fd, /*append*/ false);
    if (rc != 0) {
        FORMAT_ERRC(
            rc,
            "could not open evcap write for block %lu; caused by:\n%s",
            block_number,
            monad_evcap_writer_get_last_error());
        goto Error;
    }
    // Add SCHEMA section
    rc = monad_evcap_writer_add_schema_section(
        *evcap_writer_p,
        MONAD_EVENT_CONTENT_TYPE_EXEC,
        g_monad_exec_event_schema_hash,
        &schema_sd);
    if (rc != 0) {
        FORMAT_ERRC(
            rc,
            "could not write SCHEMA section write for block %lu; caused "
            "by:\n%s",
            block_number,
            monad_evcap_writer_get_last_error());
        goto Error;
    }
    if (schema_sd_p != nullptr) {
        *schema_sd_p = schema_sd;
    }
    if (fd_out != nullptr) {
        *fd_out = block_fd;
    }
    else {
        (void)close(block_fd);
    }
    return 0;

Error:
    monad_evcap_writer_destroy(*evcap_writer_p);
    (void)close(block_fd);
    return rc;
}

int monad_bcap_block_archive_close_block_writer(
    struct monad_bcap_block_archive *bca, uint64_t block_number,
    struct monad_evcap_writer *evcap_writer, char const *path_buf)
{
    char local_path_buf[64];
    int rc;
    int const block_fd = monad_evcap_writer_get_fd(evcap_writer);
    if (path_buf == nullptr) {
        rc = format_block_file_path(
            block_number, local_path_buf, sizeof local_path_buf, nullptr);
        if (rc != 0) {
            return rc;
        }
        path_buf = local_path_buf;
    }
    rc = 0;
    if (linkat(block_fd, "", bca->dirfd, path_buf, AT_EMPTY_PATH) == -1) {
        rc = FORMAT_ERRC(
            errno,
            "could not link block file %lu into the filesystem at %s",
            block_number,
            path_buf);
    }
    monad_evcap_writer_destroy(evcap_writer);
    return rc;
}
