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

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_reader.h>
#include <category/core/format_err.h>
#include <category/core/mem/align.h>
#include <category/core/srcloc.h>

#include <zstd.h>

static thread_local char g_error_buf[1024];

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        g_error_buf,                                                           \
        sizeof(g_error_buf),                                                   \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

struct monad_evcap_reader
{
    int fd;
    uint8_t const *map_base;
    size_t map_len;
};

static int decompress_section(
    struct monad_evcap_section_desc const *sd, void const *src, void **map_base,
    size_t *map_len)
{
    int rc;
    int memfd;
    size_t zstd_rc;
    char namebuf[32];

    *map_base = nullptr;
    snprintf(namebuf, sizeof namebuf, "sd:%lu", sd->content_offset);
    memfd = memfd_create(namebuf, 0);
    if (memfd == -1) {
        return FORMAT_ERRC(
            errno,
            "memfd_create failed for compressed %s section",
            g_monad_evcap_section_names[sd->type]);
    }
    *map_len =
        monad_round_size_to_align(sd->content_length, (size_t)getpagesize());
    if (ftruncate(memfd, (off_t)*map_len) == -1) {
        rc = FORMAT_ERRC(
            errno,
            "ftruncate failed for compressed %s section",
            g_monad_evcap_section_names[sd->type]);
        goto Error;
    }
    *map_base =
        mmap(nullptr, *map_len, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    if (*map_base == MAP_FAILED) {
        rc = FORMAT_ERRC(
            errno,
            "mmap failed for compressed %s section",
            g_monad_evcap_section_names[sd->type]);
        goto Error;
    }
    (void)close(memfd);
    memfd = -1;
    zstd_rc =
        ZSTD_decompress(*map_base, sd->content_length, src, sd->file_length);
    if (ZSTD_isError(zstd_rc)) {
        rc = FORMAT_ERRC(
            EIO,
            "zstd decompressed for compressed %s section: %s",
            g_monad_evcap_section_names[sd->type],
            ZSTD_getErrorName(zstd_rc));
        goto Error;
    }
    return 0;

Error:
    if (*map_base != MAP_FAILED && *map_base != nullptr) {
        munmap(*map_base, *map_len);
    }
    (void)close(memfd);
    return rc;
}

int monad_evcap_reader_create(
    struct monad_evcap_reader **ecr_p, int fd, char const *error_name)
{
    int rc;
    struct monad_evcap_reader *ecr;
    struct stat capture_stat;
    char fd_namebuf[32];

    if (error_name == nullptr) {
        (void)snprintf(fd_namebuf, sizeof fd_namebuf, "fd:%d", fd);
        error_name = fd_namebuf;
    }
    if (fstat(fd, &capture_stat) == -1) {
        return FORMAT_ERRC(
            errno, "fstat(2) of capture file `%s` failed", error_name);
    }
    *ecr_p = ecr = malloc(sizeof *ecr);
    if (ecr == nullptr) {
        return FORMAT_ERRC(errno, "malloc of evcap_reader failed");
    }
    memset(ecr, 0, sizeof *ecr);
    ecr->fd = dup(fd);
    if (ecr->fd == -1) {
        rc = FORMAT_ERRC(
            errno, "dup(2) of capture file `%s` fd %d failed", error_name, fd);
        goto Error;
    }

    ecr->map_len = (size_t)capture_stat.st_size;
    ecr->map_base =
        mmap(nullptr, ecr->map_len, PROT_READ, MAP_SHARED, ecr->fd, 0);
    if (ecr->map_base == MAP_FAILED) {
        rc = FORMAT_ERRC(errno, "mmap of capture file `%s` failed", error_name);
        goto Error;
    }
    if (ecr->map_len < (size_t)getpagesize() ||
        strncmp((char const *)ecr->map_base, "EVCAP_", sizeof "EVCAP_" - 1) !=
            0) {
        rc = FORMAT_ERRC(EINVAL, "`%s` is not a capture file", error_name);
        goto Error;
    }
    if (memcmp(
            ecr->map_base,
            MONAD_EVCAP_FILE_MAGIC,
            sizeof MONAD_EVCAP_FILE_MAGIC) != 0) {
        rc = FORMAT_ERRC(
            EINVAL,
            "`%s` has version %.*s, library uses version %.*s",
            error_name,
            (int)sizeof MONAD_EVCAP_FILE_MAGIC,
            (char const *)ecr->map_base,
            (int)sizeof MONAD_EVCAP_FILE_MAGIC,
            MONAD_EVCAP_FILE_MAGIC);
        goto Error;
    }
    return 0;

Error:
    monad_evcap_reader_destroy(ecr);
    *ecr_p = nullptr;
    return rc;
}

void monad_evcap_reader_destroy(struct monad_evcap_reader *ecr)
{
    if (ecr != nullptr) {
        (void)close(ecr->fd);
        if (ecr->map_base != nullptr) {
            (void)munmap((void *)ecr->map_base, ecr->map_len);
        }
        free(ecr);
    }
}

int monad_evcap_reader_refresh(
    struct monad_evcap_reader *ecr, bool *invalidated)
{
    struct stat capture_stat;
    void *new_map_base;

    if (invalidated != nullptr) {
        *invalidated = false;
    }
    if (fstat(ecr->fd, &capture_stat) == -1) {
        return FORMAT_ERRC(errno, "fstat(2) of capture file failed");
    }
    if ((size_t)capture_stat.st_size == ecr->map_len) {
        return 0;
    }
    // TODO(ken): investigate whether mremap really does what we want for this
    //  scenario; it does properly remap the extended file range, but never
    //  seems to preserve the base address even in simple cases; check if mmap
    //  with MAP_FIXED_NOREPLACE might work better here
    new_map_base = mremap(
        (void *)ecr->map_base, 0, (size_t)capture_stat.st_size, MREMAP_MAYMOVE);
    if (new_map_base == MAP_FAILED) {
        return FORMAT_ERRC(errno, "mremap of refreshed mapping failed");
    }
    if (invalidated != nullptr && new_map_base != ecr->map_base) {
        *invalidated = true;
    }
    ecr->map_base = new_map_base;
    ecr->map_len = (size_t)capture_stat.st_size;
    return 0;
}

struct monad_evcap_file_header const *
monad_evcap_reader_get_file_header(struct monad_evcap_reader const *ecr)
{
    return (struct monad_evcap_file_header const *)ecr->map_base;
}

uint8_t const *
monad_evcap_reader_get_mmap_base(struct monad_evcap_reader const *ecr)
{
    return ecr->map_base;
}

struct monad_evcap_section_desc const *
monad_evcap_reader_load_linked_section_desc(
    struct monad_evcap_reader const *ecr, uint64_t offset)
{
    return (struct monad_evcap_section_desc *)(ecr->map_base + offset);
}

struct monad_evcap_section_desc const *monad_evcap_reader_next_section(
    struct monad_evcap_reader const *ecr, enum monad_evcap_section_type filter,
    struct monad_evcap_section_desc const **sd_iter)
{
TryAgain:
    if (*sd_iter == nullptr) {
        // No previous iteration; reset iteration at the initial section table
        auto const header =
            (struct monad_evcap_file_header const *)ecr->map_base;
        *sd_iter =
            (struct monad_evcap_section_desc const *)(ecr->map_base +
                                                      header->sectab_offset);
    }
    else if ((*sd_iter)->type == MONAD_EVCAP_SECTION_LINK) {
        // Previous iteration found a link; jump to the linked section table
        *sd_iter = monad_evcap_reader_load_linked_section_desc(
            ecr, (*sd_iter)->content_offset);
    }
    else {
        // Advance past previous descriptor
        ++*sd_iter;
    }

    if ((*sd_iter)->type == MONAD_EVCAP_SECTION_NONE) {
        // This descriptor is the end sentinel
        *sd_iter = nullptr;
    }
    else if (filter != MONAD_EVCAP_SECTION_NONE && (*sd_iter)->type != filter) {
        // This descriptor is filtered out; look for another one
        goto TryAgain;
    }

    return *sd_iter;
}

int monad_evcap_reader_open_iterator(
    struct monad_evcap_reader *ecr,
    struct monad_evcap_section_desc const *event_sd,
    struct monad_evcap_event_iterator *iter)
{
    int rc;

    memset(iter, 0, sizeof *iter);
    if (event_sd == nullptr) {
        return 0;
    }
    if (event_sd->type != MONAD_EVCAP_SECTION_EVENT_BUNDLE) {
        return FORMAT_ERRC(EINVAL, "wrong section type %u", event_sd->type);
    }
    if (event_sd->compression != MONAD_EVCAP_COMPRESSION_NONE) {
        rc = decompress_section(
            event_sd,
            ecr->map_base + event_sd->content_offset,
            (void **)&iter->event_section_base,
            &iter->event_zstd_map_len);
        if (rc != 0) {
            return rc;
        }
        iter->event_section_end =
            iter->event_section_base + event_sd->content_length;
    }
    else {
        iter->event_section_base = ecr->map_base + event_sd->content_offset;
        iter->event_section_end =
            iter->event_section_base + event_sd->file_length;
    }
    iter->event_section_next = iter->event_section_base;

    if (event_sd->event_bundle.seqno_index_desc_offset != 0) {
        struct monad_evcap_section_desc const *const seqno_sd =
            monad_evcap_reader_load_linked_section_desc(
                ecr, event_sd->event_bundle.seqno_index_desc_offset);
        if (seqno_sd->compression != MONAD_EVCAP_COMPRESSION_NONE) {
            rc = decompress_section(
                seqno_sd,
                ecr->map_base + seqno_sd->content_offset,
                (void **)&iter->seqno_index.offsets,
                &iter->seqno_zstd_map_len);
            if (rc != 0) {
                return rc;
            }
        }
        else {
            iter->seqno_index.offsets =
                (uint64_t const *)(ecr->map_base + seqno_sd->content_offset);
        }
        iter->seqno_index.seqno_start = event_sd->event_bundle.start_seqno;
        iter->seqno_index.seqno_end =
            iter->seqno_index.seqno_start + event_sd->event_bundle.event_count;
    }

    return 0;
}

void monad_evcap_iterator_close(struct monad_evcap_event_iterator *iter)
{
    if (iter == nullptr || iter->event_section_base == nullptr) {
        return;
    }
    if (iter->event_zstd_map_len != 0) {
        (void)munmap(
            (void *)iter->event_section_base, iter->event_zstd_map_len);
    }
    if (iter->seqno_zstd_map_len != 0) {
        (void)munmap(
            (void *)iter->seqno_index.offsets, iter->seqno_zstd_map_len);
    }
    memset(iter, 0, sizeof *iter);
}

char const *monad_evcap_reader_get_last_error()
{
    return g_error_buf;
}

// XXX: evcap_file.h does not have its own translation unit, stick these here
// for now...
char const *g_monad_evcap_section_names[] = {
    [MONAD_EVCAP_SECTION_NONE] = "NONE",
    [MONAD_EVCAP_SECTION_LINK] = "LINK",
    [MONAD_EVCAP_SECTION_SCHEMA] = "SCHEMA",
    [MONAD_EVCAP_SECTION_EVENT_BUNDLE] = "EVENT_BUNDLE",
    [MONAD_EVCAP_SECTION_SEQNO_INDEX] = "SEQNO_INDEX",
    [MONAD_EVCAP_SECTION_BLOCK_INDEX] = "BLOCK_INDEX"};
