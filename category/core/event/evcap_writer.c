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
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#if __has_include(<sys/sendfile.h>)
    #include <sys/sendfile.h>
    #define MONAD_EVENT_HAS_SENDFILE 1
#endif

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_writer.h>
#include <category/core/event/event_ring.h>
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

struct monad_evcap_dynamic_section
{
    struct monad_evcap_section_desc *section_desc;
    void *zstd_buf;
    size_t zstd_buf_len;
};

// The main index structure within an evcap file is called a section table:
// it contains information about where the capture data is located within the
// file. Capture data is organized into separate sections, and each is
// described by a "section descriptor", represented by an instance of
// `struct monad_evcap_section_desc`.
//
// The section table is a fixed size array of `monad_evcap_section_desc`
// entries which is allocated in the file and then mmap'd into our process,
// and is tracked by one of these objects.
//
// If the array fills up, another section table is allocated.
struct section_table
{
    size_t file_offset;
    struct monad_evcap_section_desc *start;
    struct monad_evcap_section_desc *next;
    struct monad_evcap_section_desc *end;
    TAILQ_ENTRY(section_table) entry;
};

TAILQ_HEAD(section_table_list, section_table);

struct monad_evcap_writer
{
    int fd;
    size_t mmap_page_size;
    struct section_table_list section_tables;
    struct monad_evcap_dynamic_section dynsec;
    struct monad_evcap_file_header *header;
};

static int check_dynamic_section(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dynsec)
{
    if (dynsec != &ecw->dynsec) {
        return FORMAT_ERRC(EINVAL, "invalid dynamic section");
    }
    if (ecw->dynsec.section_desc == nullptr) {
        return FORMAT_ERRC(ENODEV, "no dynamic section open");
    }
    return 0;
}

static ssize_t
write_aligned(struct monad_evcap_writer *ecw, void const *buf, size_t size)
{
    off_t cur_file_length;
    off_t aligned_file_length;
    ssize_t wr_bytes;

    wr_bytes = write(ecw->fd, buf, size);
    if (wr_bytes == -1) {
        return -FORMAT_ERRC(errno, "write of %lu bytes failed", size);
    }
    cur_file_length = lseek(ecw->fd, 0, SEEK_END);
    if (cur_file_length == -1) {
        return -FORMAT_ERRC(errno, "lseek to end failed");
    }
    aligned_file_length = (off_t)monad_round_size_to_align(
        (size_t)cur_file_length, ecw->mmap_page_size);
    if (aligned_file_length != cur_file_length) {
        if (ftruncate(ecw->fd, aligned_file_length) == -1) {
            return -FORMAT_ERRC(errno, "ftruncate to grow to alignment failed");
        }
        if (lseek(ecw->fd, 0, SEEK_END) == -1) {
            return -FORMAT_ERRC(
                errno, "lseek to end after growing file failed");
        }
        wr_bytes += aligned_file_length - cur_file_length;
    }
    return wr_bytes;
}

static int write_evcap_file_header(
    struct monad_evcap_writer *ecw, uint8_t sectab_entries_shift)
{
    struct monad_evcap_file_header header;
    memset(&header, 0, sizeof header);
    memcpy(
        &header.magic, MONAD_EVCAP_FILE_MAGIC, sizeof MONAD_EVCAP_FILE_MAGIC);
    header.sectab_entries_shift = sectab_entries_shift;
    if (write(ecw->fd, &header, sizeof header) == -1) {
        return FORMAT_ERRC(errno, "write of evcap header failed");
    }

    // We also map the header so section_count can be dynamically updated
    ecw->header = mmap(
        nullptr, sizeof header, PROT_READ | PROT_WRITE, MAP_SHARED, ecw->fd, 0);
    if (ecw->header == MAP_FAILED) {
        ecw->header = nullptr;
        return FORMAT_ERRC(errno, "mmap of evcap header failed");
    }

    return 0;
}

static int alloc_new_section_table(struct monad_evcap_writer *ecw)
{
    size_t const sectab_extent = monad_evcap_get_sectab_extent(ecw->header);
    struct section_table *sectab = malloc(sizeof *sectab);
    if (sectab == nullptr) {
        return FORMAT_ERRC(errno, "sectab allocation failed");
    }
    if (ecw->header->sectab_count == UINT8_MAX) {
        return FORMAT_ERRC(ENOSPC, "section table directory full");
    }
    memset(sectab, 0, sizeof *sectab);

    off_t const cur_offset = lseek(ecw->fd, 0, SEEK_END);
    if (cur_offset == -1) {
        free(sectab);
        return FORMAT_ERRC(
            errno, "lseek failed while mapping new section table");
    }
    sectab->file_offset =
        monad_round_size_to_align((size_t)cur_offset, ecw->mmap_page_size);
    // Grow the file to include space for the new section table, then update
    // the file descriptor's position to point beyond the end of the table
    if (ftruncate(ecw->fd, (off_t)(sectab->file_offset + sectab_extent)) ==
            -1 ||
        lseek(ecw->fd, 0, SEEK_END) == -1) {
        free(sectab);
        return FORMAT_ERRC(
            errno, "growing evcap file failed while mapping new section table");
    }
    sectab->next = sectab->start = mmap(
        nullptr,
        sectab_extent,
        PROT_WRITE,
        MAP_SHARED,
        ecw->fd,
        (off_t)sectab->file_offset);
    if (sectab->start == MAP_FAILED) {
        free(sectab);
        return FORMAT_ERRC(errno, "mmap of new section table failed");
    }
    sectab->end = sectab->start + monad_evcap_get_sectab_entries(ecw->header);
    TAILQ_INSERT_TAIL(&ecw->section_tables, sectab, entry);
    ecw->header->sectab_offsets[ecw->header->sectab_count++] =
        sectab->file_offset;
    return 0;
}

// Allocate a descriptor from the section table to write into; this may also
// allocate an entirely new section table if the current one is out of space
static struct monad_evcap_section_desc *
alloc_section_table_descriptor(struct monad_evcap_writer *ecw)
{
    struct section_table *cur_sectab =
        TAILQ_LAST(&ecw->section_tables, section_table_list);

    if (cur_sectab->next == cur_sectab->end) {
        // There are no section table entries remaining. Append a new section
        // section table to the end of the file
        errno = alloc_new_section_table(ecw);
        if (errno != 0) {
            return nullptr;
        }
        cur_sectab = TAILQ_LAST(&ecw->section_tables, section_table_list);
    }

    cur_sectab->next->index = ecw->header->section_count++;
    cur_sectab->next->descriptor_offset =
        cur_sectab->file_offset +
        sizeof(struct monad_evcap_section_desc) *
            (size_t)(cur_sectab->next - cur_sectab->start);
    return cur_sectab->next++;
}

static int create_writer_append(
    struct monad_evcap_writer *ecw, uint8_t sectab_entries_shift)
{
    // Map the file header
    ecw->header = mmap(
        nullptr,
        sizeof *ecw->header,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        ecw->fd,
        0);
    if (ecw->header == MAP_FAILED) {
        return FORMAT_ERRC(errno, "mmap of evcap header failed");
    }
    if (sectab_entries_shift != 0 &&
        sectab_entries_shift != ecw->header->sectab_entries_shift) {
        return FORMAT_ERRC(
            EINVAL,
            "incompatible sectab_entries_shift %hhu with what is already in "
            "file, %hhu",
            sectab_entries_shift,
            ecw->header->sectab_entries_shift);
    }
    if (lseek(ecw->fd, 0, SEEK_END) == -1) {
        return FORMAT_ERRC(errno, "lseek to end for append mode failed");
    }
    uint32_t const sectab_entries = monad_evcap_get_sectab_entries(ecw->header);
    size_t const sectab_extent = monad_evcap_get_sectab_extent(ecw->header);

    for (uint8_t t = 0; t < ecw->header->sectab_count; ++t) {
        uint64_t const next_sectab_offset = ecw->header->sectab_offsets[t];
        struct section_table *sectab = malloc(sizeof *sectab);
        if (sectab == nullptr) {
            return FORMAT_ERRC(errno, "sectab allocation failed");
        }
        memset(sectab, 0, sizeof *sectab);
        sectab->file_offset = next_sectab_offset;
        sectab->start = mmap(
            nullptr,
            sectab_extent,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            ecw->fd,
            (off_t)sectab->file_offset);
        if (sectab->start == MAP_FAILED) {
            free(sectab);
            return FORMAT_ERRC(errno, "mmap of new section table failed");
        }
        sectab->end = sectab->start + sectab_entries;
        TAILQ_INSERT_TAIL(&ecw->section_tables, sectab, entry);
        sectab->next = sectab->start;
        while (sectab->next->type != MONAD_EVCAP_SECTION_NONE) {
            ++sectab->next;
        }
    }
    return 0;
}

static int create_writer_truncate(
    struct monad_evcap_writer *ecw, uint8_t sectab_entries_shift)
{
    int rc;
    if (ftruncate(ecw->fd, 0) == -1) {
        return FORMAT_ERRC(errno, "ftruncate failed");
    }
    // Write the file header and map the initial section table
    if ((rc = write_evcap_file_header(ecw, sectab_entries_shift)) != 0) {
        return rc;
    }
    if ((rc = alloc_new_section_table(ecw)) != 0) {
        return rc;
    }
    return 0;
}

static ssize_t sync_vbuf_chain_zstd(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dynsec,
    struct monad_vbuf_chain const *sync_chain, ZSTD_CCtx *zstd_cctx)
{
    int rc;
    struct monad_vbuf_segment *sync_segment;
    ssize_t bytes_wr;
    size_t zrc;
    size_t written = 0;

    ZSTD_CCtx_reset(zstd_cctx, ZSTD_reset_session_only);
    zrc = ZSTD_CCtx_setPledgedSrcSize(zstd_cctx, sync_chain->vbuf_length);
    if (ZSTD_isError(zrc)) {
        rc = FORMAT_ERRC(
            EIO,
            "ZSTD_CCtx_setPledgedSrcSize failed for %lu: %s",
            sync_chain->vbuf_length,
            ZSTD_getErrorName(zrc));
        return -rc;
    }
    TAILQ_FOREACH(sync_segment, &sync_chain->segments, entry)
    {
        ZSTD_inBuffer in_buf = {
            .src = sync_segment->map_base,
            .size = sync_segment->written,
            .pos = 0};
        do {
            ZSTD_outBuffer out_buf = {
                .dst = dynsec->zstd_buf,
                .size = dynsec->zstd_buf_len,
                .pos = 0};
            zrc = ZSTD_compressStream2(
                zstd_cctx, &out_buf, &in_buf, ZSTD_e_continue);
            if (ZSTD_isError(zrc)) {
                rc = FORMAT_ERRC(
                    EIO,
                    "ZSTD_compressStream2 failed in vbuf: %s",
                    ZSTD_getErrorName(zrc));
                return -rc;
            }
            bytes_wr = monad_evcap_writer_dynsec_write(
                ecw, dynsec, dynsec->zstd_buf, out_buf.pos);
            if (bytes_wr < 0) {
                return bytes_wr;
            }
            written += (size_t)bytes_wr;
        }
        while (in_buf.pos != in_buf.size);
    }
    ZSTD_inBuffer in_buf = {.src = nullptr, .size = 0, .pos = 0};
    ZSTD_outBuffer out_buf = {
        .dst = dynsec->zstd_buf, .size = dynsec->zstd_buf_len, .pos = 0};
    do {
        zrc = ZSTD_compressStream2(zstd_cctx, &out_buf, &in_buf, ZSTD_e_end);
        if (ZSTD_isError(zrc)) {
            rc = FORMAT_ERRC(
                EIO,
                "ZSTD_compressStream2 failed in vbuf: %s",
                ZSTD_getErrorName(zrc));
            return -rc;
        }
        bytes_wr = monad_evcap_writer_dynsec_write(
            ecw, dynsec, dynsec->zstd_buf, out_buf.pos);
        if (bytes_wr < 0) {
            return bytes_wr;
        }
        written += (size_t)bytes_wr;
    }
    while (zrc != 0);
    return (ssize_t)written;
}

int monad_evcap_writer_create(
    struct monad_evcap_writer **ecw_p, int fd,
    struct monad_evcap_writer_create_options const *options)
{
    struct monad_evcap_writer *ecw;
    int rc = 0;

    if (options == nullptr) {
        return FORMAT_ERRC(EFAULT, "options cannot be nullptr");
    }

    uint8_t const min_sectab_entries_shift = (uint8_t)stdc_trailing_zeros(
        (size_t)getpagesize() / sizeof(struct monad_evcap_section_desc));
    uint8_t const sectab_entries_shift =
        options->sectab_entries_shift < min_sectab_entries_shift
            ? min_sectab_entries_shift
            : options->sectab_entries_shift;

    *ecw_p = ecw = malloc(sizeof *ecw);
    if (ecw == nullptr) {
        return FORMAT_ERRC(errno, "malloc of evcap_writer failed");
    }
    memset(ecw, 0, sizeof *ecw);
    ecw->mmap_page_size = (size_t)getpagesize();
    ecw->fd = dup(fd);
    if (ecw->fd == -1) {
        rc = FORMAT_ERRC(errno, "dup of %d failed", fd);
        goto Error;
    }
    TAILQ_INIT(&ecw->section_tables);

    return options->append
               ? create_writer_append(
                     ecw,
                     options->sectab_entries_shift == 0 ? 0
                                                        : sectab_entries_shift)
               : create_writer_truncate(ecw, sectab_entries_shift);

Error:
    monad_evcap_writer_destroy(ecw);
    *ecw_p = nullptr;
    return rc;
}

void monad_evcap_writer_destroy(struct monad_evcap_writer *ecw)
{
    if (ecw != nullptr) {
        struct section_table *s;
        size_t const sectab_extent = monad_evcap_get_sectab_extent(ecw->header);
        while ((s = TAILQ_FIRST(&ecw->section_tables))) {
            TAILQ_REMOVE(&ecw->section_tables, s, entry);
            (void)munmap(s->start, sectab_extent);
            free(s);
        }
        if (ecw->header != nullptr) {
            (void)munmap(ecw->header, sizeof *ecw->header);
        }
        (void)close(ecw->fd);
        free(ecw);
    }
}

int monad_evcap_writer_get_fd(struct monad_evcap_writer const *ecw)
{
    return ecw->fd;
}

int monad_evcap_writer_alloc_empty_section(
    struct monad_evcap_writer *ecw, size_t *size,
    struct monad_evcap_section_desc **desc_p)
{
    off_t cur_offset;
    size_t const requested_size = *size;
    struct monad_evcap_section_desc *desc = *desc_p =
        alloc_section_table_descriptor(ecw);
    if (desc == nullptr) {
        return FORMAT_ERRC(errno, "alloc_section_table_descriptor failed");
    }
    *size = monad_round_size_to_align(*size, ecw->mmap_page_size);
    cur_offset = lseek(ecw->fd, 0, SEEK_END);
    if (cur_offset == -1) {
        return FORMAT_ERRC(errno, "could not seek to end for empty section");
    }
    desc->content_offset = (size_t)cur_offset;
    desc->file_length = requested_size;
    if (ftruncate(ecw->fd, (off_t)(desc->content_offset + *size)) == -1) {
        return FORMAT_ERRC(errno, "ftruncate for empty section failed");
    }
    if (lseek(ecw->fd, 0, SEEK_END) == -1) {
        return FORMAT_ERRC(errno, "lseek after empty section failed");
    }
    return 0;
}

ssize_t monad_evcap_writer_new_section(
    struct monad_evcap_writer *const ecw, void const *const buf,
    size_t const nbyte, struct monad_evcap_section_desc **desc_p)
{
    int rc;
    size_t bytes_written = 0;
    size_t alloc_size = nbyte;

    rc = monad_evcap_writer_alloc_empty_section(ecw, &alloc_size, desc_p);
    if (rc != 0) {
        return rc;
    }
    do {
        off_t const write_offset =
            (off_t)((*desc_p)->content_offset + bytes_written);
        ssize_t const wr_rc = pwrite(
            ecw->fd, buf + bytes_written, nbyte - bytes_written, write_offset);
        if (wr_rc == -1) {
            return -FORMAT_ERRC(errno, "write of section contents failed");
        }
        bytes_written += (size_t)wr_rc;
    }
    while (bytes_written < nbyte);
    return (ssize_t)bytes_written;
}

int monad_evcap_writer_add_schema_section(
    struct monad_evcap_writer *ecw, enum monad_event_content_type content_type,
    uint8_t const *schema_hash, struct monad_evcap_section_desc const **sd_p)
{
    struct monad_evcap_section_desc *sd = alloc_section_table_descriptor(ecw);
    if (sd == nullptr) {
        return errno;
    }
    sd->type = MONAD_EVCAP_SECTION_SCHEMA;
    static_assert(
        sizeof sd->schema.ring_magic >= sizeof MONAD_EVENT_RING_HEADER_VERSION);
    memcpy(
        sd->schema.ring_magic,
        MONAD_EVENT_RING_HEADER_VERSION,
        sizeof MONAD_EVENT_RING_HEADER_VERSION);
    sd->schema.content_type = content_type;
    memcpy(sd->schema.schema_hash, schema_hash, sizeof sd->schema.schema_hash);
    if (sd_p != nullptr) {
        *sd_p = sd;
    }
    return 0;
}

int monad_evcap_writer_dynsec_open(
    struct monad_evcap_writer *ecw,
    struct monad_evcap_dynamic_section **dynsec_p,
    struct monad_evcap_section_desc **sd)
{
    off_t cur_offset;

    *dynsec_p = nullptr;
    if (sd != nullptr) {
        *sd = nullptr;
    }

    // Only one dynamic section at a time is allowed
    if (ecw->dynsec.section_desc != nullptr) {
        return FORMAT_ERRC(EBUSY, "dynamic section is open");
    }
    ecw->dynsec.section_desc = alloc_section_table_descriptor(ecw);
    if (ecw->dynsec.section_desc == nullptr) {
        return errno;
    }

    // Get the current position in the file where the dynamic section will
    // start writing; note that this cannot be moved before the call to
    // alloc_section_table_descriptor, which may change the file, e.g., if
    // it needs to add a linked section table
    cur_offset = lseek(ecw->fd, 0, SEEK_END);
    if (cur_offset == -1) {
        return FORMAT_ERRC(errno, "could not seek to end for dynamic section");
    }

    *dynsec_p = &ecw->dynsec;
    if (sd != nullptr) {
        *sd = ecw->dynsec.section_desc;
    }
    // Caller can set any fields except for `offset` (only set here), and
    // `length` (only set in monad_evcap_file_dynsec_{write,sendfile})
    (*sd)->content_offset = (uint64_t)cur_offset;

    return 0;
}

ssize_t monad_evcap_writer_dynsec_write(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dynsec,
    void const *buf, size_t const size)
{
    int rc;
    size_t bytes_written = 0;

    if ((rc = check_dynamic_section(ecw, dynsec)) != 0) {
        return -rc;
    }

    do {
        ssize_t const wr_rc =
            write(ecw->fd, buf + bytes_written, size - bytes_written);
        if (wr_rc == -1) {
            return -FORMAT_ERRC(
                errno, "write of dynamic section contents failed");
        }
        dynsec->section_desc->file_length += (size_t)wr_rc;
        bytes_written += (size_t)wr_rc;
    }
    while (bytes_written < size);

    return (ssize_t)size;
}

#if MONAD_EVENT_HAS_SENDFILE

ssize_t monad_evcap_writer_dynsec_sendfile(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dynsec,
    int const in_fd, off_t offset, size_t const size)
{
    int rc;
    size_t bytes_written = 0;

    if ((rc = check_dynamic_section(ecw, dynsec)) != 0) {
        return -rc;
    }

    do {
        ssize_t const wr_rc =
            sendfile(ecw->fd, in_fd, &offset, size - bytes_written);
        if (wr_rc == -1) {
            return -FORMAT_ERRC(errno, "dynamic section sendfile failed");
        }
        dynsec->section_desc->file_length += (size_t)wr_rc;
        bytes_written += (size_t)wr_rc;
    }
    while (bytes_written < size);

    return (ssize_t)size;
}

#else // MONAD_EVENT_HAS_SENDFILE

// We either don't have sendfile(2) at all, or it only works with sockets
ssize_t monad_evcap_writer_dynsec_sendfile(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dynsec,
    int const in_fd, off_t offset, size_t const size)
{
    constexpr size_t READBUF_SIZE = 1UL << 21;
    static thread_local uint8_t readbuf[READBUF_SIZE];
    int rc;
    size_t residual = size;

    if ((rc = check_dynamic_section(ecw, dynsec)) != 0) {
        return -rc;
    }

    do {
        ssize_t bytes_read;
        size_t const buf_space =
            residual > READBUF_SIZE ? READBUF_SIZE : residual;
        if ((bytes_read = pread(in_fd, readbuf, buf_space, offset)) == -1) {
            return -FORMAT_ERRC(
                errno, "dynamic section read failed at %ld", (long)offset);
        }
        ssize_t const write_rc = monad_evcap_writer_dynsec_write(
            ecw, dynsec, readbuf, (size_t)bytes_read);
        if (write_rc < 0) {
            return write_rc;
        }
        offset += (size_t)bytes_read;
        residual -= (size_t)bytes_read;
    }
    while (residual > 0);

    return (ssize_t)size;
}

#endif

ssize_t monad_evcap_writer_dynsec_sync_vbuf_chain(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dynsec,
    struct monad_vbuf_chain const *sync_chain, ZSTD_CCtx *zstd_cctx)
{
    size_t written = 0;
    ssize_t bytes_wr;
    struct monad_vbuf_segment const *sync_segment;

    if (zstd_cctx != nullptr) {
        if (dynsec->zstd_buf == nullptr) {
            dynsec->zstd_buf_len = ZSTD_CStreamOutSize();
            dynsec->zstd_buf = malloc(dynsec->zstd_buf_len);
            if (dynsec->zstd_buf == nullptr) {
                return -FORMAT_ERRC(
                    errno,
                    "malloc of zstd output buffer failed: %lu",
                    dynsec->zstd_buf_len);
            }
        }
        return sync_vbuf_chain_zstd(ecw, dynsec, sync_chain, zstd_cctx);
    }
    else {
        TAILQ_FOREACH(sync_segment, &sync_chain->segments, entry)
        {
            bytes_wr = monad_evcap_writer_dynsec_write(
                ecw, dynsec, sync_segment->map_base, sync_segment->written);
            if (bytes_wr < 0) {
                return bytes_wr;
            }
            written += (size_t)bytes_wr;
        }
    }

    return (ssize_t)written;
}

int monad_evcap_writer_dynsec_close(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dynsec)
{
    ssize_t bytes_written;
    int rc;

    if ((rc = check_dynamic_section(ecw, dynsec)) != 0) {
        return rc;
    }
    // Ensure the file size is rounded off to a mmap page boundary
    bytes_written = write_aligned(ecw, nullptr, 0);
    if (bytes_written < 0) {
        return (int)-bytes_written;
    }
    free(dynsec->zstd_buf);
    memset(&ecw->dynsec, 0, sizeof ecw->dynsec);
    return 0;
}

char const *monad_evcap_writer_get_last_error()
{
    return g_error_buf;
}
