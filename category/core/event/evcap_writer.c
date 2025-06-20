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

#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <unistd.h>

#include <category/core/assert.h>
#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_writer.h>
#include <category/core/event/event_iterator.h>
#include <category/core/event/event_ring.h>
#include <category/core/format_err.h>
#include <category/core/mem/align.h>
#include <category/core/mem/virtual_buf.h>
#include <category/core/srcloc.h>

static thread_local char g_error_buf[1024];

constexpr size_t SECTION_TABLE_ENTRIES = 2048;
constexpr size_t SECTION_TABLE_EXTENT =
    SECTION_TABLE_ENTRIES * sizeof(struct monad_evcap_section_desc);

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        g_error_buf,                                                           \
        sizeof(g_error_buf),                                                   \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

struct monad_evcap_dynamic_section
{
    struct monad_evcap_section_desc *section_desc;
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
// If the array fills up, another section table is allocated and linked to
// the previous one using the MONAD_EVCAP_SECTION_LINK type
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
    struct monad_evcap_dynamic_section dyn_sec;
    struct monad_evcap_file_header *header;
};

static int check_dynamic_section(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dyn_sec)
{
    if (dyn_sec != &ecw->dyn_sec) {
        return FORMAT_ERRC(EINVAL, "invalid dynamic section");
    }
    if (ecw->dyn_sec.section_desc == nullptr) {
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

static int write_evcap_file_header(struct monad_evcap_writer *ecw)
{
    struct monad_evcap_file_header header = {
        .sectab_offset = ecw->mmap_page_size,
        .sectab_size = SECTION_TABLE_EXTENT};
    memcpy(
        &header.magic, MONAD_EVCAP_FILE_MAGIC, sizeof MONAD_EVCAP_FILE_MAGIC);
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
    struct section_table *sectab = malloc(sizeof *sectab);
    if (sectab == nullptr) {
        return FORMAT_ERRC(errno, "sectab allocation failed");
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
    if (ftruncate(
            ecw->fd, (off_t)(sectab->file_offset + SECTION_TABLE_EXTENT)) ==
            -1 ||
        lseek(ecw->fd, 0, SEEK_END) == -1) {
        free(sectab);
        return FORMAT_ERRC(
            errno, "growing evcap file failed while mapping new section table");
    }
    sectab->next = sectab->start = mmap(
        nullptr,
        SECTION_TABLE_EXTENT,
        PROT_WRITE,
        MAP_SHARED,
        ecw->fd,
        (off_t)sectab->file_offset);
    if (sectab->start == MAP_FAILED) {
        free(sectab);
        return FORMAT_ERRC(errno, "mmap of new section table failed");
    }
    sectab->end = sectab->start + SECTION_TABLE_ENTRIES;
    TAILQ_INSERT_TAIL(&ecw->section_tables, sectab, entry);
    return 0;
}

// Allocate a descriptor from the section table to write into; this may also
// allocate an entirely new section table if the current one is out of space
static struct monad_evcap_section_desc *
alloc_section_table_descriptor(struct monad_evcap_writer *ecw)
{
    struct section_table *cur_sectab =
        TAILQ_LAST(&ecw->section_tables, section_table_list);

    if (cur_sectab->next + 1 == cur_sectab->end) {
        struct section_table *next_sectab;
        // There is only one section table entry remaining. Append a new
        // section table to the end of the file and use the last entry to link
        // to the new one
        if (alloc_new_section_table(ecw) != 0) {
            return nullptr;
        }
        next_sectab = TAILQ_LAST(&ecw->section_tables, section_table_list);

        // Link the old section table to the new section table, then unmap the
        // old table
        ++ecw->header->section_count;
        cur_sectab->next->type = MONAD_EVCAP_SECTION_LINK;
        cur_sectab->next->descriptor_offset =
            cur_sectab->file_offset +
            sizeof(struct monad_evcap_section_desc) *
                (size_t)(cur_sectab->next - cur_sectab->start);
        cur_sectab->next->content_offset = next_sectab->file_offset;
        cur_sectab->next->file_length = SECTION_TABLE_EXTENT;

        cur_sectab = next_sectab;
    }

    ++ecw->header->section_count;
    cur_sectab->next->descriptor_offset =
        cur_sectab->file_offset +
        sizeof(struct monad_evcap_section_desc) *
            (size_t)(cur_sectab->next - cur_sectab->start);
    return cur_sectab->next++;
}

int monad_evcap_writer_create(struct monad_evcap_writer **ecw_p, int fd)
{
    struct monad_evcap_writer *ecw;
    int rc = 0;

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

    // Write the file header and map the initial section table
    if ((rc = write_evcap_file_header(ecw)) != 0) {
        goto Error;
    }
    if ((rc = alloc_new_section_table(ecw)) != 0) {
        goto Error;
    }
    return 0;

Error:
    monad_evcap_writer_destroy(ecw);
    *ecw_p = nullptr;
    return rc;
}

void monad_evcap_writer_destroy(struct monad_evcap_writer *ecw)
{
    if (ecw != nullptr) {
        struct section_table *s;
        while ((s = TAILQ_FIRST(&ecw->section_tables))) {
            TAILQ_REMOVE(&ecw->section_tables, s, entry);
            (void)munmap(s->start, SECTION_TABLE_EXTENT);
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
    struct monad_evcap_writer *ecw, enum monad_evcap_section_type type,
    size_t *size, struct monad_evcap_section_desc **desc_p)
{
    off_t cur_offset;
    struct monad_evcap_section_desc *desc = *desc_p =
        alloc_section_table_descriptor(ecw);
    if (desc == nullptr) {
        return FORMAT_ERRC(errno, "alloc_section_table_descriptor failed");
    }
    desc->type = type;
    *size = monad_round_size_to_align(*size, ecw->mmap_page_size);
    cur_offset = lseek(ecw->fd, 0, SEEK_END);
    if (cur_offset == -1) {
        return FORMAT_ERRC(errno, "could not seek to end for empty section");
    }
    desc->content_offset = (size_t)cur_offset;
    desc->file_length = *size;
    if (ftruncate(ecw->fd, (off_t)(desc->content_offset + desc->file_length)) ==
        -1) {
        return FORMAT_ERRC(errno, "ftruncate for empty section failed");
    }
    if (lseek(ecw->fd, 0, SEEK_END) == -1) {
        return FORMAT_ERRC(errno, "lseek after empty section failed");
    }
    return 0;
}

int monad_evcap_writer_add_schema_section(
    struct monad_evcap_writer *ecw, enum monad_event_content_type content_type,
    uint8_t const *schema_hash)
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
    return 0;
}

int monad_evcap_writer_dyn_sec_open(
    struct monad_evcap_writer *ecw,
    struct monad_evcap_dynamic_section **dyn_sec_p,
    struct monad_evcap_section_desc **sd)
{
    off_t cur_offset;

    *dyn_sec_p = nullptr;
    if (sd != nullptr) {
        *sd = nullptr;
    }

    // Only one dynamic section at a time is allowed
    if (ecw->dyn_sec.section_desc != nullptr) {
        return FORMAT_ERRC(EBUSY, "dynamic section is open");
    }
    ecw->dyn_sec.section_desc = alloc_section_table_descriptor(ecw);
    if (ecw->dyn_sec.section_desc == nullptr) {
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

    *dyn_sec_p = &ecw->dyn_sec;
    if (sd != nullptr) {
        *sd = ecw->dyn_sec.section_desc;
    }
    // Caller can set any fields except for `offset` (only set here), and
    // `length` (only set in monad_evcap_file_dyn_sec_{write,sendfile})
    (*sd)->content_offset = (uint64_t)cur_offset;

    return 0;
}

ssize_t monad_evcap_writer_dyn_sec_write(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dyn_sec,
    void const *buf, size_t size)
{
    int rc;
    ssize_t bytes_written;
    if ((rc = check_dynamic_section(ecw, dyn_sec)) != 0) {
        return -rc;
    }
    if ((bytes_written = write(ecw->fd, buf, size)) == -1) {
        return -FORMAT_ERRC(errno, "write of dynamic section contents failed");
    }
    dyn_sec->section_desc->file_length += (size_t)bytes_written;
    return bytes_written;
}

ssize_t monad_evcap_writer_dyn_sec_sendfile(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dyn_sec,
    int in_fd, off_t offset, size_t size)
{
    int rc;
    ssize_t bytes_written;
    if ((rc = check_dynamic_section(ecw, dyn_sec)) != 0) {
        return rc;
    }
    if ((bytes_written = sendfile(ecw->fd, in_fd, &offset, size)) == -1) {
        return -FORMAT_ERRC(errno, "dynamic section sendfile failed");
    }
    dyn_sec->section_desc->file_length += (size_t)bytes_written;
    return bytes_written;
}

ssize_t monad_evcap_writer_dyn_sec_sync_vbuf_segment(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dyn_sec,
    struct monad_vbuf_segment const *sync_segment)
{
    size_t written = 0;
    ssize_t bytes_wr;

    while (written < sync_segment->size) {
        bytes_wr = monad_evcap_writer_dyn_sec_sendfile(
            ecw, dyn_sec, sync_segment->fd, 0, sync_segment->size);
        if (bytes_wr < 0) {
            return bytes_wr;
        }
        written += (size_t)bytes_wr;
    }

    return (ssize_t)written;
}

ssize_t monad_evcap_writer_dyn_sec_sync_vbuf_chain(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dyn_sec,
    struct monad_vbuf_chain const *sync_chain)
{
    size_t written = 0;
    ssize_t bytes_wr;
    struct monad_vbuf_segment const *sync_segment;

    TAILQ_FOREACH(sync_segment, &sync_chain->segments, entry)
    {
        bytes_wr = monad_evcap_writer_dyn_sec_sync_vbuf_segment(
            ecw, dyn_sec, sync_segment);
        if (bytes_wr < 0) {
            return bytes_wr;
        }
        written += (size_t)bytes_wr;
    }

    return (ssize_t)written;
}

int monad_evcap_writer_dyn_sec_close(
    struct monad_evcap_writer *ecw, struct monad_evcap_dynamic_section *dyn_sec)
{
    ssize_t bytes_written;
    int rc;

    if ((rc = check_dynamic_section(ecw, dyn_sec)) != 0) {
        return rc;
    }
    // Ensure the file size is rounded off to a mmap page boundary
    if ((bytes_written = write_aligned(ecw, nullptr, 0)) < 0) {
        return (int)-bytes_written;
    }
    memset(&ecw->dyn_sec, 0, sizeof ecw->dyn_sec);
    return 0;
}

int monad_evcap_writer_commit_seqno_index(
    struct monad_evcap_writer *ecw, struct monad_vbuf_chain const *index_chain,
    enum monad_evcap_section_compression compression,
    size_t uncompressed_length,
    struct monad_evcap_section_desc *event_bundle_sd)
{
    int rc;
    ssize_t bytes_wr;
    struct monad_evcap_dynamic_section *dyn_sec;
    struct monad_evcap_section_desc *seqno_index_sd;

    rc = monad_evcap_writer_dyn_sec_open(ecw, &dyn_sec, &seqno_index_sd);
    if (rc != 0) {
        return FORMAT_ERRC(
            rc,
            "seqno index commit not open evcap dynamic section; caused by:\n%s",
            monad_evcap_writer_get_last_error());
    }

    seqno_index_sd->type = MONAD_EVCAP_SECTION_SEQNO_INDEX;
    seqno_index_sd->compression = compression;
    seqno_index_sd->seqno_index.event_bundle_desc_offset =
        event_bundle_sd->descriptor_offset;

    event_bundle_sd->event_bundle.seqno_index_desc_offset =
        seqno_index_sd->descriptor_offset;

    bytes_wr =
        monad_evcap_writer_dyn_sec_sync_vbuf_chain(ecw, dyn_sec, index_chain);
    if (bytes_wr < 0) {
        return FORMAT_ERRC(
            (int)-bytes_wr,
            "seqno index vbuf sync error, caused by:\n%s",
            monad_evcap_writer_get_last_error());
    }

    seqno_index_sd->content_length = compression == MONAD_EVCAP_COMPRESSION_NONE
                                         ? seqno_index_sd->file_length
                                         : uncompressed_length;

    return monad_evcap_writer_dyn_sec_close(ecw, dyn_sec);
}

int monad_evcap_vbuf_append_event(
    struct monad_vbuf_writer *vbuf_writer,
    enum monad_event_content_type content_type,
    struct monad_event_descriptor const *event, void const *payload,
    struct monad_vbuf_chain *vbuf_chain)
{
    int rc;

    // Write the event descriptor, payload, and event content type (to support
    // mixed content captures). The writes may need to insert padding to align
    // the next descriptor to a "safe" file offset:
    //
    //    .--------------.
    //    |  Descriptor  |
    //    .--------------.
    //    |    Payload   |
    //    .--------------.
    //    |   Ring type  |
    //    .--------------.
    //    | Tail padding |
    //    .--------------. <-- Aligned to alignof(monad_event_descriptor)
    //
    // This is needed because the reader will mmap this section, and may try
    // to copy the descriptor with an expression like `*copy = *event` rather
    // than memcpy. Event descriptors are over-aligned (to the cache line
    // size), and in optimized binaries this typed copy may be lowered to a
    // 64-byte aligned instruction such as the x64-64 AVX512 `vmovdqa64`. If
    // this happens at an unaligned address, this will fail (and it will appear
    // as a SIGSEGV with si_code set to SI_KERNEL, and the _wrong_ fault
    // address, rather than the expected SIGBUS). The eventcap utility's event
    // source "compatibility" iterator, for example, makes such copies to be
    // compatible with the event ring iterator.
    if ((rc = monad_vbuf_writer_memcpy(
             vbuf_writer,
             event,
             sizeof *event,
             alignof(struct monad_event_descriptor),
             vbuf_chain)) != 0) {
        return FORMAT_ERRC(
            rc,
            "vbuf couldn't append descriptor, caused by:\n%s",
            monad_vbuf_writer_get_last_error());
    }

    // memcpy to an "unaligned" address since it's slightly faster and we know
    // we're 64-byte aligned already
    if ((rc = monad_vbuf_writer_memcpy(
             vbuf_writer, payload, event->payload_size, 1, vbuf_chain)) != 0) {
        return FORMAT_ERRC(
            rc,
            "vbuf couldn't append payload, caused by:\n%s",
            monad_vbuf_writer_get_last_error());
    }

    if ((rc = monad_vbuf_writer_memcpy(
             vbuf_writer,
             &content_type,
             sizeof content_type,
             alignof(enum monad_event_content_type),
             vbuf_chain)) != 0) {
        return FORMAT_ERRC(
            rc,
            "vbuf couldn't append content_type code, caused by:\n%s",
            monad_vbuf_writer_get_last_error());
    }

    return 0;
}

char const *monad_evcap_writer_get_last_error()
{
    return g_error_buf;
}
