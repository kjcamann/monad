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
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/types.h>

#include <category/core/event/evcap_file.h>
#include <category/core/event/evcap_writer.h>
#include <category/core/event/event_ring.h>
#include <category/core/format_err.h>
#include <category/core/mem/virtual_buf.h>
#include <category/core/srcloc.h>
#include <category/execution/ethereum/event/blockcap.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

// Defined in blockcap_builder.c
extern thread_local char _g_monad_blockcap_error_buf[1024];

#define FORMAT_ERRC(...)                                                       \
    monad_format_err(                                                          \
        _g_monad_blockcap_error_buf,                                           \
        sizeof(_g_monad_blockcap_error_buf),                                   \
        &MONAD_SOURCE_LOCATION_CURRENT(),                                      \
        __VA_ARGS__)

// XXX: fixed size index of 256k blocks for now
constexpr uint32_t BLOCK_INDEX_CAPACITY = 1U << 18;

struct monad_blockcap_writer
{
    struct monad_evcap_writer *evcap_writer;
    struct monad_blockcap_index_entry *index_entries;
    size_t index_entries_map_len;
    struct monad_evcap_block_index_desc *index_desc;
    bool desynchronized;
};

#if !defined(__clang__)

static inline void write_index_entry(
    struct monad_blockcap_index_entry *address,
    struct monad_blockcap_index_entry *value)
{

    __asm__ __volatile__("vmovdqa %1, %0" : "=m"(*address) : "x"(*value));
}

#else

static inline void write_index_entry(
    struct monad_blockcap_index_entry *address,
    struct monad_blockcap_index_entry *value)
{
    __atomic_store(address, value, __ATOMIC_RELEASE);
}

#endif

static int write_event_bundle_section(
    struct monad_blockcap_writer *bcw, struct monad_blockcap_proposal *proposal,
    struct monad_evcap_section_desc **event_sd_p)
{
    int rc;
    struct monad_evcap_dynamic_section *dyn_sec;
    struct monad_evcap_section_desc *event_sd;
    struct monad_evcap_writer *ecw = bcw->evcap_writer;

    *event_sd_p = nullptr;
    rc = monad_evcap_writer_dyn_sec_open(ecw, &dyn_sec, event_sd_p);
    if (rc != 0) {
        bcw->desynchronized = true;
        return FORMAT_ERRC(
            rc,
            "can't open dynamic section to write finalized block %lu, caused "
            "by:\n%s",
            proposal->block_tag.block_number,
            monad_evcap_writer_get_last_error());
    }
    event_sd = *event_sd_p;
    event_sd->type = MONAD_EVCAP_SECTION_EVENT_BUNDLE;
    event_sd->compression = proposal->event_compression_info.compression;
    event_sd->content_length =
        proposal->event_compression_info.uncompressed_length;
    event_sd->event_bundle.event_count = proposal->event_count;
    event_sd->event_bundle.start_seqno = proposal->start_seqno;
    event_sd->event_bundle.block_index_id = bcw->index_desc->block_count + 1;

    rc = (int)monad_evcap_writer_dyn_sec_sync_vbuf_chain(
        ecw, dyn_sec, &proposal->event_vbuf_chain);
    if (rc < 0) {
        bcw->desynchronized = true;
        return (int)-rc;
    }
    monad_vbuf_chain_free(&proposal->event_vbuf_chain);

    rc = monad_evcap_writer_dyn_sec_close(ecw, dyn_sec);
    if (rc != 0) {
        bcw->desynchronized = true;
        return FORMAT_ERRC(
            rc,
            "can't close dynamic section while writing finalized block %lu, "
            "caused by:\n%s",
            proposal->block_tag.block_number,
            monad_evcap_writer_get_last_error());
    }

    return 0;
}

int monad_blockcap_writer_create(struct monad_blockcap_writer **bcw_p, int fd)
{
    int rc;
    struct monad_blockcap_writer *bcw;
    struct monad_evcap_section_desc *index_sd;

    *bcw_p = bcw = malloc(sizeof *bcw);
    if (bcw == nullptr) {
        return FORMAT_ERRC(errno, "malloc of monad_blockcap_writer failed");
    }
    memset(bcw, 0, sizeof *bcw);
    if ((rc = monad_evcap_writer_create(&bcw->evcap_writer, fd)) != 0) {
        goto EVCAP_Error;
    }
    rc = monad_evcap_writer_add_schema_section(
        bcw->evcap_writer,
        MONAD_EVENT_CONTENT_TYPE_EXEC,
        g_monad_exec_event_schema_hash);
    if (rc != 0) {
        goto EVCAP_Error;
    }

    // Allocate an empty block index section in the file, and mark it active
    bcw->index_entries_map_len =
        BLOCK_INDEX_CAPACITY * sizeof(struct monad_blockcap_index_entry);
    rc = monad_evcap_writer_alloc_empty_section(
        bcw->evcap_writer,
        MONAD_EVCAP_SECTION_BLOCK_INDEX,
        &bcw->index_entries_map_len,
        &index_sd);
    if (rc != 0) {
        goto EVCAP_Error;
    }
    bcw->index_entries = mmap(
        nullptr,
        bcw->index_entries_map_len,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        monad_evcap_writer_get_fd(bcw->evcap_writer),
        (off_t)index_sd->content_offset);
    if (bcw->index_entries == MAP_FAILED) {
        rc = FORMAT_ERRC(errno, "mmap of blockcap_writer index entries failed");
        goto Error;
    }
    bcw->index_desc = &index_sd->block_index;
    bcw->index_desc->entry_capacity = BLOCK_INDEX_CAPACITY;
    __atomic_store_n(&bcw->index_desc->is_active, true, __ATOMIC_RELEASE);

    return 0;

EVCAP_Error:
    FORMAT_ERRC(
        rc,
        "cannot create blockcap writer, caused by:\n%s",
        monad_evcap_writer_get_last_error());
Error:
    monad_blockcap_writer_destroy(bcw);
    *bcw_p = nullptr;
    return rc;
}

void monad_blockcap_writer_destroy(struct monad_blockcap_writer *bcw)
{
    if (bcw != nullptr) {
        __atomic_store_n(&bcw->index_desc->is_active, false, __ATOMIC_RELEASE);
        if (bcw->index_entries != nullptr) {
            (void)munmap(bcw->index_entries, bcw->index_entries_map_len);
        }
        monad_evcap_writer_destroy(bcw->evcap_writer);
        free(bcw);
    }
}

struct monad_evcap_writer *
monad_blockcap_writer_get_evcap_writer(struct monad_blockcap_writer *bcw)
{
    return bcw->evcap_writer;
}

int monad_blockcap_writer_add_block(
    struct monad_blockcap_writer *bcw, struct monad_blockcap_proposal *proposal)
{
    struct monad_evcap_section_desc *event_sd;
    int rc;

    if (bcw->desynchronized) {
        return FORMAT_ERRC(ENOTRECOVERABLE, "blockcap writer desynchronized");
    }
    if (bcw->index_desc->block_count == bcw->index_desc->entry_capacity) {
        return FORMAT_ERRC(
            ENOSPC,
            "block index is full, all %u entries used",
            bcw->index_desc->block_count);
    }

    if ((rc = write_event_bundle_section(bcw, proposal, &event_sd)) != 0) {
        return rc;
    }

    if (proposal->seqno_index_vbuf_chain.segment_count > 0) {
        rc = monad_evcap_writer_commit_seqno_index(
            bcw->evcap_writer,
            &proposal->seqno_index_vbuf_chain,
            proposal->seqno_index_compression_info.compression,
            proposal->seqno_index_compression_info.uncompressed_length,
            event_sd);
        monad_vbuf_chain_free(&proposal->seqno_index_vbuf_chain);
        if (rc != 0) {
            bcw->desynchronized = true;
            return FORMAT_ERRC(
                rc,
                "can't commit seqno index while writing finalized block %lu, "
                "caused by:\n%s",
                proposal->block_tag.block_number,
                monad_evcap_writer_get_last_error());
        }
    }

    write_index_entry(
        &bcw->index_entries[bcw->index_desc->block_count],
        &(struct monad_blockcap_index_entry){
            .block_number = proposal->block_tag.block_number,
            .section_desc_offset = event_sd->content_offset,
        });

    if (bcw->index_desc->block_count == 0) {
        __atomic_store_n(
            &bcw->index_desc->start_block,
            proposal->block_tag.block_number,
            __ATOMIC_RELEASE);
    }
    __atomic_fetch_add(&bcw->index_desc->block_count, 1, __ATOMIC_ACQ_REL);
    return 0;
}
