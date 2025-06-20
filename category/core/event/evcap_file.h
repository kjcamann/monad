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

#pragma once

/**
 * @file
 *
 * This file defines structures in the "event capture" file format. This is a
 * simple file format optimized for reading and writing forensic captures of
 * event ring data.
 */

#include <stddef.h>
#include <stdint.h>

enum monad_event_content_type : uint16_t;

#ifdef __cplusplus
extern "C"
{
#endif

constexpr char const MONAD_EVCAP_FILE_MAGIC[] = {
    'E', 'V', 'C', 'A', 'P', '_', '0', '1'};

struct monad_evcap_file_header
{
    char magic[8];
    uint32_t section_count;
    uint8_t sectab_entries_shift;
    uint8_t sectab_count;
    uint64_t reserved[6];
    uint64_t sectab_offsets[1];
};

enum monad_evcap_section_type : uint16_t
{
    MONAD_EVCAP_SECTION_NONE,
    MONAD_EVCAP_SECTION_SCHEMA,
    MONAD_EVCAP_SECTION_EVENT_BUNDLE,
    MONAD_EVCAP_SECTION_SEQNO_INDEX,
    MONAD_EVCAP_SECTION_PACK_INDEX,
    MONAD_EVCAP_SECTION_COUNT,
};

// SCHEMA section: records the schema hash for a particular content type as
// was defined at the time of capture. The event ring file's magic number is
// also included, because it implies the version of the content_type enum
struct monad_evcap_schema_desc
{
    char ring_magic[6];
    enum monad_event_content_type content_type;
    uint8_t schema_hash[32];
};

// EVENT_BUNDLE section: the main section type in an event capture file, which
// stores event content. Event bundles are generic: they can contain events
// with any content_type, but all events must all be from same content type.
// Most fields in this descriptor do not apply to all event bundles, but give
// extra metadata for special kinds of capture files, e.g., block_number
// applies when a section contains all the events in one finalized block, and
// is used by block archive and pack files
struct monad_evcap_event_bundle_desc
{
    uint64_t schema_desc_offset;
    uint64_t event_count;
    uint64_t start_seqno;
    uint32_t pack_index_id;
    uint32_t : 32;
    uint64_t seqno_index_desc_offset;
    uint64_t block_number;
};

// SEQNO_INDEX section: a seqno index maps a sequence number to the offset in
// an event bundle section where the associated event is recorded; this section
// descriptor points to the corresponding event bundle descriptor
struct monad_evcap_seqno_index_desc
{
    uint64_t event_bundle_desc_offset;
};

// PACK_INDEX section: a "packed" bcap file has one EVENT_BUNDLE section for
// each finalized block, and a "pack index" (entries defined in blockcap.h)
// mapping the block numbers to EVENT_BUNDLE descriptor offsets
struct monad_evcap_pack_index_desc
{
    uint64_t start_block;
    uint32_t block_count;
    uint32_t entry_capacity;
    bool is_active;
};

enum monad_evcap_section_compression : uint8_t
{
    MONAD_EVCAP_COMPRESSION_NONE,
    MONAD_EVCAP_COMPRESSION_ZSTD_SINGLE_PASS,
    MONAD_EVCAP_COMPRESSION_ZSTD_STREAMING
};

struct monad_evcap_section_desc
{
    enum monad_evcap_section_type type;
    enum monad_evcap_section_compression compression;
    uint32_t index;
    uint64_t descriptor_offset;
    uint64_t content_offset;
    uint64_t content_length;
    uint64_t file_length;

    union
    {
        struct monad_evcap_schema_desc schema;
        struct monad_evcap_event_bundle_desc event_bundle;
        struct monad_evcap_pack_index_desc pack_index;
        struct monad_evcap_seqno_index_desc seqno_index;
        uint64_t padding[11];
    };
};

// It is OK to increase this is the size of the union increases, but it must
// be a power of 2 so that an array of these evenly fills an mmap'ed page
static_assert(sizeof(struct monad_evcap_section_desc) == 128);

static inline uint32_t
monad_evcap_get_sectab_entries(struct monad_evcap_file_header const *fh)
{
    return 1U << fh->sectab_entries_shift;
}

static inline size_t
monad_evcap_get_sectab_extent(struct monad_evcap_file_header const *fh)
{
    return sizeof(struct monad_evcap_section_desc) *
           monad_evcap_get_sectab_entries(fh);
}

static inline uint64_t monad_evcap_get_section_desc_offset(
    struct monad_evcap_file_header const *fh, uint32_t section_index)
{
    uint32_t const sectab_entries = monad_evcap_get_sectab_entries(fh);
    uint32_t const table_num = section_index / sectab_entries;
    uint32_t const entry_offset = section_index % sectab_entries;
    return fh->sectab_offsets[table_num] +
           sizeof(struct monad_evcap_section_desc) * entry_offset;
}

extern char const *g_monad_evcap_section_names[MONAD_EVCAP_SECTION_COUNT];

#ifdef __cplusplus
} // extern "C"
#endif
