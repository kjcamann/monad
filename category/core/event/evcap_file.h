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
    uint64_t sectab_offset;
    uint64_t sectab_size;
    uint64_t section_count;
};

enum monad_evcap_section_type : uint16_t
{
    MONAD_EVCAP_SECTION_NONE,
    MONAD_EVCAP_SECTION_LINK,
    MONAD_EVCAP_SECTION_SCHEMA,
    MONAD_EVCAP_SECTION_EVENT_BUNDLE,
    MONAD_EVCAP_SECTION_SEQNO_INDEX,
    MONAD_EVCAP_SECTION_BLOCK_INDEX,
};

struct monad_evcap_schema_desc
{
    char ring_magic[6];
    enum monad_event_content_type content_type;
    uint8_t schema_hash[32];
};

struct monad_evcap_event_bundle_desc
{
    uint64_t event_count;
    uint64_t start_seqno;
    uint32_t block_index_id;
    uint32_t : 32;
    uint64_t seqno_index_desc_offset;
};

struct monad_evcap_seqno_index_desc
{
    uint64_t event_bundle_desc_offset;
};

struct monad_evcap_block_index_desc
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
    uint32_t : 32;
    uint64_t descriptor_offset;
    uint64_t content_offset;
    uint64_t content_length;
    uint64_t file_length;

    union
    {
        struct monad_evcap_schema_desc schema;
        struct monad_evcap_event_bundle_desc event_bundle;
        struct monad_evcap_block_index_desc block_index;
        struct monad_evcap_seqno_index_desc seqno_index;
        uint64_t padding[11];
    };
};

// It is OK to increase this is the size of the union increases, but it must
// be a power of 2 so that an array of these evenly fills an mmap'ed page
static_assert(sizeof(struct monad_evcap_section_desc) == 128);

extern char const *g_monad_evcap_section_names[];

#ifdef __cplusplus
} // extern "C"
#endif
