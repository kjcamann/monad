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
 * This file defines the interface for reading event capture files
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_evcap_event_iterator;
struct monad_evcap_file_header;
struct monad_evcap_reader;
struct monad_evcap_section_desc;
struct monad_event_descriptor;

enum monad_evcap_section_type : uint16_t;
enum monad_event_content_type : uint16_t;

/// Create a reader for an event capture file
int monad_evcap_reader_create(
    struct monad_evcap_reader **, int fd, char const *error_name);

/// Destroy a reader for an event capture file created by an earlier call to
/// monad_evcap_reader_create
void monad_evcap_reader_destroy(struct monad_evcap_reader *);

/// Try to refresh the view an event capture file, if it has changed on disk
/// since the creation of the reader; if `invalidated` is not nullptr, then
/// `*invalidated` will be set to true if any memory addresses returned by this
/// API were invalidated by the refresh
int monad_evcap_reader_refresh(struct monad_evcap_reader *, bool *invalidated);

struct monad_evcap_file_header const *
monad_evcap_reader_get_file_header(struct monad_evcap_reader const *);

uint8_t const *
monad_evcap_reader_get_mmap_base(struct monad_evcap_reader const *);

struct monad_evcap_section_desc const *
monad_evcap_reader_load_linked_section_desc(
    struct monad_evcap_reader const *, uint64_t offset);

/// Return a section descriptor for the next section in the capture file;
/// see "section iteration" in the evcap.md documentation file
struct monad_evcap_section_desc const *monad_evcap_reader_next_section(
    struct monad_evcap_reader const *, enum monad_evcap_section_type filter,
    struct monad_evcap_section_desc const **);

/// Open an iterator to the events in an EVENT_BUNDLE section; if the section
/// is compressed, this will allocate memory to hold the decompressed contents,
/// and the user must call monad_evcap_iterator_close to free this memory
int monad_evcap_reader_open_iterator(
    struct monad_evcap_reader *, struct monad_evcap_section_desc const *,
    struct monad_evcap_event_iterator *);

/// Set the ring type, descriptor, and payload for the next event in the
/// EVENT_BUNDLE section referred to by the given iterator; returns false if
/// no event was available because all events have been visited
static bool monad_evcap_iterator_next(
    struct monad_evcap_event_iterator *, enum monad_event_content_type *,
    struct monad_event_descriptor const **, uint8_t const **payload);

/// Set the ring type, descriptor, and payload for the event present at the
/// given section offset; returns the next (unaligned) read/ address after the
/// event
static size_t monad_evcap_iterator_at_offset(
    struct monad_evcap_event_iterator const *, uint64_t section_offset,
    enum monad_event_content_type *, struct monad_event_descriptor const **,
    uint8_t const **payload);

/// Set the ring type, descriptor, and payload for the event with the given
/// sequence number; this is the "evcap equivalent" of the event ring
/// iterator's `monad_event_iterator_try_copy`; returns false if there's no
/// sequence number index or if the requested sequence number is out of range
static bool monad_evcap_iterator_copy_seqno(
    struct monad_evcap_event_iterator const *, uint64_t seqno,
    enum monad_event_content_type *, struct monad_event_descriptor const **,
    uint8_t const **payload);

void monad_evcap_iterator_close(struct monad_evcap_event_iterator *);

/// Return a description of the last event reader API error that occurred on
/// this thread
char const *monad_evcap_reader_get_last_error();

struct monad_evcap_seqno_index
{
    uint64_t const *offsets;
    uint64_t seqno_start;
    uint64_t seqno_end;
};

// clang-format off

struct monad_evcap_event_iterator
{
    uint8_t const *event_section_base;   ///< Base of EVENT_BUNDLE section mmap
    uint8_t const *event_section_next;   ///< Next event descriptor in section
    uint8_t const *event_section_end;    ///< Marks end of EVENT_BUNDLE section
    struct monad_evcap_seqno_index
        seqno_index;                     ///< Sequence number -> offset index
    size_t event_zstd_map_len;           ///< munmap info, if zstd EVENT_BUNDLE
    size_t seqno_zstd_map_len;           ///< munmap info, is zstd SEQNO_INDEX
};

// clang-format on

#ifdef __cplusplus
} // extern "C"
#endif

#define MONAD_EVCAP_READER_INTERNAL
#include "evcap_reader_inline.h"
#undef MONAD_EVCAP_READER_INTERNAL
