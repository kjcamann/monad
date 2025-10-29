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

struct monad_evcap_event_iter;
struct monad_evcap_event_section;
struct monad_evcap_file_header;
struct monad_evcap_reader;
struct monad_evcap_section_desc;
struct monad_event_descriptor;

enum monad_evcap_section_type : uint16_t;
enum monad_event_content_type : uint16_t;

/// Result of trying to read an event descriptor and payload from an event
/// capture file; MONAD_EVCAP_READ_END is returned when ++i (or --i) is after
/// (or before) the captured event range, or if seeking to any sequence number
/// outside the capture range; MONAD_EVCAP_READ_NO_SEQNO is returned if the
/// capture does not contain a sequence number index at all
typedef enum monad_evcap_read_result
    : uint16_t
{
    MONAD_EVCAP_READ_SUCCESS = 0,
    MONAD_EVCAP_READ_END = 0x0200,
    MONAD_EVCAP_READ_NO_SEQNO = 0x0201,
} monad_evcap_read_result_t;

/// Create a reader for an event capture file
int monad_evcap_reader_create(
    struct monad_evcap_reader **, int fd, char const *error_name);

/// Destroy a reader for an event capture file
void monad_evcap_reader_destroy(struct monad_evcap_reader *);

/// Try to refresh the view an event capture file, if it has changed on disk
/// since the creation of the reader; if `invalidated` is not nullptr, then
/// `*invalidated` will be set to true if any memory address returned by this
/// API was potentially invalidated by the refresh
int monad_evcap_reader_refresh(struct monad_evcap_reader *, bool *invalidated);

struct monad_evcap_file_header const *
monad_evcap_reader_get_file_header(struct monad_evcap_reader const *);

/// Return the base address where the capture file bits are mmap'ed
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

/// Check that the capture file contains a SCHEMA section descriptor with the
/// given content_type and schema_hash; returns 0 upon success, ENOMSG if no
/// such section was found, EPROTO if it does not match, and EBADMSG if there
/// are multiple descriptors for the same content_type (even if they match)
int monad_evcap_reader_check_schema(
    struct monad_evcap_reader const *, uint8_t const *ring_magic,
    enum monad_event_content_type, uint8_t const *schema_hash);

/// Open an EVENT_BUNDLE section; if the section is compressed, this will
/// allocate memory to hold the decompressed contents, and the user must call
/// monad_evcap_event_section_close to free this memory
int monad_evcap_event_section_open(
    struct monad_evcap_event_section *, struct monad_evcap_reader const *,
    struct monad_evcap_section_desc const *);

/// Close an EVENT_BUNDLE and free any dynamically allocated memory for
/// decompressed section content
void monad_evcap_event_section_close(struct monad_evcap_event_section *);

/// Open an iterator to the events in an EVENT_BUNDLE section
static void monad_evcap_event_section_open_iterator(
    struct monad_evcap_event_section const *, struct monad_evcap_event_iter *);

/// Set the event descriptor and payload for the event present at the given
/// section offset; returns the next (unaligned) read address after the event
static size_t monad_evcap_event_section_at_offset(
    struct monad_evcap_event_section const *, uint64_t section_offset,
    struct monad_event_descriptor const **, void const **payload);

/// Set the event descriptor and payload for the event with the given sequence
/// number; this is the "evcap equivalent" of the event ring function
/// `monad_event_ring_try_copy`; returns EBADF if there is no sequence number
/// index and ERANGE if the requested sequence number is out of range
static monad_evcap_read_result_t monad_evcap_event_section_copy_seqno(
    struct monad_evcap_event_section const *, uint64_t seqno,
    struct monad_event_descriptor const **, void const **payload);

/// Set the event descriptor and payload for the next event in the EVENT_BUNDLE
/// section referred to by the given iterator; advances the iterator if
/// successful and returns false once all events have been visited
static monad_evcap_read_result_t monad_evcap_event_iter_next(
    struct monad_evcap_event_iter *, struct monad_event_descriptor const **,
    void const **payload);

/// Set the event descriptor and payload for the previous event in the
/// EVENT_BUNDLE section referred to by the given iterator; advances the
/// iterator if successful and returns false once all events have been visited
static monad_evcap_read_result_t monad_evcap_event_iter_prev(
    struct monad_evcap_event_iter *, struct monad_event_descriptor const **,
    void const **payload);

/// Similar to monad_evcap_event_iter_next, but does not advance the iterator
static monad_evcap_read_result_t monad_evcap_event_iter_copy(
    struct monad_evcap_event_iter const *,
    struct monad_event_descriptor const **, void const **payload);

/// Advance the given number of events from the current iterator position;
/// returns the number of events actually moved, which may be less if the end
/// of the capture is encountered
static int64_t monad_evcap_event_iter_advance(
    struct monad_evcap_event_iter *, int64_t distance);

/// Set the iterator so that the next call to monad_evcap_event_iter_copy
/// or monad_evcap_event_iter_next will return the given sequence number;
/// possible return codes are the same as `monad_evcap_event_iter_copy_seqno`
static monad_evcap_read_result_t monad_evcap_event_iter_set_seqno(
    struct monad_evcap_event_iter *, uint64_t seqno);

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

struct monad_evcap_event_section
{
    uint8_t const *section_base;         ///< Base of EVENT_BUNDLE section mmap
    uint8_t const *section_end;          ///< Marks end of EVENT_BUNDLE section
    struct monad_evcap_seqno_index
        seqno_index;                     ///< Sequence number -> offset index
    struct monad_evcap_section_desc
        const *event_sd;                 ///< EVENT_BUNDLE section descriptor
    size_t event_zstd_map_len;           ///< munmap info, if zstd EVENT_BUNDLE
    size_t seqno_zstd_map_len;           ///< munmap info, is zstd SEQNO_INDEX
};

struct monad_evcap_event_iter
{
    struct monad_evcap_event_section
        const *event_section;            ///< Event section we're reading from
    uint8_t const *event_section_next;   ///< Next event descriptor in section
};

// clang-format on

#ifdef __cplusplus
} // extern "C"
#endif

#define MONAD_EVCAP_READER_INTERNAL
#include "evcap_reader_inline.h"
#undef MONAD_EVCAP_READER_INTERNAL
