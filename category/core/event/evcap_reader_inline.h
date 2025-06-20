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

/**
 * @file
 *
 * Inlined implementation of the performance sensitive functions for
 * `struct monad_evcap_event_iterator`
 */

#ifndef MONAD_EVCAP_READER_INTERNAL
    #error This file should only be included directly by evcap_reader.h
#endif

#include <stddef.h>
#include <stdint.h>

#include <category/core/assert.h>
#include <category/core/event/event_ring.h>
#include <category/core/mem/align.h>

#ifdef __cplusplus
extern "C"
{
#endif

static inline uint8_t const *
_monad_evcap_align_address(uint8_t const *p, size_t align)
{
    return (uint8_t *)monad_round_size_to_align((uintptr_t)p, align);
}

inline size_t monad_evcap_iterator_at_offset(
    struct monad_evcap_event_iterator const *iter, uint64_t section_offset,
    enum monad_event_content_type *content_type,
    struct monad_event_descriptor const **event, uint8_t const **payload)
{
    uint8_t const *initial_address = iter->event_section_base + section_offset;
    uint8_t const *read = _monad_evcap_align_address(
        initial_address, alignof(struct monad_event_descriptor));
    *event = (struct monad_event_descriptor *)read;
    read += sizeof **event;
    *payload = read;
    read = _monad_evcap_align_address(
        read + (*event)->payload_size, alignof(enum monad_event_content_type));
    if (content_type != nullptr) {
        *content_type = *(enum monad_event_content_type const *)read;
    }
    read += sizeof *content_type;
    return (size_t)(read - initial_address);
}

inline bool monad_evcap_iterator_next(
    struct monad_evcap_event_iterator *iter,
    enum monad_event_content_type *content_type,
    struct monad_event_descriptor const **event, uint8_t const **payload)
{
    if (iter->event_section_next == iter->event_section_end) {
        *event = nullptr;
        *payload = nullptr;
        return false;
    }
    MONAD_DEBUG_ASSERT(iter->event_section_next < iter->event_section_end);
    iter->event_section_next += monad_evcap_iterator_at_offset(
        iter,
        (uint64_t)(iter->event_section_next - iter->event_section_base),
        content_type,
        event,
        payload);
    return true;
}

inline bool monad_evcap_iterator_copy_seqno(
    struct monad_evcap_event_iterator const *iter, uint64_t seqno,
    enum monad_event_content_type *content_type,
    struct monad_event_descriptor const **event, uint8_t const **payload)
{
    if (iter->seqno_index.offsets == nullptr ||
        seqno < iter->seqno_index.seqno_start ||
        seqno >= iter->seqno_index.seqno_end) {
        return false;
    }
    uint64_t const offset =
        iter->seqno_index.offsets[seqno - iter->seqno_index.seqno_start];
    (void)monad_evcap_iterator_at_offset(
        iter, offset, content_type, event, payload);
    return true;
}

#ifdef __cplusplus
} // extern "C"
#endif
