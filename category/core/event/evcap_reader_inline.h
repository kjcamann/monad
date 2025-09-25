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

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <category/core/assert.h>
#include <category/core/event/event_ring.h>
#include <category/core/likely.h>
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

__attribute__((format(printf, 5, 6))) int _monad_evcap_set_inline_error(
    char const *function, char const *file, unsigned line, int rc,
    char const *format, ...);

#define MONAD_EVCAP_INLINE_ERR(...)                                            \
    _monad_evcap_set_inline_error(                                             \
        __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

inline void monad_evcap_event_section_open_iterator(
    struct monad_evcap_event_section const *es,
    struct monad_evcap_iterator *iter)
{
    iter->event_section = es;
    iter->event_section_next = es->section_base;
}

inline size_t monad_evcap_event_section_at_offset(
    struct monad_evcap_event_section const *es, uint64_t section_offset,
    struct monad_event_descriptor const **event, void const **payload)
{
    uint8_t const *initial_address = es->section_base + section_offset;
    uint8_t const *read = _monad_evcap_align_address(
        initial_address, alignof(struct monad_event_descriptor));
    if (read >= es->section_end) {
        *event = nullptr;
        *payload = nullptr;
        return 0;
    }
    *event = (struct monad_event_descriptor *)read;
    read += sizeof **event;
    if (payload != nullptr) {
        *payload = read;
    }
    read = _monad_evcap_align_address(
        read + (*event)->payload_size, alignof(size_t));
    read += sizeof(size_t);
    return (size_t)(read - initial_address);
}

inline int monad_evcap_event_section_copy_seqno(
    struct monad_evcap_event_section const *es, uint64_t seqno,
    struct monad_event_descriptor const **event, void const **payload)
{
    if (es->seqno_index.offsets == nullptr) {
        return MONAD_EVCAP_INLINE_ERR(
            EBADF, "evcap file does not have a sequence number index");
    }
    if (seqno < es->seqno_index.seqno_start ||
        seqno >= es->seqno_index.seqno_end) {
        return MONAD_EVCAP_INLINE_ERR(
            ERANGE,
            "sequence number %lu outside section range [%lu, %lu)",
            seqno,
            es->seqno_index.seqno_start,
            es->seqno_index.seqno_end);
    }
    uint64_t const offset =
        es->seqno_index.offsets[seqno - es->seqno_index.seqno_start];
    (void)monad_evcap_event_section_at_offset(es, offset, event, payload);
    return 0;
}

inline bool monad_evcap_iterator_next(
    struct monad_evcap_iterator *iter,
    struct monad_event_descriptor const **event, void const **payload)
{
    uint64_t const event_offset =
        (uint64_t)(iter->event_section_next - iter->event_section->section_base);
    size_t const event_size = monad_evcap_event_section_at_offset(
        iter->event_section,
        event_offset,
        event,
        payload);
    iter->event_section_next += event_size;
    return event_size > 0;
}

inline bool monad_evcap_iterator_prev(
    struct monad_evcap_iterator *iter,
    struct monad_event_descriptor const **event, void const **payload)
{
    if (MONAD_UNLIKELY(iter->event_section_next == iter->event_section->section_base)) {
        return false;
    }
    iter->event_section_next -= *((size_t const *)iter->event_section_next - 1);
    return monad_evcap_iterator_copy(iter, event, payload);
}

inline bool monad_evcap_iterator_copy(
    struct monad_evcap_iterator const *iter,
    struct monad_event_descriptor const **event, void const **payload)
{
    uint64_t const event_offset =
        (uint64_t)(iter->event_section_next - iter->event_section->section_base);
    return monad_evcap_event_section_at_offset(
               iter->event_section,
               event_offset,
               event,
               payload) > 0;
}

inline int monad_evcap_iterator_set_seqno(
    struct monad_evcap_iterator *iter, uint64_t seqno)
{
    struct monad_evcap_seqno_index const *const seqno_index =
        &iter->event_section->seqno_index;
    if (seqno_index->offsets == nullptr) {
        return MONAD_EVCAP_INLINE_ERR(
            EBADF, "evcap file does not have a sequence number index");
    }
    if (seqno < seqno_index->seqno_start || seqno >= seqno_index->seqno_end) {
        return MONAD_EVCAP_INLINE_ERR(
            ERANGE,
            "sequence number %lu outside section range [%lu, %lu)",
            seqno,
            seqno_index->seqno_start,
            seqno_index->seqno_end);
    }
    iter->event_section_next =
        iter->event_section->section_base +
        seqno_index->offsets[seqno - seqno_index->seqno_start];
    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif
