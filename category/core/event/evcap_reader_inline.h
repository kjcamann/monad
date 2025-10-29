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
 * `struct monad_evcap_event_iter`
 */

#ifndef MONAD_EVCAP_READER_INTERNAL
    #error This file should only be included directly by evcap_reader.h
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <category/core/assert.h>
#include <category/core/event/event_def.h>
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

inline void monad_evcap_event_section_open_iterator(
    struct monad_evcap_event_section const *es,
    struct monad_evcap_event_iter *iter)
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

inline monad_evcap_read_result_t monad_evcap_event_section_copy_seqno(
    struct monad_evcap_event_section const *es, uint64_t seqno,
    struct monad_event_descriptor const **event, void const **payload)
{
    if (es->seqno_index.offsets == nullptr) {
        return MONAD_EVCAP_READ_NO_SEQNO;
    }
    if (seqno < es->seqno_index.seqno_start ||
        seqno >= es->seqno_index.seqno_end) {
        return MONAD_EVCAP_READ_END;
    }
    uint64_t const offset =
        es->seqno_index.offsets[seqno - es->seqno_index.seqno_start];
    (void)monad_evcap_event_section_at_offset(es, offset, event, payload);
    return MONAD_EVCAP_READ_SUCCESS;
}

inline monad_evcap_read_result_t monad_evcap_event_iter_next(
    struct monad_evcap_event_iter *iter,
    struct monad_event_descriptor const **event, void const **payload)
{
    uint64_t const event_offset = (uint64_t)(iter->event_section_next -
                                             iter->event_section->section_base);
    size_t const event_size = monad_evcap_event_section_at_offset(
        iter->event_section, event_offset, event, payload);
    iter->event_section_next += event_size;
    return event_size > 0 ? MONAD_EVCAP_READ_SUCCESS : MONAD_EVCAP_READ_END;
}

inline monad_evcap_read_result_t monad_evcap_event_iter_prev(
    struct monad_evcap_event_iter *iter,
    struct monad_event_descriptor const **event, void const **payload)
{
    if (MONAD_UNLIKELY(
            iter->event_section_next == iter->event_section->section_base)) {
        return MONAD_EVCAP_READ_END;
    }
    iter->event_section_next -= *((size_t const *)iter->event_section_next - 1);
    return monad_evcap_event_iter_copy(iter, event, payload);
}

inline monad_evcap_read_result_t monad_evcap_event_iter_copy(
    struct monad_evcap_event_iter const *iter,
    struct monad_event_descriptor const **event, void const **payload)
{
    uint64_t const event_offset = (uint64_t)(iter->event_section_next -
                                             iter->event_section->section_base);
    return monad_evcap_event_section_at_offset(
               iter->event_section, event_offset, event, payload) > 0
               ? MONAD_EVCAP_READ_SUCCESS
               : MONAD_EVCAP_READ_END;
}

inline int64_t monad_evcap_event_iter_advance(
    struct monad_evcap_event_iter *iter, int64_t distance)
{
    monad_evcap_read_result_t r;
    int64_t move_count = 0;

    constexpr long SCAN_THRESHOLD = 8;
    struct monad_evcap_seqno_index const *const seqno_index =
        &iter->event_section->seqno_index;
    if (seqno_index->offsets != nullptr && labs(distance) > SCAN_THRESHOLD) {
        struct monad_event_descriptor const *event;

        // Faster implementation when we have a sequence number index. First
        // we need the current sequence number where we are, which may involve
        // moving back one if we're already at the end
        if (iter->event_section_next == iter->event_section->section_end) {
            if (distance >= 0) {
                // At the end and trying to move forwards; do nothing
                return 0;
            }
            // distance is at least -1; back up one so we can read a sequence
            // number
            r = monad_evcap_event_iter_prev(iter, &event, nullptr);
            if (r != MONAD_EVCAP_READ_SUCCESS) {
                return 0;
            }
            ++distance;
            --move_count;
        }
        else {
            // Not at the end; get whatever sequence number is here
            r = monad_evcap_event_iter_copy(iter, &event, nullptr);
            if (r != MONAD_EVCAP_READ_SUCCESS) {
                return 0;
            }
        }

        int64_t const cur_seqno = (int64_t)event->seqno;
        uint64_t new_seqno;
        if (cur_seqno + distance < (int64_t)seqno_index->seqno_start) {
            new_seqno = seqno_index->seqno_start;
        }
        else if (cur_seqno + distance >= (int64_t)seqno_index->seqno_end) {
            new_seqno = seqno_index->seqno_end;
        }
        else {
            new_seqno = (uint64_t)(cur_seqno + distance);
        }
        move_count = (int64_t)new_seqno - cur_seqno;
        if (new_seqno == seqno_index->seqno_end) {
            iter->event_section_next = iter->event_section->section_end;
        }
        else {
            (void)monad_evcap_event_iter_set_seqno(iter, new_seqno);
        }
    }
    // Slow, scan based implementation
    while (distance > 0) {
        struct monad_event_descriptor const *event;
        if (monad_evcap_event_iter_next(iter, &event, nullptr) ==
            MONAD_EVCAP_READ_END) {
            return move_count;
        }
        --distance;
        ++move_count;
    }
    while (distance < 0) {
        struct monad_event_descriptor const *event;
        if (monad_evcap_event_iter_prev(iter, &event, nullptr) ==
            MONAD_EVCAP_READ_END) {
            return move_count;
        }
        ++distance;
        --move_count;
    }
    return move_count;
}

inline monad_evcap_read_result_t monad_evcap_event_iter_set_seqno(
    struct monad_evcap_event_iter *iter, uint64_t seqno)
{
    struct monad_evcap_seqno_index const *const seqno_index =
        &iter->event_section->seqno_index;
    if (seqno_index->offsets == nullptr) {
        return MONAD_EVCAP_READ_NO_SEQNO;
    }
    if (seqno < seqno_index->seqno_start || seqno >= seqno_index->seqno_end) {
        return MONAD_EVCAP_READ_END;
    }
    iter->event_section_next =
        iter->event_section->section_base +
        seqno_index->offsets[seqno - seqno_index->seqno_start];
    return MONAD_EVCAP_READ_SUCCESS;
}

#ifdef __cplusplus
} // extern "C"
#endif
