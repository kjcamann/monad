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
 * Defines the event iterator object and its API; iterators are used for
 * reading events
 */

#include <stddef.h>
#include <stdint.h>

#include <category/core/event/event_ring.h>
#include <category/core/likely.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum monad_event_ring_result : unsigned;
struct monad_event_descriptor;
struct monad_event_iterator;
struct monad_event_ring_control;

/// Copy the next event descriptor and advance the iterator, if the next event
/// is available, similar to `*++i`; returns MONAD_EVENT_SUCCESS upon success,
/// otherwise returns a code indicating why the iterator could not be advanced
static enum monad_event_ring_result monad_event_iterator_try_next(
    struct monad_event_iterator *, struct monad_event_descriptor *);

/// Move the iterator back to previous event descriptor and copy it out, if the
/// previous event is still available, similar to `*--i`; return behavior is
/// the same as monad_event_iterator_try_next
static enum monad_event_ring_result monad_event_iterator_try_prev(
    struct monad_event_iterator *, struct monad_event_descriptor *);

/// Copy the event descriptor at the current iteration point, without advancing
/// the iterator; returns MONAD_EVENT_SUCCESS upon success, otherwise returns
/// a code indicating why the descriptor at the iteration point was not ready
static enum monad_event_ring_result monad_event_iterator_try_copy(
    struct monad_event_iterator const *, struct monad_event_descriptor *);

/// Unchecked advance of the iterator by a signed distance; the typical
/// iteration pattern is to use monad_event_iterator_try_next, which performs
/// `*i++` atomically if and only if an event is ready, but the caller can also
/// use `monad_event_iterator_try_copy`/ and `monad_event_iterator_advance`
/// (which is unchecked) in certain situations
static uint64_t
monad_event_iterator_advance(struct monad_event_iterator *, int64_t distance);

/// Set the iterator so that the next call to `monad_event_iterator_try_next`
/// or `monad_event_iterator_try_copy` will read the event descriptor with the
/// specified sequence number; this performs no checking
static void
monad_event_iterator_set_seqno(struct monad_event_iterator *, uint64_t seqno);

/// Reset the iterator to point to the latest event produced; used for gap
/// recovery
static uint64_t monad_event_iterator_reset(struct monad_event_iterator *);

// clang-format off

/// Holds the state of a single event iterator
struct monad_event_iterator
{
    uint64_t read_last_seqno;
    struct monad_event_ring const *event_ring;
};

// clang-format on

/*
 * Inline implementation
 */

inline enum monad_event_ring_result monad_event_iterator_try_next(
    struct monad_event_iterator *iter, struct monad_event_descriptor *event)
{
    enum monad_event_ring_result const r =
        monad_event_iterator_try_copy(iter, event);
    if (MONAD_LIKELY(r == MONAD_EVENT_SUCCESS)) {
        ++iter->read_last_seqno;
    }
    return r;
}

inline enum monad_event_ring_result monad_event_iterator_try_prev(
    struct monad_event_iterator *iter, struct monad_event_descriptor *event)
{
    if (MONAD_UNLIKELY(iter->read_last_seqno == 0)) {
        return MONAD_EVENT_NOT_READY;
    }
    --iter->read_last_seqno;
    enum monad_event_ring_result const r =
        monad_event_iterator_try_copy(iter, event);
    if (MONAD_UNLIKELY(r != MONAD_EVENT_SUCCESS)) {
        ++iter->read_last_seqno;
    }
    return r;
}

inline enum monad_event_ring_result monad_event_iterator_try_copy(
    struct monad_event_iterator const *iter,
    struct monad_event_descriptor *event)
{
    return monad_event_ring_try_copy(
        iter->event_ring, iter->read_last_seqno, event);
}

inline uint64_t monad_event_iterator_advance(
    struct monad_event_iterator *iter, int64_t distance)
{
    int64_t const new_position = (int64_t)iter->read_last_seqno + distance;
    if (MONAD_UNLIKELY(new_position < 0)) {
        iter->read_last_seqno = 0;
    }
    else {
        iter->read_last_seqno = (uint64_t)new_position;
    }
    return iter->read_last_seqno;
}

inline void monad_event_iterator_set_seqno(
    struct monad_event_iterator *iter, uint64_t seqno)
{
    iter->read_last_seqno = seqno - 1;
}

inline uint64_t monad_event_iterator_reset(struct monad_event_iterator *iter)
{
    uint64_t last_available_seqno = monad_event_ring_get_last_written_seqno(
        iter->event_ring, /*sync_wait*/ true);
    return iter->read_last_seqno =
               last_available_seqno > 0 ? last_available_seqno - 1 : 0;
}

#ifdef __cplusplus
} // extern "C"
#endif
