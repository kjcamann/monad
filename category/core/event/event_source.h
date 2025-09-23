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

#include <stdint.h>

#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_iterator.h>

/**
 * @file
 *
 * This file defines an "event source iterator", which unifies the API of
 * event ring iterators and event capture iterators. This allows the user
 * to write code that will work with either source of events
 */

#include <stdint.h>

#include <category/core/event/event_ring.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct monad_evsrc_iterator
{
    uintptr_t opaque;
} monad_evsrc_iterator_t;

typedef struct monad_evsrc_const_iterator
{
    uintptr_t opaque;
} monad_evsrc_const_iterator_t;

static monad_evsrc_const_iterator_t
    monad_evsrc_to_const(monad_evsrc_iterator_t);

#define EVSRC_CONST(X) monad_evsrc_to_const((X))

enum monad_evsrc_type
{
    MONAD_EVSRC_EVENT_RING,
    MONAD_EVSRC_EVCAP_SECTION
};

enum monad_evsrc_iter_result
{
    MONAD_EVSRC_SUCCESS = MONAD_EVENT_SUCCESS,
    MONAD_EVSRC_NOT_READY = MONAD_EVENT_NOT_READY,
    MONAD_EVSRC_GAP = MONAD_EVENT_GAP,
    MONAD_EVSRC_NO_MORE_EVENTS,
    MONAD_EVSRC_ERROR,
};

static enum monad_evsrc_type
    monad_evsrc_iterator_get_type(monad_evsrc_const_iterator_t);

static bool monad_evsrc_iterator_check_payload(
    monad_evsrc_const_iterator_t, struct monad_event_descriptor const *);

static enum monad_evsrc_iter_result monad_evsrc_iterator_try_next(
    monad_evsrc_iterator_t, struct monad_event_descriptor *,
    void const **payload);

static enum monad_evsrc_iter_result monad_evsrc_iterator_try_prev(
    monad_evsrc_iterator_t, struct monad_event_descriptor *,
    void const **payload);

static enum monad_evsrc_iter_result monad_evsrc_iterator_try_copy(
    monad_evsrc_const_iterator_t, struct monad_event_descriptor *,
    void const **payload);

static enum monad_evsrc_iter_result monad_evsrc_iterator_copy_seqno(
    monad_evsrc_const_iterator_t, uint64_t seqno,
    struct monad_event_descriptor *, void const **payload);

static int
monad_evsrc_iterator_set_seqno(monad_evsrc_iterator_t, uint64_t seqno);

static uint64_t monad_evsrc_iterator_tell(monad_evsrc_const_iterator_t);

static void
monad_evsrc_iterator_seek(monad_evsrc_iterator_t, uint64_t position);

static uint64_t monad_evsrc_iterator_reset(monad_evsrc_iterator_t);

static void monad_evsrc_iterator_close(monad_evsrc_iterator_t);

static monad_evsrc_iterator_t
monad_evsrc_iterator_from_ring(struct monad_event_iterator *);

static monad_evsrc_const_iterator_t
monad_evsrc_iterator_from_ring_const(struct monad_event_iterator const *);

static monad_evsrc_iterator_t
monad_evsrc_iterator_from_evcap(struct monad_evcap_iterator *);

static monad_evsrc_const_iterator_t
monad_evsrc_iterator_from_evcap_const(struct monad_evcap_iterator const *);

#define EVSRC_ITER(R)                                                          \
    _Generic(                                                                  \
        (R),                                                                   \
        struct monad_evcap_iterator const                                      \
            *: monad_evsrc_iterator_from_evcap_const,                          \
        struct monad_evcap_iterator *: monad_evsrc_iterator_from_evcap,        \
        struct monad_event_iterator const                                      \
            *: monad_evsrc_iterator_from_ring_const,                           \
        struct monad_event_iterator *: monad_evsrc_iterator_from_ring)((R))

#define EVSRC_CONST_ITER(R) EVSRC_CONST(EVSRC_ITER((R)))

#ifdef __cplusplus
} // extern "C"
#endif

#define MONAD_EVENT_SOURCE_INTERNAL
#include "event_source_inline.h"
#undef MONAD_EVENT_SOURCE_INTERNAL
