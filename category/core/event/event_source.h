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
 * This file defines the concepts of an "event source" and "event source
 * iterator", which can be used to write code that works with either:
 *
 *  - Event rings / event ring iterators
 *  - Event capture files / event section iterators
 *
 * A "source" corresponds to the object which provides the underlying memory
 * for the event descriptor and payload, and a "source iterator" knows how to
 * iterate through all the events in the source.
 */

#include <stdint.h>

#include <category/core/event/event_ring.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct monad_event_iterator;
struct monad_evcap_event_section;
struct monad_evcap_iterator;

enum monad_evsrc_type
{
    MONAD_EVSRC_EVENT_RING,
    MONAD_EVSRC_EVCAP_SECTION
};

/// An event source represents the underlying memory region that an event
/// descriptor and payload are drawn from; these are always passed by value but
/// have implicit reference semantics, because they carry a pointer to the
/// underlying source; they are usually constructed from the source pointer
/// using the conversion macro EVSRC_GET
typedef struct monad_evsrc
{
    enum monad_evsrc_type source_type;

    union
    {
        struct monad_event_ring const *event_ring;
        struct monad_evcap_event_section const *event_section;
    };
} monad_evsrc_t;

/// An event source iterator is a wrapper of either an event ring iterator or
/// an event capture file iterator; like the event source itself, these are
/// always passed by value but have implicit reference semantics, because they
/// carry a pointer to the underlying iterator; they are usually constructed
/// from the source iterator using the EVSRC_ITER conversion macro
typedef struct monad_evsrc_iterator
{
    enum monad_evsrc_type source_type;

    union
    {
        struct monad_event_iterator *ring_iter;
        struct monad_evcap_iterator *evcap_iter;
    };
} monad_evsrc_iterator_t;

/// Because monad_evsrc_iterator_t is an opaque wrapper around a pointer,
/// const-correctness requires a separate type; you can easily construct one
/// of these from a monad_evsrc_iterator_t using the EVSRC_CONST conversion
/// macro
typedef struct monad_evsrc_const_iterator
{
    enum monad_evsrc_type source_type;

    union
    {
        struct monad_event_iterator const *ring_iter;
        struct monad_evcap_iterator const *evcap_iter;
    };
} monad_evsrc_const_iterator_t;

static monad_evsrc_const_iterator_t
monad_evsrc_iterator_to_const(monad_evsrc_iterator_t i);

#define EVSRC_CONST(X) monad_evsrc_iterator_to_const((X))

/// Result of trying to read an event descriptor and payload from an event
/// source; these extend the monad_event_ring_result values with two new kinds
/// of behavior only possible in event capture files: (1) trying advance the
/// iterator after the last event (or before the first event when seeking
/// backwards) which returns END, and (2) the ERROR case; for the latter use
/// monad_evcap_get_last_error to diagnose
enum monad_evsrc_result
{
    MONAD_EVSRC_SUCCESS = MONAD_EVENT_SUCCESS,
    MONAD_EVSRC_NOT_READY = MONAD_EVENT_NOT_READY,
    MONAD_EVSRC_GAP = MONAD_EVENT_GAP,
    MONAD_EVSRC_END,
    MONAD_EVSRC_ERROR,
};

static bool
monad_evsrc_check_payload(monad_evsrc_t, struct monad_event_descriptor const *);

static enum monad_evsrc_result monad_evsrc_copy_seqno(
    monad_evsrc_t, uint64_t seqno, struct monad_event_descriptor *,
    void const **payload);

static void monad_evsrc_close(monad_evsrc_t);

static enum monad_evsrc_result monad_evsrc_iterator_try_next(
    monad_evsrc_iterator_t, struct monad_event_descriptor *,
    void const **payload);

static enum monad_evsrc_result monad_evsrc_iterator_try_prev(
    monad_evsrc_iterator_t, struct monad_event_descriptor *,
    void const **payload);

static enum monad_evsrc_result monad_evsrc_iterator_try_copy(
    monad_evsrc_const_iterator_t, struct monad_event_descriptor *,
    void const **payload);

static monad_evsrc_t monad_evsrc_iterator_get_source(monad_evsrc_iterator_t);

static monad_evsrc_t
    monad_evsrc_const_iterator_get_source(monad_evsrc_const_iterator_t);

static int
monad_evsrc_iterator_set_seqno(monad_evsrc_iterator_t, uint64_t seqno);

static uint64_t monad_evsrc_iterator_tell(monad_evsrc_const_iterator_t);

static void
monad_evsrc_iterator_seek(monad_evsrc_iterator_t, uint64_t position);

static uint64_t monad_evsrc_iterator_reset(monad_evsrc_iterator_t);

/*
 * monad_evsrc_t and monad_evsrc[_const]_iterator_t creation functions;
 * these are not usually called directly, but through the _Generic conversion
 * macros EVSRC_GET, EVSRC_ITER, and EVSRC_CONST_ITER
 */

static monad_evsrc_t monad_evsrc_from_ring(struct monad_event_ring const *);

static monad_evsrc_t
monad_evsrc_from_evcap(struct monad_evcap_event_section const *);

static monad_evsrc_iterator_t
monad_evsrc_iterator_from_ring(struct monad_event_iterator *);

static monad_evsrc_const_iterator_t
monad_evsrc_iterator_from_ring_const(struct monad_event_iterator const *);

static monad_evsrc_iterator_t
monad_evsrc_iterator_from_evcap(struct monad_evcap_iterator *);

static monad_evsrc_const_iterator_t
monad_evsrc_iterator_from_evcap_const(struct monad_evcap_iterator const *);

#define EVSRC_CONST_ITER(R) EVSRC_CONST(EVSRC_ITER((R)))

#ifdef __cplusplus
} // extern "C"
#endif

#ifdef __cplusplus

inline monad_evsrc_t EVSRC_GET(monad_event_ring const *r)
{
    return monad_evsrc_from_ring(r);
}

inline monad_evsrc_t EVSRC_GET(monad_evcap_event_section const *s)
{
    return monad_evsrc_from_evcap(s);
}

inline monad_evsrc_t EVSRC_GET(monad_evsrc_const_iterator_t i)
{
    return monad_evsrc_const_iterator_get_source(i);
}

inline monad_evsrc_t EVSRC_GET(monad_evsrc_iterator_t i)
{
    return monad_evsrc_iterator_get_source(i);
}

inline monad_evsrc_iterator_t EVSRC_ITER(monad_event_iterator *iter)
{
    return monad_evsrc_iterator_from_ring(iter);
}

inline monad_evsrc_iterator_t EVSRC_ITER(monad_evcap_iterator *iter)
{
    return monad_evsrc_iterator_from_evcap(iter);
}

#else // __cplusplus

    #define EVSRC_GET(R)                                                         \
        _Generic(                                                                \
            (R),                                                                 \
            struct monad_event_ring *: monad_evsrc_from_ring,                    \
            struct monad_event_ring const *: monad_evsrc_from_ring,              \
            struct monad_evcap_event_section *: monad_evsrc_from_evcap,          \
            struct monad_evcap_event_section const *: monad_evsrc_from_evcap,    \
            monad_evsrc_const_iterator_t: monad_evsrc_const_iterator_get_source, \
            monad_evsrc_iterator_t: monad_evsrc_iterator_get_source)((R))

    #define EVSRC_ITER(R)                                                      \
        _Generic(                                                              \
            (R),                                                               \
            struct monad_evcap_iterator const                                  \
                *: monad_evsrc_iterator_from_evcap_const,                      \
            struct monad_evcap_iterator *: monad_evsrc_iterator_from_evcap,    \
            struct monad_event_iterator const                                  \
                *: monad_evsrc_iterator_from_ring_const,                       \
            struct monad_event_iterator *: monad_evsrc_iterator_from_ring)(    \
            (R))

#endif // __cplusplus

#define MONAD_EVENT_SOURCE_INTERNAL
#include "event_source_inline.h"
#undef MONAD_EVENT_SOURCE_INTERNAL
