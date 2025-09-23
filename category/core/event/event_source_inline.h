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

#ifndef MONAD_EVENT_SOURCE_INTERNAL
    #error This file should only be included directly by event_source.h
#endif

#include <stddef.h>
#include <stdint.h>

#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_iterator.h>
#include <category/core/event/event_ring.h>

#ifdef __cplusplus
extern "C"
{
#endif

constexpr uintptr_t MONAD_EVSRC_EVCAP_MASK = 0b1;

union monad_evsrc_iterator_union
{
    struct monad_event_iterator *ring_iter;
    struct monad_evcap_iterator *evcap_iter;
};

union monad_evsrc_const_iterator_union
{
    struct monad_event_iterator const *ring_iter;
    struct monad_evcap_iterator const *evcap_iter;
};

inline enum monad_evsrc_type
monad_evsrc_iterator_get_type(monad_evsrc_const_iterator_t c)
{
    return c.opaque & MONAD_EVSRC_EVCAP_MASK ? MONAD_EVSRC_EVCAP_SECTION
                                             : MONAD_EVSRC_EVENT_RING;
}

static inline enum monad_evsrc_type monad_evsrc_decode_const_iter(
    monad_evsrc_const_iterator_t iter,
    union monad_evsrc_const_iterator_union *u)
{
    if (monad_evsrc_iterator_get_type(iter) == MONAD_EVSRC_EVCAP_SECTION) {
        u->evcap_iter =
            (struct monad_evcap_iterator const *)(iter.opaque &
                                                  ~MONAD_EVSRC_EVCAP_MASK);
        return MONAD_EVSRC_EVCAP_SECTION;
    }
    else {
        u->ring_iter = (struct monad_event_iterator const *)(iter.opaque);
        return MONAD_EVSRC_EVENT_RING;
    }
}

static inline enum monad_evsrc_type monad_evsrc_decode_iter(
    monad_evsrc_iterator_t iter, union monad_evsrc_iterator_union *u)
{
    if (monad_evsrc_iterator_get_type(EVSRC_CONST(iter)) ==
        MONAD_EVSRC_EVCAP_SECTION) {
        u->evcap_iter =
            (struct monad_evcap_iterator *)(iter.opaque &
                                            ~MONAD_EVSRC_EVCAP_MASK);
        return MONAD_EVSRC_EVCAP_SECTION;
    }
    else {
        u->ring_iter = (struct monad_event_iterator *)(iter.opaque);
        return MONAD_EVSRC_EVENT_RING;
    }
}

inline monad_evsrc_const_iterator_t
monad_evsrc_to_const(monad_evsrc_iterator_t iter)
{
    monad_evsrc_const_iterator_t c = {iter.opaque};
    return c;
}

inline bool monad_evsrc_iterator_check_payload(
    monad_evsrc_const_iterator_t iter,
    struct monad_event_descriptor const *event)
{
    union monad_evsrc_const_iterator_union u;

    switch (monad_evsrc_decode_const_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        return monad_event_ring_payload_check(u.ring_iter->event_ring, event);
    case MONAD_EVSRC_EVCAP_SECTION:
        return true;
    default:
        __builtin_unreachable();
    }
}

inline enum monad_evsrc_iter_result monad_evsrc_iterator_try_next(
    monad_evsrc_iterator_t iter, struct monad_event_descriptor *event,
    void const **payload)
{
    union monad_evsrc_iterator_union u;
    struct monad_event_descriptor const *evcap_event;
    enum monad_event_ring_result r;

    switch (monad_evsrc_decode_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        r = monad_event_iterator_try_next(u.ring_iter, event);
        if (payload != nullptr) {
            *payload =
                r == MONAD_EVENT_SUCCESS && monad_event_ring_payload_check(
                                                u.ring_iter->event_ring, event)
                    ? monad_event_ring_payload_peek(
                          u.ring_iter->event_ring, event)
                    : nullptr;
        }
        return (enum monad_evsrc_iter_result)r;
    case MONAD_EVSRC_EVCAP_SECTION:
        if (monad_evcap_iterator_next(u.evcap_iter, &evcap_event, payload)) {
            *event = *evcap_event;
            return MONAD_EVSRC_SUCCESS;
        }
        return MONAD_EVSRC_NO_MORE_EVENTS;
    default:
        __builtin_unreachable();
    }
}

inline enum monad_evsrc_iter_result monad_evsrc_iterator_try_prev(
    monad_evsrc_iterator_t iter, struct monad_event_descriptor *event,
    void const **payload)
{
    union monad_evsrc_iterator_union u;
    struct monad_event_descriptor const *evcap_event;
    enum monad_event_ring_result r;

    switch (monad_evsrc_decode_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        r = monad_event_iterator_try_prev(u.ring_iter, event);
        if (payload != nullptr) {
            *payload =
                r == MONAD_EVENT_SUCCESS && monad_event_ring_payload_check(
                                                u.ring_iter->event_ring, event)
                    ? monad_event_ring_payload_peek(
                          u.ring_iter->event_ring, event)
                    : nullptr;
        }
        return (enum monad_evsrc_iter_result)r;
    case MONAD_EVSRC_EVCAP_SECTION:
        if (monad_evcap_iterator_prev(u.evcap_iter, &evcap_event, payload)) {
            *event = *evcap_event;
            return MONAD_EVSRC_SUCCESS;
        }
        return MONAD_EVSRC_NO_MORE_EVENTS;
    default:
        __builtin_unreachable();
    }
}

inline enum monad_evsrc_iter_result monad_evsrc_iterator_try_copy(
    monad_evsrc_const_iterator_t iter, struct monad_event_descriptor *event,
    void const **payload)
{
    union monad_evsrc_const_iterator_union u;
    struct monad_event_descriptor const *evcap_event;
    enum monad_event_ring_result r;

    switch (monad_evsrc_decode_const_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        r = monad_event_iterator_try_copy(u.ring_iter, event);
        if (payload != nullptr) {
            *payload =
                r == MONAD_EVENT_SUCCESS && monad_event_ring_payload_check(
                                                u.ring_iter->event_ring, event)
                    ? monad_event_ring_payload_peek(
                          u.ring_iter->event_ring, event)
                    : nullptr;
        }
        return (enum monad_evsrc_iter_result)r;
    case MONAD_EVSRC_EVCAP_SECTION:
        if (monad_evcap_iterator_copy(u.evcap_iter, &evcap_event, payload)) {
            *event = *evcap_event;
            return MONAD_EVSRC_SUCCESS;
        }
        return MONAD_EVSRC_NO_MORE_EVENTS;
    default:
        __builtin_unreachable();
    }
}

inline enum monad_evsrc_iter_result monad_evsrc_iterator_copy_seqno(
    monad_evsrc_const_iterator_t iter, uint64_t seqno,
    struct monad_event_descriptor *event, void const **payload)
{
    union monad_evsrc_const_iterator_union u;
    struct monad_event_descriptor const *evcap_event;
    enum monad_event_ring_result r;

    switch (monad_evsrc_decode_const_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        r = monad_event_ring_try_copy(u.ring_iter->event_ring, seqno, event);
        if (payload != nullptr) {
            *payload =
                r == MONAD_EVENT_SUCCESS && monad_event_ring_payload_check(
                                                u.ring_iter->event_ring, event)
                    ? monad_event_ring_payload_peek(
                          u.ring_iter->event_ring, event)
                    : nullptr;
        }
        return (enum monad_evsrc_iter_result)r;
    case MONAD_EVSRC_EVCAP_SECTION:
        if (monad_evcap_iterator_copy_seqno(
                u.evcap_iter, seqno, &evcap_event, payload)) {
            *event = *evcap_event;
            return MONAD_EVSRC_SUCCESS;
        }
        return MONAD_EVSRC_ERROR;
    default:
        __builtin_unreachable();
    }
}

inline int
monad_evsrc_iterator_set_seqno(monad_evsrc_iterator_t iter, uint64_t seqno)
{
    union monad_evsrc_iterator_union u;

    switch (monad_evsrc_decode_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        monad_event_iterator_set_seqno(u.ring_iter, seqno);
        return 0;
    case MONAD_EVSRC_EVCAP_SECTION:
        return monad_evcap_iterator_set_seqno(u.evcap_iter, seqno) == 0
                   ? MONAD_EVSRC_SUCCESS
                   : MONAD_EVSRC_ERROR;
    default:
        __builtin_unreachable();
    }
}

inline uint64_t monad_evsrc_iterator_tell(monad_evsrc_const_iterator_t iter)
{
    union monad_evsrc_const_iterator_union u;

    switch (monad_evsrc_decode_const_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        return u.ring_iter->read_last_seqno;
    case MONAD_EVSRC_EVCAP_SECTION:
        return (uint64_t)(u.evcap_iter->event_section_next -
                          u.evcap_iter->event_section_base);
    default:
        MONAD_ABORT("unknown event source type");
    }
}

inline void
monad_evsrc_iterator_seek(monad_evsrc_iterator_t iter, uint64_t position)
{
    union monad_evsrc_iterator_union u;

    switch (monad_evsrc_decode_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        u.ring_iter->read_last_seqno = position;
        break;
    case MONAD_EVSRC_EVCAP_SECTION:
        u.evcap_iter->event_section_next =
            u.evcap_iter->event_section_base + position;
        break;
    default:
        __builtin_unreachable();
    }
}

inline uint64_t monad_evsrc_iterator_reset(monad_evsrc_iterator_t iter)
{
    union monad_evsrc_iterator_union u;
    struct monad_event_descriptor const *evcap_event;
    void const *payload;

    switch (monad_evsrc_decode_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        return monad_event_iterator_reset(u.ring_iter);
    case MONAD_EVSRC_EVCAP_SECTION:
        return monad_evcap_iterator_copy(u.evcap_iter, &evcap_event, &payload)
                   ? evcap_event->seqno
                   : 0;
    default:
        __builtin_unreachable();
    }
}

inline void monad_evsrc_iterator_close(monad_evsrc_iterator_t iter)
{
    union monad_evsrc_iterator_union u;

    switch (monad_evsrc_decode_iter(iter, &u)) {
    case MONAD_EVSRC_EVENT_RING:
        return;
    case MONAD_EVSRC_EVCAP_SECTION:
        return monad_evcap_iterator_close(u.evcap_iter);
    default:
        __builtin_unreachable();
    }
}

inline monad_evsrc_iterator_t
monad_evsrc_iterator_from_ring(struct monad_event_iterator *iter)
{
    monad_evsrc_iterator_t const i = {.opaque = (uintptr_t)iter};
    return i;
}

inline monad_evsrc_const_iterator_t
monad_evsrc_iterator_from_ring_const(struct monad_event_iterator const *iter)
{
    monad_evsrc_const_iterator_t const i = {.opaque = (uintptr_t)iter};
    return i;
}

inline monad_evsrc_iterator_t
monad_evsrc_iterator_from_evcap(struct monad_evcap_iterator *iter)
{
    monad_evsrc_iterator_t const i = {
        .opaque = (uintptr_t)iter & MONAD_EVSRC_EVCAP_MASK};
    return i;
}

inline monad_evsrc_const_iterator_t
monad_evsrc_iterator_from_evcap_const(struct monad_evcap_iterator const *iter)
{
    monad_evsrc_const_iterator_t const i = {
        .opaque = (uintptr_t)iter & MONAD_EVSRC_EVCAP_MASK};
    return i;
}

#ifdef __cplusplus
} // extern "C"
#endif
