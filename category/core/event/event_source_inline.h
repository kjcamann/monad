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
#include <string.h>

#include <category/core/event/evcap_reader.h>
#include <category/core/event/event_iterator.h>
#include <category/core/event/event_ring.h>

#ifdef __cplusplus
extern "C"
{
#endif

inline monad_evsrc_const_iterator_t
monad_evsrc_iterator_to_const(monad_evsrc_iterator_t iter)
{
    monad_evsrc_const_iterator_t const_iter;
    memcpy(&const_iter, &iter, sizeof iter);
    return const_iter;
}

inline bool monad_evsrc_check_payload(
    monad_evsrc_t evsrc, struct monad_event_descriptor const *event)
{
    return evsrc.source_type == MONAD_EVSRC_EVENT_RING
               ? monad_event_ring_payload_check(evsrc.event_ring, event)
               : true;
}

inline enum monad_evsrc_result monad_evsrc_copy_seqno(
    monad_evsrc_t evsrc, uint64_t seqno, struct monad_event_descriptor *event,
    void const **payload)
{
    struct monad_event_descriptor const *evcap_event = nullptr;
    enum monad_event_ring_result r;

    switch (evsrc.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        r = monad_event_ring_try_copy(evsrc.event_ring, seqno, event);
        if (payload != nullptr) {
            *payload =
                r == MONAD_EVENT_SUCCESS &&
                        monad_event_ring_payload_check(evsrc.event_ring, event)
                    ? monad_event_ring_payload_peek(evsrc.event_ring, event)
                    : nullptr;
        }
        return (enum monad_evsrc_result)r;
    case MONAD_EVSRC_EVCAP_SECTION:
        if (monad_evcap_event_section_copy_seqno(
                evsrc.event_section, seqno, &evcap_event, payload) == 0) {
            *event = *evcap_event;
            return MONAD_EVSRC_SUCCESS;
        }
        return MONAD_EVSRC_ERROR;
    default:
        __builtin_unreachable();
    }
}

inline void monad_evsrc_close(monad_evsrc_t evsrc)
{
    switch (evsrc.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        return;
    case MONAD_EVSRC_EVCAP_SECTION:
        monad_evcap_event_section_close(
            (struct monad_evcap_event_section *)evsrc.event_section);
    default:
        __builtin_unreachable();
    }
}

inline enum monad_evsrc_result monad_evsrc_iterator_try_next(
    monad_evsrc_iterator_t iter, struct monad_event_descriptor *event,
    void const **payload)
{
    struct monad_event_descriptor const *evcap_event;
    enum monad_event_ring_result r;

    switch (iter.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        r = monad_event_iterator_try_next(iter.ring_iter, event);
        if (payload != nullptr) {
            struct monad_event_ring const *const event_ring =
                iter.ring_iter->event_ring;
            *payload = r == MONAD_EVENT_SUCCESS &&
                               monad_event_ring_payload_check(event_ring, event)
                           ? monad_event_ring_payload_peek(event_ring, event)
                           : nullptr;
        }
        return (enum monad_evsrc_result)r;
    case MONAD_EVSRC_EVCAP_SECTION:
        if (monad_evcap_iterator_next(iter.evcap_iter, &evcap_event, payload)) {
            *event = *evcap_event;
            return MONAD_EVSRC_SUCCESS;
        }
        return MONAD_EVSRC_END;
    default:
        __builtin_unreachable();
    }
}

inline enum monad_evsrc_result monad_evsrc_iterator_try_prev(
    monad_evsrc_iterator_t iter, struct monad_event_descriptor *event,
    void const **payload)
{
    struct monad_event_descriptor const *evcap_event;
    enum monad_event_ring_result r;

    switch (iter.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        r = monad_event_iterator_try_prev(iter.ring_iter, event);
        if (payload != nullptr) {
            struct monad_event_ring const *const event_ring =
                iter.ring_iter->event_ring;
            *payload = r == MONAD_EVENT_SUCCESS &&
                               monad_event_ring_payload_check(event_ring, event)
                           ? monad_event_ring_payload_peek(event_ring, event)
                           : nullptr;
        }
        return (enum monad_evsrc_result)r;
    case MONAD_EVSRC_EVCAP_SECTION:
        if (monad_evcap_iterator_prev(iter.evcap_iter, &evcap_event, payload)) {
            *event = *evcap_event;
            return MONAD_EVSRC_SUCCESS;
        }
        return MONAD_EVSRC_END;
    default:
        __builtin_unreachable();
    }
}

inline enum monad_evsrc_result monad_evsrc_iterator_try_copy(
    monad_evsrc_const_iterator_t iter, struct monad_event_descriptor *event,
    void const **payload)
{
    struct monad_event_descriptor const *evcap_event;
    enum monad_event_ring_result r;

    switch (iter.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        r = monad_event_iterator_try_copy(iter.ring_iter, event);
        if (payload != nullptr) {
            struct monad_event_ring const *const event_ring =
                iter.ring_iter->event_ring;
            *payload = r == MONAD_EVENT_SUCCESS &&
                               monad_event_ring_payload_check(event_ring, event)
                           ? monad_event_ring_payload_peek(event_ring, event)
                           : nullptr;
        }
        return (enum monad_evsrc_result)r;
    case MONAD_EVSRC_EVCAP_SECTION:
        if (monad_evcap_iterator_copy(iter.evcap_iter, &evcap_event, payload)) {
            *event = *evcap_event;
            return MONAD_EVSRC_SUCCESS;
        }
        return MONAD_EVSRC_END;
    default:
        __builtin_unreachable();
    }
}

inline monad_evsrc_t
monad_evsrc_iterator_get_source(monad_evsrc_iterator_t iter)
{
    monad_evsrc_t evsrc;

    evsrc.source_type = iter.source_type;
    switch (evsrc.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        evsrc.event_ring = iter.ring_iter->event_ring;
        return evsrc;
    case MONAD_EVSRC_EVCAP_SECTION:
        evsrc.event_section = iter.evcap_iter->event_section;
        return evsrc;
    default:
        __builtin_unreachable();
    }
}

inline monad_evsrc_t
monad_evsrc_const_iterator_get_source(monad_evsrc_const_iterator_t iter)
{
    monad_evsrc_t evsrc;

    evsrc.source_type = iter.source_type;
    switch (evsrc.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        evsrc.event_ring = iter.ring_iter->event_ring;
        return evsrc;
    case MONAD_EVSRC_EVCAP_SECTION:
        evsrc.event_section = iter.evcap_iter->event_section;
        return evsrc;
    default:
        __builtin_unreachable();
    }
}

inline int
monad_evsrc_iterator_set_seqno(monad_evsrc_iterator_t iter, uint64_t seqno)
{
    switch (iter.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        monad_event_iterator_set_seqno(iter.ring_iter, seqno);
        return 0;
    case MONAD_EVSRC_EVCAP_SECTION:
        return monad_evcap_iterator_set_seqno(iter.evcap_iter, seqno) == 0
                   ? MONAD_EVSRC_SUCCESS
                   : MONAD_EVSRC_ERROR;
    default:
        __builtin_unreachable();
    }
}

inline uint64_t monad_evsrc_iterator_tell(monad_evsrc_const_iterator_t iter)
{
    switch (iter.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        return iter.ring_iter->read_last_seqno;
    case MONAD_EVSRC_EVCAP_SECTION:
        return (uint64_t)(iter.evcap_iter->event_section_next -
                          iter.evcap_iter->event_section->section_base);
    default:
        __builtin_unreachable();
    }
}

inline void
monad_evsrc_iterator_seek(monad_evsrc_iterator_t iter, uint64_t position)
{
    switch (iter.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        iter.ring_iter->read_last_seqno = position;
        break;
    case MONAD_EVSRC_EVCAP_SECTION:
        iter.evcap_iter->event_section_next =
            iter.evcap_iter->event_section->section_base + position;
        break;
    default:
        __builtin_unreachable();
    }
}

inline uint64_t monad_evsrc_iterator_reset(monad_evsrc_iterator_t iter)
{
    struct monad_event_descriptor const *evcap_event;

    switch (iter.source_type) {
    case MONAD_EVSRC_EVENT_RING:
        return monad_event_iterator_reset(iter.ring_iter);
    case MONAD_EVSRC_EVCAP_SECTION:
        return monad_evcap_iterator_copy(iter.evcap_iter, &evcap_event, nullptr)
                   ? evcap_event->seqno
                   : 0;
    default:
        __builtin_unreachable();
    }
}

/*
 * Creation functions
 */

inline monad_evsrc_t
monad_evsrc_from_ring(struct monad_event_ring const *event_ring)
{
    monad_evsrc_t const s = {
        .source_type = MONAD_EVSRC_EVENT_RING, .event_ring = event_ring};
    return s;
}

inline monad_evsrc_t
monad_evsrc_from_evcap(struct monad_evcap_event_section const *event_section)
{
    monad_evsrc_t const s = {
        .source_type = MONAD_EVSRC_EVCAP_SECTION,
        .event_section = event_section};
    return s;
}

inline monad_evsrc_iterator_t
monad_evsrc_iterator_from_ring(struct monad_event_iterator *iter)
{
    monad_evsrc_iterator_t const i = {
        .source_type = MONAD_EVSRC_EVENT_RING, .ring_iter = iter};
    return i;
}

inline monad_evsrc_const_iterator_t
monad_evsrc_iterator_from_ring_const(struct monad_event_iterator const *iter)
{
    monad_evsrc_const_iterator_t const i = {
        .source_type = MONAD_EVSRC_EVENT_RING, .ring_iter = iter};
    return i;
}

inline monad_evsrc_iterator_t
monad_evsrc_iterator_from_evcap(struct monad_evcap_iterator *iter)
{
    monad_evsrc_iterator_t const i = {
        .source_type = MONAD_EVSRC_EVCAP_SECTION, .evcap_iter = iter};
    return i;
}

inline monad_evsrc_const_iterator_t
monad_evsrc_iterator_from_evcap_const(struct monad_evcap_iterator const *iter)
{
    monad_evsrc_const_iterator_t const i = {
        .source_type = MONAD_EVSRC_EVCAP_SECTION, .evcap_iter = iter};
    return i;
}

#ifdef __cplusplus
} // extern "C"
#endif
