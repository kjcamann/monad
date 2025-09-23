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

#ifndef MONAD_EXEC_ITER_HELP_INTERNAL
    #error This file should only be included directly by exec_iter_help.h
#endif

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <category/core/event/event_ring.h>
#include <category/core/event/event_source.h>
#include <category/core/likely.h>
#include <category/execution/ethereum/core/base_ctypes.h>
#include <category/execution/ethereum/event/exec_event_ctypes.h>

// Functions like monad_exec_get_block_number expect the caller to pass a
// descriptor containing a consensus event; if this is not the case, we need to
// seek to the nearest BLOCK_START and copy that event into a caller-provided
// buffer, then reseat the event_p pointer to refer to that event buffer instead
static inline bool _monad_exec_ensure_block(
    void const *source, struct monad_event_descriptor const **event_p,
    void const **payload, struct monad_event_descriptor *buf,
    monad_evsrc_copy_seqno_fn_t *const source_copy_seqno)
{
    if (MONAD_UNLIKELY(
            (*event_p)->content_ext[MONAD_FLOW_BLOCK_SEQNO] != 0 &&
            (*event_p)->event_type != MONAD_EXEC_BLOCK_START)) {
        if (MONAD_UNLIKELY(
                source_copy_seqno(
                    source,
                    (*event_p)->content_ext[MONAD_FLOW_BLOCK_SEQNO],
                    buf,
                    payload) != MONAD_EVSRC_SUCCESS)) {
            return false;
        }
        *event_p = buf;
    }
    return true;
}

// Copy the event descriptor for the consensus event pointed to by `iter`. If
// `iter` is pointing inside a block, rewind it to BLOCK_START, and copy that
// out instead (and set `*moved` to true); if false is returned, the event
// descriptor is not valid
static inline bool _monad_exec_iter_copy_consensus_event(
    void *iter, struct monad_event_descriptor *event, void const **payload,
    bool *moved, monad_evsrc_iter_seek_fn_t *const iter_seek,
    monad_evsrc_iter_set_seqno_fn_t *const iter_set_seqno,
    monad_evsrc_iter_tell_fn_t *const iter_tell,
    monad_evsrc_iter_try_copy_fn_t *const iter_try_copy)
{
    *moved = false;
    if (MONAD_UNLIKELY(
            iter_try_copy(iter, event, nullptr) != MONAD_EVSRC_SUCCESS)) {
        return false;
    }
    if (event->content_ext[MONAD_FLOW_BLOCK_SEQNO] != 0 &&
        event->event_type != MONAD_EXEC_BLOCK_START) {
        uint64_t const iter_save = iter_tell(iter);
        iter_set_seqno(iter, event->content_ext[MONAD_FLOW_BLOCK_SEQNO]);
        if (MONAD_UNLIKELY(
                iter_try_copy(iter, event, payload) != MONAD_EVSRC_SUCCESS)) {
            iter_seek(iter, iter_save);
            return false;
        }
        *moved = true;
    }
    return true;
}

/*
 * monad_exec_get_block_number
 */

static inline bool monad_exec_get_block_number_generic(
    void const *source, struct monad_event_descriptor const *event,
    void const *payload, uint64_t *block_number,
    monad_evsrc_check_payload_fn_t *const source_check_payload,
    monad_evsrc_copy_seqno_fn_t *const source_copy_seqno)
{
    struct monad_event_descriptor buf;

    if (MONAD_UNLIKELY(!_monad_exec_ensure_block(
            source, &event, &payload, &buf, source_copy_seqno))) {
        return false;
    }

    switch (event->event_type) {
    case MONAD_EXEC_BLOCK_START:
        *block_number = ((struct monad_exec_block_start const *)payload)
                            ->block_tag.block_number;
        break;

    case MONAD_EXEC_BLOCK_QC:
        *block_number = ((struct monad_exec_block_qc const *)payload)
                            ->block_tag.block_number;
        break;

    case MONAD_EXEC_BLOCK_FINALIZED:
        *block_number =
            ((struct monad_exec_block_tag const *)payload)->block_number;
        break;

    case MONAD_EXEC_BLOCK_VERIFIED:
        *block_number =
            ((struct monad_exec_block_verified *)payload)->block_number;
        break;

    default:
        return false;
    }

    return source_check_payload(source, event);
}

inline bool monad_exec_get_block_number_r(
    struct monad_event_ring const *event_ring,
    struct monad_event_descriptor const *event, void const *payload,
    uint64_t *block_number)
{
    return monad_exec_get_block_number_generic(
        event_ring,
        event,
        payload,
        block_number,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_r,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_r);
}

inline bool monad_exec_get_block_number_c(
    struct monad_evcap_event_section const *event_section,
    struct monad_event_descriptor const *event, void const *payload,
    uint64_t *block_number)
{
    return monad_exec_get_block_number_generic(
        event_section,
        event,
        payload,
        block_number,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_c,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_c);
}

inline bool monad_exec_get_block_number_a(
    struct monad_evsrc_any const *any,
    struct monad_event_descriptor const *event, void const *payload,
    uint64_t *block_number)
{
    return monad_exec_get_block_number_generic(
        any,
        event,
        payload,
        block_number,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_a,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_a);
}

/*
 * monad_exec_get_block_id
 */

static inline bool monad_exec_get_block_id_generic(
    void const *source, struct monad_event_descriptor const *event,
    void const *payload, monad_c_bytes32 *block_id,
    monad_evsrc_check_payload_fn_t *const source_check_payload,
    monad_evsrc_copy_seqno_fn_t *const source_copy_seqno)
{
    struct monad_event_descriptor buf;

    if (MONAD_UNLIKELY(!_monad_exec_ensure_block(
            source, &event, &payload, &buf, source_copy_seqno))) {
        return false;
    }

    switch (event->event_type) {
    case MONAD_EXEC_BLOCK_START:
        *block_id =
            ((struct monad_exec_block_start const *)payload)->block_tag.id;
        break;

    case MONAD_EXEC_BLOCK_QC:
        *block_id = ((struct monad_exec_block_qc const *)payload)->block_tag.id;
        break;

    case MONAD_EXEC_BLOCK_FINALIZED:
        *block_id = ((struct monad_exec_block_tag const *)payload)->id;
        break;

    default:
        return false;
    }

    return source_check_payload(source, event);
}

inline bool monad_exec_get_block_id_r(
    struct monad_event_ring const *event_ring,
    struct monad_event_descriptor const *event, void const *payload,
    monad_c_bytes32 *block_id)
{
    return monad_exec_get_block_id_generic(
        event_ring,
        event,
        payload,
        block_id,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_r,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_r);
}

inline bool monad_exec_get_block_id_c(
    struct monad_evcap_event_section const *event_section,
    struct monad_event_descriptor const *event, void const *payload,
    monad_c_bytes32 *block_id)
{
    return monad_exec_get_block_id_generic(
        event_section,
        event,
        payload,
        block_id,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_c,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_c);
}

inline bool monad_exec_get_block_id_a(
    struct monad_evsrc_any const *any,
    struct monad_event_descriptor const *event, void const *payload,
    monad_c_bytes32 *block_id)
{
    return monad_exec_get_block_id_generic(
        any,
        event,
        payload,
        block_id,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_a,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_a);
}

/*
 * monad_exec_iter_consensus_generic
 */

static inline bool monad_exec_iter_consensus_prev_generic(
    void *iter, enum monad_exec_event_type filter,
    struct monad_event_descriptor *event, void const **payload,
    monad_evsrc_iter_seek_fn_t *const iter_seek,
    monad_evsrc_iter_set_seqno_fn_t *const iter_set_seqno,
    monad_evsrc_iter_tell_fn_t *const iter_tell,
    monad_evsrc_iter_try_copy_fn_t *const iter_try_copy,
    monad_evsrc_iter_try_prev_fn_t *const iter_try_prev)
{
    struct monad_event_descriptor event_buf;
    void const *payload_buf;
    bool moved;
    uint64_t const iter_save = iter_tell(iter);

    if (event == nullptr) {
        event = &event_buf;
    }
    if (payload == nullptr) {
        payload = &payload_buf;
    }

    // Try to copy out the current consensus event
    if (MONAD_UNLIKELY(!_monad_exec_iter_copy_consensus_event(
            iter,
            event,
            payload,
            &moved,
            iter_seek,
            iter_set_seqno,
            iter_tell,
            iter_try_copy))) {
        return false;
    }
    if ((filter == MONAD_EXEC_NONE || filter == MONAD_EXEC_BLOCK_START) &&
        moved) {
        // The above call rewound the iterator from a block-internal event to
        // BLOCK_START; if this happens immediately upon entry and we're
        // interested in stopping at BLOCK_START events, then stop now
        return true;
    }

    // After the above check, if the iterator is valid then it is now pointing
    // at the "current" consensus event. This loop will walk backwards over
    // these type of events, and will stop in the following cases:
    //
    //   - immediately, if filter == MONAD_EXEC_NONE; this means the user
    //     isn't looking for a particular kind of consensus event, and only
    //     wants the immediately previous one
    //
    //   - as soon as filter == event_type, i.e., we find the immediately
    //     previous consensus event type with the given block state, e.g.,
    //     "find the previous BLOCK_FINALIZE"
    //
    // If we run out of events before this occurs, the iterator is reset to
    // its original position, and false is returned
    while (MONAD_UNLIKELY(
        iter_try_prev(iter, event, payload) == MONAD_EVSRC_SUCCESS)) {
        if (MONAD_UNLIKELY(!_monad_exec_iter_copy_consensus_event(
                iter,
                event,
                payload,
                &moved,
                iter_seek,
                iter_set_seqno,
                iter_tell,
                iter_try_copy))) {
            break;
        }
        if (filter == MONAD_EXEC_NONE ||
            (uint16_t)filter == event->event_type) {
            return true;
        }
    }

    iter_seek(iter, iter_save);
    return false;
}

inline bool monad_exec_iter_consensus_prev_ri(
    struct monad_event_ring_iter *iter, enum monad_exec_event_type filter,
    struct monad_event_descriptor *event, void const **payload)
{
    return monad_exec_iter_consensus_prev_generic(
        iter,
        filter,
        event,
        payload,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ri,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ri,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_rci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_rci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ri);
}

inline bool monad_exec_iter_consensus_prev_ci(
    struct monad_evcap_event_iter *iter, enum monad_exec_event_type filter,
    struct monad_event_descriptor *event, void const **payload)
{
    return monad_exec_iter_consensus_prev_generic(
        iter,
        filter,
        event,
        payload,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ci,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ci,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_cci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_cci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ci);
}

inline bool monad_exec_iter_consensus_prev_ai(
    struct monad_evsrc_any_iter *iter, enum monad_exec_event_type filter,
    struct monad_event_descriptor *event, void const **payload)
{
    return monad_exec_iter_consensus_prev_generic(
        iter,
        filter,
        event,
        payload,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ai,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ai,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_aci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_aci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ai);
}

static inline bool monad_exec_iter_block_number_prev_generic(
    void const *source, void *iter, uint64_t block_number,
    enum monad_exec_event_type filter, struct monad_event_descriptor *event,
    void const **payload,
    monad_evsrc_check_payload_fn_t *const source_check_payload,
    monad_evsrc_copy_seqno_fn_t *const source_copy_seqno,
    monad_evsrc_iter_seek_fn_t *const iter_seek,
    monad_evsrc_iter_set_seqno_fn_t *const iter_set_seqno,
    monad_evsrc_iter_tell_fn_t *const iter_tell,
    monad_evsrc_iter_try_copy_fn_t *const iter_try_copy,
    monad_evsrc_iter_try_prev_fn_t *const iter_try_prev)
{
    uint64_t cur_block_number;
    struct monad_event_descriptor event_buf;
    void const *payload_buf;
    uint64_t const iter_save = iter_tell(iter);

    switch (filter) {
    case MONAD_EXEC_NONE:
        [[fallthrough]];
    case MONAD_EXEC_BLOCK_START:
        [[fallthrough]];
    case MONAD_EXEC_BLOCK_QC:
        [[fallthrough]];
    case MONAD_EXEC_BLOCK_FINALIZED:
        [[fallthrough]];
    case MONAD_EXEC_BLOCK_VERIFIED:
        break;
    default:
        return false; // Not a valid filter value
    }

    if (event == nullptr) {
        event = &event_buf;
    }
    if (payload == nullptr) {
        payload = &payload_buf;
    }

    while (MONAD_LIKELY(monad_exec_iter_consensus_prev_generic(
        iter,
        filter,
        event,
        payload,
        iter_seek,
        iter_set_seqno,
        iter_tell,
        iter_try_copy,
        iter_try_prev))) {
        if (!monad_exec_get_block_number_generic(
                source,
                event,
                *payload,
                &cur_block_number,
                source_check_payload,
                source_copy_seqno)) {
            break;
        }
        if (block_number == cur_block_number) {
            return true;
        }
        if (cur_block_number < block_number &&
            (filter == MONAD_EXEC_BLOCK_FINALIZED ||
             filter == MONAD_EXEC_BLOCK_VERIFIED)) {
            break;
        }
    }

    iter_seek(iter, iter_save);
    return false;
}

inline bool monad_exec_iter_block_number_prev_ri(
    struct monad_event_ring_iter *iter, uint64_t block_number,
    enum monad_exec_event_type filter, struct monad_event_descriptor *event,
    void const **payload)
{
    return monad_exec_iter_block_number_prev_generic(
        iter->event_ring,
        iter,
        block_number,
        filter,
        event,
        payload,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_r,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_r,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ri,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ri,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_rci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_rci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ri);
}

inline bool monad_exec_iter_block_number_prev_ci(
    struct monad_evcap_event_iter *iter, uint64_t block_number,
    enum monad_exec_event_type filter, struct monad_event_descriptor *event,
    void const **payload)
{
    return monad_exec_iter_block_number_prev_generic(
        iter->event_section,
        iter,
        block_number,
        filter,
        event,
        payload,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_c,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_c,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ci,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ci,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_cci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_cci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ci);
}

inline bool monad_exec_iter_block_number_prev_ai(
    struct monad_evsrc_any_iter *iter, uint64_t block_number,
    enum monad_exec_event_type filter, struct monad_event_descriptor *event,
    void const **payload)
{
    return monad_exec_iter_block_number_prev_generic(
        monad_evsrc_any_from_aci(iter),
        iter,
        block_number,
        filter,
        event,
        payload,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_a,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_a,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ai,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ai,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_aci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_aci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ai);
}

static inline bool monad_exec_iter_block_id_prev_generic(
    void const *source, void *iter, monad_c_bytes32 const *target_block_id,
    enum monad_exec_event_type filter, struct monad_event_descriptor *event,
    void const **payload,
    monad_evsrc_check_payload_fn_t *const source_check_payload,
    monad_evsrc_copy_seqno_fn_t *const source_copy_seqno,
    monad_evsrc_iter_seek_fn_t *const iter_seek,
    monad_evsrc_iter_set_seqno_fn_t *const iter_set_seqno,
    monad_evsrc_iter_tell_fn_t *const iter_tell,
    monad_evsrc_iter_try_copy_fn_t *const iter_try_copy,
    monad_evsrc_iter_try_prev_fn_t *const iter_try_prev)
{
    struct monad_event_descriptor event_buf;
    void const *payload_buf;
    monad_c_bytes32 block_id_buf;
    uint64_t const iter_save = iter_tell(iter);

    switch (filter) {
    case MONAD_EXEC_NONE:
        [[fallthrough]];
    case MONAD_EXEC_BLOCK_START:
        [[fallthrough]];
    case MONAD_EXEC_BLOCK_QC:
        [[fallthrough]];
    case MONAD_EXEC_BLOCK_FINALIZED:
        break;
    default:
        return false; // Not a valid filter value
    }

    if (event == nullptr) {
        event = &event_buf;
    }
    if (payload == nullptr) {
        payload = &payload_buf;
    }

    while (MONAD_LIKELY(monad_exec_iter_consensus_prev_generic(
        iter,
        filter,
        event,
        payload,
        iter_seek,
        iter_set_seqno,
        iter_tell,
        iter_try_copy,
        iter_try_prev))) {
        if (event->event_type == MONAD_EXEC_BLOCK_VERIFIED) {
            continue;
        }
        if (!monad_exec_get_block_id_generic(
                source,
                event,
                *payload,
                &block_id_buf,
                source_check_payload,
                source_copy_seqno)) {
            return false;
        }
        if (memcmp(&block_id_buf, target_block_id, sizeof block_id_buf) == 0) {
            return true;
        }
        assert(
            (filter == MONAD_EXEC_BLOCK_START ||
             filter == MONAD_EXEC_BLOCK_QC) &&
            "block number matched, tag didn't, and not START/QC?");
    }

    iter_seek(iter, iter_save);
    return false;
}

inline bool monad_exec_iter_block_id_prev_ri(
    struct monad_event_ring_iter *iter, monad_c_bytes32 const *target_block_id,
    enum monad_exec_event_type filter, struct monad_event_descriptor *event,
    void const **payload)
{
    return monad_exec_iter_block_id_prev_generic(
        iter->event_ring,
        iter,
        target_block_id,
        filter,
        event,
        payload,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_r,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_r,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ri,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ri,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_rci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_rci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ri);
}

inline bool monad_exec_iter_block_id_prev_ci(
    struct monad_evcap_event_iter *iter, monad_c_bytes32 const *target_block_id,
    enum monad_exec_event_type filter, struct monad_event_descriptor *event,
    void const **payload)
{
    return monad_exec_iter_block_id_prev_generic(
        iter->event_section,
        iter,
        target_block_id,
        filter,
        event,
        payload,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_c,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_c,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ci,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ci,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_cci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_cci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ci);
}

inline bool monad_exec_iter_block_id_prev_ai(
    struct monad_evsrc_any_iter *iter, monad_c_bytes32 const *target_block_id,
    enum monad_exec_event_type filter, struct monad_event_descriptor *event,
    void const **payload)
{
    return monad_exec_iter_block_id_prev_generic(
        monad_evsrc_any_from_aci(iter),
        iter,
        target_block_id,
        filter,
        event,
        payload,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_a,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_a,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ai,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ai,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_aci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_aci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ai);
}

static inline bool _monad_exec_is_start_of_block(
    void const *source, struct monad_event_descriptor const *event,
    void const *payload, uint64_t block_number,
    monad_evsrc_check_payload_fn_t *const source_check_payload,
    monad_evsrc_copy_seqno_fn_t *const source_copy_seqno)
{
    uint64_t b;
    return event->event_type == MONAD_EXEC_BLOCK_START &&
           monad_exec_get_block_number_generic(
               source,
               event,
               payload,
               &b,
               source_check_payload,
               source_copy_seqno) &&
           b == block_number;
}

static inline bool monad_exec_iter_rewind_for_simple_replay_generic(
    void const *source, void *iter, uint64_t block_number,
    struct monad_event_descriptor *event, void const **payload,
    monad_evsrc_check_payload_fn_t *const source_check_payload,
    monad_evsrc_copy_seqno_fn_t *const source_copy_seqno,
    monad_evsrc_iter_seek_fn_t *const iter_seek,
    monad_evsrc_iter_set_seqno_fn_t *const iter_set_seqno,
    monad_evsrc_iter_tell_fn_t *const iter_tell,
    monad_evsrc_iter_try_copy_fn_t *const iter_try_copy,
    monad_evsrc_iter_try_prev_fn_t *const iter_try_prev)
{
    struct monad_event_descriptor event_buf;
    void const *payload_buf;
    uint64_t const iter_save = iter_tell(iter);

    if (event == nullptr) {
        event = &event_buf;
    }
    if (payload == nullptr) {
        payload = &payload_buf;
    }

    // First, scan backwards to find the BLOCK_FINALIZED for block_number
    if (!monad_exec_iter_block_number_prev_generic(
            source,
            iter,
            block_number,
            MONAD_EXEC_BLOCK_FINALIZED,
            event,
            payload,
            source_check_payload,
            source_copy_seqno,
            iter_seek,
            iter_set_seqno,
            iter_tell,
            iter_try_copy,
            iter_try_prev)) {
        return false; // No need to restore iter_save, done by callee
    }

    // There are an unknown number of events (proposed block EVM events,
    // consensus events) between the original proposal of this finalized block
    // and its finalization; the one thing we do know is that once we've seen
    // the BLOCK_START for its original proposal, we want the consensus
    // event immediately prior to that
    bool found_finalized_block_start = false;
    uint64_t prev_read = iter_tell(iter);

    while (monad_exec_iter_consensus_prev_generic(
               iter,
               MONAD_EXEC_NONE,
               event,
               payload,
               iter_seek,
               iter_set_seqno,
               iter_tell,
               iter_try_copy,
               iter_try_prev) &&
           !(found_finalized_block_start = _monad_exec_is_start_of_block(
                 source,
                 event,
                 *payload,
                 block_number,
                 source_check_payload,
                 source_copy_seqno))) {
        prev_read = iter_tell(iter);
    }

    if (found_finalized_block_start) {
        iter_seek(iter, prev_read);
        if (iter_try_copy(iter, event, payload) == MONAD_EVSRC_SUCCESS) {
            return true;
        }
    }

    iter_seek(iter, iter_save);
    return false;
}

inline bool monad_exec_iter_rewind_for_simple_replay_ri(
    struct monad_event_ring_iter *iter, uint64_t block_number,
    struct monad_event_descriptor *event, void const **payload)
{
    return monad_exec_iter_rewind_for_simple_replay_generic(
        iter->event_ring,
        iter,
        block_number,
        event,
        payload,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_r,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_r,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ri,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ri,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_rci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_rci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ri);
}

inline bool monad_exec_iter_rewind_for_simple_replay_ci(
    struct monad_evcap_event_iter *iter, uint64_t block_number,
    struct monad_event_descriptor *event, void const **payload)
{
    return monad_exec_iter_rewind_for_simple_replay_generic(
        iter->event_section,
        iter,
        block_number,
        event,
        payload,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_c,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_c,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ci,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ci,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_cci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_cci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ci);
}

inline bool monad_exec_iter_rewind_for_simple_replay_ai(
    struct monad_evsrc_any_iter *iter, uint64_t block_number,
    struct monad_event_descriptor *event, void const **payload)
{
    return monad_exec_iter_rewind_for_simple_replay_generic(
        monad_evsrc_any_from_aci(iter),
        iter,
        block_number,
        event,
        payload,
        (monad_evsrc_check_payload_fn_t *)monad_evsrc_check_payload_a,
        (monad_evsrc_copy_seqno_fn_t *)monad_evsrc_copy_seqno_a,
        (monad_evsrc_iter_seek_fn_t *)monad_evsrc_iter_seek_ai,
        (monad_evsrc_iter_set_seqno_fn_t *)monad_evsrc_iter_set_seqno_ai,
        (monad_evsrc_iter_tell_fn_t *)monad_evsrc_iter_tell_aci,
        (monad_evsrc_iter_try_copy_fn_t *)monad_evsrc_iter_try_copy_aci,
        (monad_evsrc_iter_try_prev_fn_t *)monad_evsrc_iter_try_prev_ai);
}
