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
 * This file defines the EVM trace event recorder, which is a global object.
 * It is up to the driver code using this library to configure it, otherwise
 * recording will remain disabled.
 */

#include <category/core/config.hpp>
#include <category/core/event/event_recorder.h>
#include <category/core/event/event_recorder.hpp>
#include <category/core/event/event_ring.h>
#include <category/core/event/owned_event_ring.hpp>
#include <category/vm/event/evmt_event_ctypes.h>
#include <category/vm/runtime/evm_ctypes.h>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>

#include <evmc/evmc.hpp>

enum monad_evmt_event_type : uint16_t;

MONAD_NAMESPACE_BEGIN

class EvmTraceEventRecorder : private EventRecorder
{
public:
    using EventRecorder::EventRecorder;

    template <typename T, std::same_as<std::span<std::byte const>>... U>
    [[nodiscard]] ReservedEvent<T> reserve_evm_event(
        monad_evmt_event_type, uint64_t exec_txn_seqno, uint64_t call_seqno,
        uint64_t gas_remaining, U &&...trailing_bufs);

    using EventRecorder::commit;

    uint64_t record_marker_event(
        monad_evmt_event_type, uint64_t exec_txn_seqno, uint64_t call_seqno,
        uint64_t gas_remaining);
};

template <typename T, std::same_as<std::span<std::byte const>>... U>
ReservedEvent<T> EvmTraceEventRecorder::reserve_evm_event(
    monad_evmt_event_type event_type, uint64_t exec_txn_seqno,
    uint64_t call_seqno, uint64_t gas_remaining, U &&...trailing_bufs)
{
    ReservedEvent const r =
        this->reserve_event<T>(event_type, std::forward<U>(trailing_bufs)...);
    r.event->content_ext[MONAD_EVMT_EXT_TXN] = exec_txn_seqno;
    r.event->content_ext[MONAD_EVMT_EXT_MSG_CALL] = call_seqno;
    r.event->content_ext[MONAD_EVMT_EXT_GAS] = gas_remaining;
    return r;
}

inline uint64_t EvmTraceEventRecorder::record_marker_event(
    monad_evmt_event_type event_type, uint64_t exec_txn_seqno,
    uint64_t call_seqno, uint64_t gas_remaining)
{
    uint64_t seqno;
    uint8_t *payload_buf;
    monad_event_descriptor *const event =
        monad_event_recorder_reserve(&recorder_, 0, &seqno, &payload_buf);
    event->event_type = std::to_underlying(event_type);
    event->content_ext[MONAD_EVMT_EXT_TXN] = exec_txn_seqno;
    event->content_ext[MONAD_EVMT_EXT_MSG_CALL] = call_seqno;
    event->content_ext[MONAD_EVMT_EXT_GAS] = gas_remaining;
    monad_event_recorder_commit(event, seqno);
    return seqno;
}

extern std::unique_ptr<OwnedEventRing> g_evmt_event_ring;
extern std::unique_ptr<EvmTraceEventRecorder> g_evmt_event_recorder;

inline uint64_t record_evm_marker_event(
    monad_evmt_event_type event_type, uint64_t exec_txn_seqno,
    uint64_t call_seqno, uint64_t gas_remaining)
{
    if (auto *const r = g_evmt_event_recorder.get()) {
        return r->record_marker_event(
            event_type, exec_txn_seqno, call_seqno, gas_remaining);
    }
    return 0;
}

inline uint64_t record_evm_result(
    monad_evmt_event_type event_type, uint64_t exec_txn_seqno,
    uint64_t call_seqno, uint64_t gas_remaining, evmc::Result const &result)
{
    if (auto *const r = g_evmt_event_recorder.get()) {
        std::span const output{result.output_data, result.output_size};
        ReservedEvent const event = r->reserve_evm_event<monad_c_evm_result>(
            event_type,
            exec_txn_seqno,
            call_seqno,
            gas_remaining,
            std::as_bytes(output));
        *event.payload = monad_c_evm_result{
            .status_code = std::to_underlying(result.status_code),
            .create_address = {}, // XXX deal with this later
            .gas_left = static_cast<uint64_t>(result.gas_left),
            .gas_refund = static_cast<uint64_t>(result.gas_refund),
            .output_data_length = static_cast<uint32_t>(result.output_size),
        };
        r->commit(event);
    }
    return 0;
}

MONAD_NAMESPACE_END
