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
#include <category/vm/runtime/types.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>

enum monad_evmt_event_type : uint16_t;

struct evmc_message;
struct evmc_result;

MONAD_NAMESPACE_BEGIN

enum EvmTraceFlag : uint8_t
{
    EVM_TRACE_NONE = 0,
    EVM_TRACE_BASIC = 0b0001,
    EVM_TRACE_DECODE = 0b0010,
    EVM_TRACE_STACK = 0b0100,
    EVM_TRACE_ALL = EVM_TRACE_BASIC | EVM_TRACE_DECODE | EVM_TRACE_STACK,
};

constexpr uint8_t EvmTraceFlagRequires[] = {
    EVM_TRACE_NONE,
    EVM_TRACE_NONE,
    EVM_TRACE_BASIC,
    EVM_TRACE_BASIC | EVM_TRACE_DECODE,
};

class EvmTraceEventRecorder : private EventRecorder
{
public:
    using EventRecorder::EventRecorder;

    template <typename T, std::same_as<std::span<std::byte const>>... U>
    [[nodiscard]] ReservedEvent<T> reserve_evm_event(
        monad_evmt_event_type, vm::runtime::TraceFlowTag const &,
        uint64_t gas_remaining, U &&...trailing_bufs);

    using EventRecorder::commit;

    uint64_t record_marker_event(
        monad_evmt_event_type, vm::runtime::TraceFlowTag const &,
        uint64_t gas_remaining);

    [[nodiscard]] uint64_t record_message_call_enter(
        vm::runtime::TraceFlowTag const &, uint64_t gas_left,
        evmc_message const &);

    void record_message_call_exit(
        vm::runtime::TraceFlowTag const &, uint64_t gas_remaining,
        evmc_result const &);

    void record_transaction_evm_exit(
        vm::runtime::TraceFlowTag const &, uint64_t gas_remaining,
        evmc_result const &);
};

extern uint8_t g_evm_trace_flags;
extern std::unique_ptr<OwnedEventRing> g_evmt_event_ring;
extern std::unique_ptr<EvmTraceEventRecorder> g_evmt_event_recorder;

inline bool is_evm_trace_enabled(EvmTraceFlag flag)
{
    return (g_evm_trace_flags & flag) == flag;
}

template <typename T, std::same_as<std::span<std::byte const>>... U>
ReservedEvent<T> EvmTraceEventRecorder::reserve_evm_event(
    monad_evmt_event_type event_type,
    vm::runtime::TraceFlowTag const &trace_flow, uint64_t gas_remaining,
    U &&...trailing_bufs)
{
    ReservedEvent const r =
        this->reserve_event<T>(event_type, std::forward<U>(trailing_bufs)...);
    r.event->content_ext[MONAD_EVMT_EXT_TXN] = trace_flow.exec_txn_seqno;
    r.event->content_ext[MONAD_EVMT_EXT_MSG_CALL] = trace_flow.msg_call_seqno;
    r.event->content_ext[MONAD_EVMT_EXT_GAS] = gas_remaining;
    return r;
}

inline uint64_t EvmTraceEventRecorder::record_marker_event(
    monad_evmt_event_type event_type,
    vm::runtime::TraceFlowTag const &trace_flow, uint64_t gas_remaining)
{
    uint64_t seqno;
    uint8_t *payload_buf;
    monad_event_descriptor *const event =
        monad_event_recorder_reserve(&recorder_, 0, &seqno, &payload_buf);
    event->event_type = std::to_underlying(event_type);
    event->content_ext[MONAD_EVMT_EXT_TXN] = trace_flow.exec_txn_seqno;
    event->content_ext[MONAD_EVMT_EXT_MSG_CALL] = trace_flow.msg_call_seqno;
    event->content_ext[MONAD_EVMT_EXT_GAS] = gas_remaining;
    monad_event_recorder_commit(event, seqno);
    return seqno;
}

inline uint64_t record_evm_marker_event(
    monad_evmt_event_type event_type,
    vm::runtime::TraceFlowTag const &trace_flow, uint64_t gas_remaining)
{
    if (is_evm_trace_enabled(EVM_TRACE_BASIC)) {
        auto *const recorder = g_evmt_event_recorder.get();
        return recorder->record_marker_event(
            event_type, trace_flow, gas_remaining);
    }
    return 0;
}

MONAD_NAMESPACE_END
