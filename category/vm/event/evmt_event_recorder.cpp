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

#include <category/core/config.hpp>
#include <category/core/event/event_recorder.hpp>
#include <category/core/event/owned_event_ring.hpp>
#include <category/vm/event/evmt_event_ctypes.h>
#include <category/vm/event/evmt_event_recorder.hpp>
#include <category/vm/evm/opcodes.hpp>
#include <category/vm/runtime/evm_ctypes.h>

#include <cstdint>
#include <memory>
#include <span>

#include <evmc/evmc.h>
#include <string.h>

MONAD_ANONYMOUS_NAMESPACE_BEGIN

monad::vm::compiler::EvmOpCode get_opcode_for_msg(evmc_message const &msg)
{
    using enum vm::compiler::EvmOpCode;
    switch (msg.kind) {
    case EVMC_CALL:
        return msg.flags & EVMC_STATIC ? STATICCALL : CALL;
    case EVMC_CALLCODE:
        return CALLCODE;
    case EVMC_DELEGATECALL:
        return DELEGATECALL;
    case EVMC_CREATE:
        return CREATE;
    case EVMC_CREATE2:
        return CREATE2;
    default:
        std::unreachable();
    }
}

MONAD_ANONYMOUS_NAMESPACE_END

MONAD_NAMESPACE_BEGIN

std::unique_ptr<OwnedEventRing> g_evmt_event_ring;
std::unique_ptr<EvmTraceEventRecorder> g_evmt_event_recorder;

void init_evm_msg_call(evmc_message const &msg, monad_c_evm_msg_call *payload)
{
    *payload = monad_c_evm_msg_call{
        .opcode = get_opcode_for_msg(msg),
        .depth = static_cast<uint32_t>(msg.depth),
        .gas = static_cast<uint64_t>(msg.gas),
        .code_address = msg.code_address,
        .sender = msg.sender,
        .recipient = msg.recipient,
        .value = {},
        .create2_salt = msg.create2_salt,
        .input_data_length = static_cast<uint32_t>(msg.input_size),
        .code_length = static_cast<uint32_t>(msg.code_size)};
    memcpy(payload->value.limbs, msg.value.bytes, sizeof msg.value);
}

uint64_t record_evm_result(
    monad_evmt_event_type event_type, uint64_t exec_txn_seqno,
    uint64_t call_seqno, uint64_t gas_remaining, evmc_result const &result)
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
            .create_address = result.create_address,
            .gas_left = static_cast<uint64_t>(result.gas_left),
            .gas_refund = static_cast<uint64_t>(result.gas_refund),
            .output_data_length = static_cast<uint32_t>(result.output_size),
        };
        r->commit(event);
    }
    return 0;
}

MONAD_NAMESPACE_END
