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

#include <category/core/bytes.hpp>
#include <category/core/config.hpp>
#include <category/execution/ethereum/chain/chain.hpp>
#include <category/execution/ethereum/core/address.hpp>
#include <category/execution/ethereum/evm.hpp>
#include <category/execution/ethereum/precompiles.hpp>
#include <category/execution/ethereum/state3/state.hpp>
#include <category/execution/ethereum/trace/call_tracer.hpp>
#include <category/execution/ethereum/transaction_gas.hpp>
#include <category/vm/event/evmt_event_ctypes.h>
#include <category/vm/event/evmt_event_recorder.hpp>
#include <category/vm/evm/delegation.hpp>
#include <category/vm/evm/traits.hpp>
#include <category/vm/host.hpp>
#include <category/vm/runtime/types.hpp>

#include <intx/intx.hpp>

#include <evmc/evmc.h>
#include <evmc/evmc.hpp>

#include <functional>
#include <utility>

MONAD_NAMESPACE_BEGIN

static_assert(sizeof(vm::Host) == 56);
static_assert(alignof(vm::Host) == 8);

class BlockHashBuffer;

class EvmcHostBase : public vm::Host
{
    BlockHashBuffer const &block_hash_buffer_;

protected:
    evmc_tx_context const &tx_context_;
    State &state_;
    CallTracerBase &call_tracer_;
    std::function<bool()> revert_transaction_;

public:
    EvmcHostBase(
        CallTracerBase &, evmc_tx_context const &, BlockHashBuffer const &,
        State &, std::function<bool()> const &revert_transaction = [] {
            return false;
        }) noexcept;

    virtual ~EvmcHostBase() noexcept = default;

    virtual bytes32_t
    get_storage(Address const &, bytes32_t const &key) const noexcept override;

    virtual evmc_storage_status set_storage(
        Address const &, bytes32_t const &key,
        bytes32_t const &value) noexcept override;

    virtual evmc::uint256be
    get_balance(Address const &) const noexcept override;

    virtual size_t get_code_size(Address const &) const noexcept override;

    virtual bytes32_t get_code_hash(Address const &) const noexcept override;

    virtual size_t copy_code(
        Address const &, size_t offset, uint8_t *data,
        size_t size) const noexcept override;

    virtual evmc_tx_context const *get_tx_context() const noexcept override;

    virtual bytes32_t get_block_hash(int64_t) const noexcept override;

    virtual void emit_log(
        Address const &, uint8_t const *data, size_t data_size,
        bytes32_t const topics[], size_t num_topics) noexcept override;

    virtual evmc_access_status
    access_storage(Address const &, bytes32_t const &key) noexcept override;

    virtual bytes32_t get_transient_storage(
        Address const &, bytes32_t const &key) const noexcept override;

    virtual void set_transient_storage(
        Address const &, bytes32_t const &key,
        bytes32_t const &value) noexcept override;
};

static_assert(sizeof(EvmcHostBase) == 120);
static_assert(alignof(EvmcHostBase) == 8);

template <Traits traits>
struct EvmcHost final : public EvmcHostBase
{
    using EvmcHostBase::EvmcHostBase;

    virtual bool account_exists(Address const &address) const noexcept override
    {
        try {
            if constexpr (traits::evm_rev() < EVMC_SPURIOUS_DRAGON) {
                return state_.account_exists(address);
            }
            return !state_.account_is_dead(address);
        }
        catch (...) {
            capture_current_exception();
        }
        stack_unwind();
    }

    virtual bool selfdestruct(
        Address const &address, Address const &beneficiary) noexcept override
    {
        try {
            call_tracer_.on_self_destruct(address, beneficiary);
            return state_.selfdestruct<traits>(address, beneficiary);
        }
        catch (...) {
            capture_current_exception();
        }
        stack_unwind();
    }

    virtual evmc::Result call(evmc_message const &msg) noexcept override
    {
        try {
            // Record MSG_CALL_ENTER
            uint64_t msg_call_flow_seqno = 0;
            if (auto *const r = g_evmt_event_recorder.get()) {
                ReservedEvent const msg_call_enter =
                    r->reserve_evm_event<monad_evmt_msg_call_enter>(
                        MONAD_EVMT_MSG_CALL_ENTER,
                        this->get_exec_txn_seqno(),
                        0,
                        this->gas_remaining(),
                        std::as_bytes(
                            std::span{msg.input_data, msg.input_size}),
                        std::as_bytes(std::span{msg.code, msg.code_size}));
                msg_call_flow_seqno = msg_call_enter.seqno;
                msg_call_enter.event->content_ext[MONAD_EVMT_EXT_MSG_CALL] =
                    msg_call_flow_seqno;
                init_evm_msg_call(msg, msg_call_enter.payload);
                r->commit(msg_call_enter);
            }
            this->msg_call_seqno_push(msg_call_flow_seqno);

            evmc::Result result;
            if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2) {
                result = ::monad::create<traits>(this, state_, msg);

                // EIP-211
                if (result.status_code != EVMC_REVERT) {
                    result = evmc::Result{
                        result.status_code,
                        result.gas_left,
                        result.gas_refund,
                        result.create_address};
                }
            }
            else {
                result = ::monad::call(this, state_, msg, revert_transaction_);
            }

            record_evm_result(
                MONAD_EVMT_MSG_CALL_EXIT,
                this->get_exec_txn_seqno(),
                msg_call_flow_seqno,
                static_cast<uint64_t>(result.gas_left),
                result.raw());
            this->msg_call_seqno_pop();

            return result;
        }
        catch (...) {
            capture_current_exception();
        }
        stack_unwind();
    }

    virtual evmc_access_status
    access_account(Address const &address) noexcept override
    {
        try {
            if (is_precompile<traits>(address)) {
                return EVMC_ACCESS_WARM;
            }
            return state_.access_account(address);
        }
        catch (...) {
            capture_current_exception();
        }
        stack_unwind();
    }

    CallTracerBase &get_call_tracer() noexcept
    {
        return call_tracer_;
    }
};

static_assert(sizeof(EvmcHost<EvmTraits<EVMC_LATEST_STABLE_REVISION>>) == 120);
static_assert(alignof(EvmcHost<EvmTraits<EVMC_LATEST_STABLE_REVISION>>) == 8);

MONAD_NAMESPACE_END
