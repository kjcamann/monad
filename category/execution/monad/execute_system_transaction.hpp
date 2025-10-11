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

#include <category/core/byte_string.hpp>
#include <category/core/config.hpp>
#include <category/execution/ethereum/execute_transaction.hpp>
#include <category/vm/evm/traits.hpp>

#include <evmc/evmc.h>

#include <memory>

MONAD_NAMESPACE_BEGIN

template <Traits traits>
class ExecuteSystemTransaction
{
    Chain const &chain_;
    uint64_t i_;
    Transaction const &tx_;
    Address const &sender_;
    BlockHeader const &header_;
    BlockState &block_state_;
    BlockMetrics &block_metrics_;
    boost::fibers::promise<void> &prev_;
    CallTracerBase &call_tracer_;
    std::unique_ptr<State> captured_state_;

public:
    ExecuteSystemTransaction(
        Chain const &, uint64_t i, Transaction const &, Address const &,
        BlockHeader const &, BlockState &, BlockMetrics &,
        boost::fibers::promise<void> &prev, CallTracerBase &);

    Result<Receipt> operator()();

    evmc_message to_message() const;
    Result<void> execute(State &);
    Receipt execute_final(State &);

    Result<void> execute_staking_syscall(
        State &state, byte_string_view data, uint256_t const &);

    std::unique_ptr<State> take_captured_state();
};

MONAD_NAMESPACE_END
