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

#include <category/core/config.hpp>
#include <category/core/fiber/priority_pool.hpp>
#include <category/core/result.hpp>
#include <category/execution/ethereum/core/address.hpp>
#include <category/execution/ethereum/core/receipt.hpp>
#include <category/execution/ethereum/dispatch_transaction.hpp>
#include <category/execution/ethereum/state3/state.hpp>
#include <category/execution/ethereum/trace/call_tracer.hpp>
#include <category/vm/evm/traits.hpp>

#include <evmc/evmc.h>

#include <memory>
#include <optional>
#include <vector>

MONAD_NAMESPACE_BEGIN

class BlockHashBuffer;
class BlockMetrics;
class BlockState;
class State;
struct Block;
struct Chain;

struct BlockEvmOutput
{
    State prologue_state;
    State epilogue_state;
    std::vector<Receipt> receipts;
    std::vector<State> txn_states;
};

template <Traits traits>
Result<std::pair<std::vector<Receipt>, std::vector<State>>>
execute_block_transactions(
    Chain const &, BlockHeader const &, std::vector<Transaction> const &,
    std::vector<Address> const &senders,
    std::vector<std::vector<std::optional<Address>>> const &authorities,
    BlockState &, BlockHashBuffer const &, fiber::PriorityPool &,
    BlockMetrics &, std::vector<std::unique_ptr<CallTracerBase>> &,
    RevertTransactionFn const & = [](Address const &, Transaction const &,
                                     uint64_t, State &) { return false; });

template <Traits traits>
Result<BlockEvmOutput> execute_block(
    Chain const &, Block const &, std::vector<Address> const &senders,
    std::vector<std::vector<std::optional<Address>>> const &authorities,
    BlockState &, BlockHashBuffer const &, fiber::PriorityPool &,
    BlockMetrics &, std::vector<std::unique_ptr<CallTracerBase>> &,
    RevertTransactionFn const & = [](Address const &, Transaction const &,
                                     uint64_t, State &) { return false; });

std::vector<std::optional<Address>>
recover_senders(std::vector<Transaction> const &, fiber::PriorityPool &);

std::vector<std::vector<std::optional<Address>>>
recover_authorities(std::vector<Transaction> const &, fiber::PriorityPool &);

MONAD_NAMESPACE_END
