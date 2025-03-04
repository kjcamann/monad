#pragma once

#include <monad/config.hpp>
#include <monad/core/receipt.hpp>
#include <monad/core/result.hpp>
#include <monad/execution/execute_transaction.hpp>
#include <monad/fiber/priority_pool.hpp>
#include <monad/state3/state.hpp>

#include <evmc/evmc.h>

#include <vector>

MONAD_NAMESPACE_BEGIN

struct Block;
class BlockHashBuffer;
class BlockState;

struct BlockResult
{
    State prologue_state;
    State epilogue_state;
    std::vector<ExecutionResult> txn_results;
};

template <evmc_revision rev>
Result<BlockResult> execute_block(
    Chain const &, Block &, BlockState &, BlockHashBuffer const &,
    fiber::PriorityPool &);

Result<BlockResult> execute_block(
    Chain const &, evmc_revision, Block &, BlockState &,
    BlockHashBuffer const &, fiber::PriorityPool &);

MONAD_NAMESPACE_END
