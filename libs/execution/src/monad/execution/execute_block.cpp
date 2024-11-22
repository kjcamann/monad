#include <monad/chain/chain.hpp>
#include <monad/config.hpp>
#include <monad/core/assert.h>
#include <monad/core/block.hpp>
#include <monad/core/fmt/transaction_fmt.hpp>
#include <monad/core/int.hpp>
#include <monad/core/likely.h>
#include <monad/core/receipt.hpp>
#include <monad/core/result.hpp>
#include <monad/core/withdrawal.hpp>
#include <monad/event/event.h>
#include <monad/event/event_recorder.h>
#include <monad/execution/block_hash_buffer.hpp>
#include <monad/execution/block_reward.hpp>
#include <monad/execution/ethereum/dao.hpp>
#include <monad/execution/execute_block.hpp>
#include <monad/execution/execute_transaction.hpp>
#include <monad/execution/explicit_evmc_revision.hpp>
#include <monad/execution/switch_evmc_revision.hpp>
#include <monad/execution/trace/event_trace.hpp>
#include <monad/execution/validate_block.hpp>
#include <monad/fiber/fiber.h>
#include <monad/fiber/fiber_semaphore.h>
#include <monad/fiber/priority_pool.hpp>
#include <monad/state2/block_state.hpp>
#include <monad/state3/state.hpp>

#include <evmc/evmc.h>

#include <intx/intx.hpp>

#include <boost/outcome/try.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

MONAD_NAMESPACE_BEGIN

// EIP-4895
constexpr void process_withdrawal(
    State &state, std::optional<std::vector<Withdrawal>> const &withdrawals)
{
    if (withdrawals.has_value()) {
        for (auto const &withdrawal : withdrawals.value()) {
            state.add_to_balance(
                withdrawal.recipient,
                uint256_t{withdrawal.amount} * uint256_t{1'000'000'000u});
        }
    }
}

inline void
transfer_balance_dao(BlockState &block_state, Incarnation const incarnation)
{
    State state{block_state, incarnation};

    for (auto const &addr : dao::child_accounts) {
        auto const balance = intx::be::load<uint256_t>(state.get_balance(addr));
        state.add_to_balance(dao::withdraw_account, balance);
        state.subtract_from_balance(addr, balance);
    }

    MONAD_ASSERT(block_state.can_merge(state));
    block_state.merge(state);
}

inline void set_beacon_root(BlockState &block_state, Block &block)
{
    constexpr auto BEACON_ROOTS_ADDRESS{
        0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02_address};
    constexpr uint256_t HISTORY_BUFFER_LENGTH{8191};

    State state{block_state, Incarnation{block.header.number, 0}};
    if (state.account_exists(BEACON_ROOTS_ADDRESS)) {
        uint256_t timestamp{block.header.timestamp};
        bytes32_t k1{
            to_bytes(to_big_endian(timestamp % HISTORY_BUFFER_LENGTH))};
        bytes32_t k2{to_bytes(to_big_endian(
            timestamp % HISTORY_BUFFER_LENGTH + HISTORY_BUFFER_LENGTH))};
        state.set_storage(
            BEACON_ROOTS_ADDRESS, k1, to_bytes(to_big_endian(timestamp)));
        state.set_storage(
            BEACON_ROOTS_ADDRESS,
            k2,
            block.header.parent_beacon_block_root.value());

        MONAD_ASSERT(block_state.can_merge(state));
        block_state.merge(state);
    }
}

template <evmc_revision rev>
Result<std::vector<ExecutionResult>> execute_block(
    Chain const &chain, Block &block, BlockState &block_state,
    BlockHashBuffer const &block_hash_buffer,
    fiber::PriorityPool &priority_pool)
{
    MONAD_EVENT(MONAD_EVENT_BLOCK_START, 0);
    TRACE_BLOCK_EVENT(StartBlock);

    if constexpr (rev >= EVMC_CANCUN) {
        set_beacon_root(block_state, block);
    }

    if constexpr (rev == EVMC_HOMESTEAD) {
        if (MONAD_UNLIKELY(block.header.number == dao::dao_block_number)) {
            transfer_balance_dao(
                block_state, Incarnation{block.header.number, 0});
        }
    }

    std::shared_ptr<std::optional<Address>[]> const senders{
        new std::optional<Address>[block.transactions.size()]};

    // When sender_semaphores[i] is released, it is safe to read senders[i]
    std::shared_ptr<monad_fiber_semaphore_t[]> const sender_semaphores{
        new monad_fiber_semaphore_t[block.transactions.size()]};

    // When txn_sync_semaphores[i] is released, it is safe for txn `i` to
    // try merging. Until then, we have to wait for txn `i - 1` (and earlier)
    // to be merged first.
    std::shared_ptr<monad_fiber_semaphore_t[]> const txn_sync_semaphores{
        new monad_fiber_semaphore_t[block.transactions.size() + 1]};

    std::shared_ptr<std::optional<Result<ExecutionResult>>[]> const results{
        new std::optional<Result<ExecutionResult>>[block.transactions.size()]};

    // txn 0 can always commit immediately, so its semaphore is born holding an
    // immediate wakeup token
    monad_fiber_semaphore_init(&txn_sync_semaphores[0]);
    monad_fiber_semaphore_release(&txn_sync_semaphores[0], 1);

    for (unsigned i = 0; i < block.transactions.size(); ++i) {
        monad_fiber_semaphore_init(&sender_semaphores[i]);
        monad_fiber_semaphore_init(&txn_sync_semaphores[i + 1]);
        priority_pool.submit(
            MONAD_FIBER_PRIO_HIGHEST + 2 * i,
            [i = i,
             senders = senders,
             sender_semaphores = sender_semaphores,
             &transaction = block.transactions[i]] {
                senders[i] = recover_sender(transaction);
                monad_fiber_semaphore_release(&sender_semaphores[i], 1);
            });
        priority_pool.submit(
            MONAD_FIBER_PRIO_HIGHEST + 2 * (i + 1),
            [&chain = chain,
             i = i,
             results = results,
             sender_semaphores = sender_semaphores,
             txn_sync_semaphores = txn_sync_semaphores,
             &transaction = block.transactions[i],
             &sender = senders[i],
             &header = block.header,
             &block_hash_buffer = block_hash_buffer,
             &block_state] {
                results[i] = execute<rev>(
                    chain,
                    i,
                    transaction,
                    sender,
                    header,
                    block_hash_buffer,
                    block_state,
                    &sender_semaphores[i],
                    &txn_sync_semaphores[i]);
                // Release the token that allows the transaction after us to
                // merge; if we're the last transaction, this wakes up the
                // thread that is running `execute_block`
                monad_fiber_semaphore_release(&txn_sync_semaphores[i + 1], 1);
            });
    }

    // Wait for the final txn in the block to wake us up
    auto const last = static_cast<std::ptrdiff_t>(block.transactions.size());
    monad_fiber_semaphore_thread_acquire_one(&txn_sync_semaphores[last]);

    std::vector<ExecutionResult> retvals;
    for (unsigned i = 0; i < block.transactions.size(); ++i) {
        MONAD_ASSERT(results[i].has_value());
        if (MONAD_UNLIKELY(results[i].value().has_error())) {
            LOG_ERROR(
                "tx {} {} validation failed: {}",
                i,
                block.transactions[i],
                results[i].value().assume_error().message().c_str());
        }
        BOOST_OUTCOME_TRY(auto retval, std::move(results[i].value()));
        retvals.push_back(std::move(retval));
    }

    // YP eq. 22
    uint64_t cumulative_gas_used = 0;
    for (auto &[receipt, call_frame] : retvals) {
        cumulative_gas_used += receipt.gas_used;
        receipt.gas_used = cumulative_gas_used;
    }

    State state{
        block_state, Incarnation{block.header.number, Incarnation::LAST_TX}};

    if constexpr (rev >= EVMC_SHANGHAI) {
        process_withdrawal(state, block.withdrawals);
    }

    apply_block_reward<rev>(state, block);

    if constexpr (rev >= EVMC_SPURIOUS_DRAGON) {
        state.destruct_touched_dead();
    }

    MONAD_ASSERT(block_state.can_merge(state));
    block_state.merge(state);

    return retvals;
}

EXPLICIT_EVMC_REVISION(execute_block);

Result<std::vector<ExecutionResult>> execute_block(
    Chain const &chain, evmc_revision const rev, Block &block,
    BlockState &block_state, BlockHashBuffer const &block_hash_buffer,
    fiber::PriorityPool &priority_pool)
{
    SWITCH_EVMC_REVISION(
        execute_block,
        chain,
        block,
        block_state,
        block_hash_buffer,
        priority_pool);
    MONAD_ASSERT(false);
}

MONAD_NAMESPACE_END
