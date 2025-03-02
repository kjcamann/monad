#include <monad/chain/chain.hpp>
#include <monad/config.hpp>
#include <monad/core/assert.h>
#include <monad/core/block.hpp>
#include <monad/core/cpu_relax.h>
#include <monad/core/eth_ctypes.h>
#include <monad/core/exec_event_ctypes.h>
#include <monad/core/fmt/transaction_fmt.hpp>
#include <monad/core/int.hpp>
#include <monad/core/likely.h>
#include <monad/core/receipt.hpp>
#include <monad/core/result.hpp>
#include <monad/core/withdrawal.hpp>
#include <monad/execution/block_hash_buffer.hpp>
#include <monad/execution/block_reward.hpp>
#include <monad/execution/ethereum/dao.hpp>
#include <monad/execution/execute_block.hpp>
#include <monad/execution/execute_transaction.hpp>
#include <monad/execution/explicit_evmc_revision.hpp>
#include <monad/execution/record_txn_events.hpp>
#include <monad/execution/switch_evmc_revision.hpp>
#include <monad/execution/trace/event_trace.hpp>
#include <monad/execution/validate_block.hpp>
#include <monad/fiber/priority_pool.hpp>
#include <monad/state2/block_state.hpp>
#include <monad/state3/state.hpp>

#include <evmc/evmc.h>
#include <intx/intx.hpp>

#include <boost/fiber/future/promise.hpp>
#include <boost/outcome/try.hpp>

#include <atomic>
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

inline void transfer_balance_dao(State &prologue_state)
{
    for (auto const &addr : dao::child_accounts) {
        auto const balance =
            intx::be::load<uint256_t>(prologue_state.get_balance(addr));
        prologue_state.add_to_balance(dao::withdraw_account, balance);
        prologue_state.subtract_from_balance(addr, balance);
    }
}

inline void set_beacon_root(State &prologue_state, Block &block)
{
    constexpr auto BEACON_ROOTS_ADDRESS{
        0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02_address};
    constexpr uint256_t HISTORY_BUFFER_LENGTH{8191};

    if (prologue_state.account_exists(BEACON_ROOTS_ADDRESS)) {
        uint256_t timestamp{block.header.timestamp};
        bytes32_t k1{
            to_bytes(to_big_endian(timestamp % HISTORY_BUFFER_LENGTH))};
        bytes32_t k2{to_bytes(to_big_endian(
            timestamp % HISTORY_BUFFER_LENGTH + HISTORY_BUFFER_LENGTH))};
        prologue_state.set_storage(
            BEACON_ROOTS_ADDRESS, k1, to_bytes(to_big_endian(timestamp)));
        prologue_state.set_storage(
            BEACON_ROOTS_ADDRESS,
            k2,
            block.header.parent_beacon_block_root.value());
    }
}

template <evmc_revision rev>
Result<std::vector<ExecutionResult>> execute_block(
    Chain const &chain, Block &block, BlockState &block_state,
    BlockHashBuffer const &block_hash_buffer,
    fiber::PriorityPool &priority_pool)
{
    TRACE_BLOCK_EVENT(StartBlock);

    // A few "system level" state-affecting operations occur prior to
    // transaction execution.
    State prologue_state{block_state, Incarnation{block.header.number, 0}};

    if constexpr (rev >= EVMC_CANCUN) {
        set_beacon_root(prologue_state, block);
    }

    if constexpr (rev == EVMC_HOMESTEAD) {
        if (MONAD_UNLIKELY(block.header.number == dao::dao_block_number)) {
            transfer_balance_dao(prologue_state);
        }
    }

    MONAD_ASSERT(block_state.can_merge(prologue_state));
    block_state.merge(prologue_state);
    record_account_access_events(
        MONAD_ACCT_ACCESS_BLOCK_PROLOGUE, prologue_state);

    std::shared_ptr<std::optional<Address>[]> const senders{
        new std::optional<Address>[block.transactions.size()]};

    std::shared_ptr<boost::fibers::promise<void>[]> promises{
        new boost::fibers::promise<void>[block.transactions.size()]};

    std::unique_ptr<std::atomic<bool>[]> const txn_record_sync_order_barriers{
        new std::atomic<bool>[block.transactions.size()] {}};

    for (unsigned i = 0; i < block.transactions.size(); ++i) {
        priority_pool.submit(
            i,
            [i = i,
             senders = senders,
             promises = promises,
             txn_record_sync = txn_record_sync_order_barriers.get(),
             &transaction = block.transactions[i]] {
                senders[i] = recover_sender(transaction);
                promises[i].set_value();
                record_txn_start_event(
                    i, transaction, senders[i], txn_record_sync[i]);
            });
    }

    for (unsigned i = 0; i < block.transactions.size(); ++i) {
        promises[i].get_future().wait();
    }

    std::shared_ptr<std::optional<Result<ExecutionResult>>[]> const results{
        new std::optional<Result<ExecutionResult>>[block.transactions.size()]};

    promises.reset(
        new boost::fibers::promise<void>[block.transactions.size() + 1]);
    promises[0].set_value();

    std::atomic<size_t> tx_exec_finished = 0;
    for (unsigned i = 0; i < block.transactions.size(); ++i) {
        priority_pool.submit(
            i,
            [&chain = chain,
             i = i,
             results = results,
             promises = promises,
             txn_record_sync = txn_record_sync_order_barriers.get(),
             &transaction = block.transactions[i],
             &sender = senders[i],
             &header = block.header,
             &block_hash_buffer = block_hash_buffer,
             &block_state,
             &tx_exec_finished] {
                results[i].emplace(execute<rev>(
                    chain,
                    i,
                    transaction,
                    sender,
                    header,
                    block_hash_buffer,
                    block_state,
                    promises[i]));
                promises[i + 1].set_value();
                record_txn_exec_result_events(
                    i, *results[i], txn_record_sync[i]);
                tx_exec_finished.fetch_add(1, std::memory_order::relaxed);
            });
    }

    auto const last = static_cast<std::ptrdiff_t>(block.transactions.size());
    promises[last].get_future().wait();

    // All transactions have released their merge-order synchronization
    // primitive (promises[i + 1]) but some stragglers could still be running
    // post-execution code that occurs immediately after that, e.g.
    // `record_txn_exec_result_events`. This waits for everything to finish
    // so that it's safe to assume we're the only ones using `results`.
    while (tx_exec_finished.load() < block.transactions.size()) {
        cpu_relax();
    }

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
    for (auto &[_1, receipt, _2, call_frame] : retvals) {
        cumulative_gas_used += receipt.gas_used;
        receipt.gas_used = cumulative_gas_used;
    }

    State epilogue_state{
        block_state, Incarnation{block.header.number, Incarnation::LAST_TX}};

    if constexpr (rev >= EVMC_SHANGHAI) {
        process_withdrawal(epilogue_state, block.withdrawals);
    }

    apply_block_reward<rev>(epilogue_state, block);

    if constexpr (rev >= EVMC_SPURIOUS_DRAGON) {
        epilogue_state.destruct_touched_dead();
    }

    MONAD_ASSERT(block_state.can_merge(epilogue_state));
    block_state.merge(epilogue_state);
    record_account_access_events(
        MONAD_ACCT_ACCESS_BLOCK_EPILOGUE, epilogue_state);

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
