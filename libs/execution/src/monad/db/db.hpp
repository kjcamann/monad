#pragma once

#include <monad/config.hpp>
#include <monad/core/account.hpp>
#include <monad/core/address.hpp>
#include <monad/core/byte_string.hpp>
#include <monad/core/bytes.hpp>
#include <monad/core/withdrawal.hpp>
#include <monad/execution/code_analysis.hpp>
#include <monad/state2/state_deltas.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <span>

MONAD_NAMESPACE_BEGIN

struct BlockHeader;
struct MonadConsensusBlockHeader;
struct Transaction;
struct TxnExecOutput;
struct Withdrawal;

struct Db
{
    virtual std::optional<Account> read_account(Address const &) = 0;

    virtual bytes32_t
    read_storage(Address const &, Incarnation, bytes32_t const &key) = 0;

    virtual std::shared_ptr<CodeAnalysis> read_code(bytes32_t const &) = 0;

    virtual BlockHeader read_eth_header() = 0;
    virtual bytes32_t state_root() = 0;
    virtual bytes32_t receipts_root() = 0;
    virtual bytes32_t transactions_root() = 0;
    virtual std::optional<bytes32_t> withdrawals_root() = 0;

    virtual void set_block_and_round(
        uint64_t block_number,
        std::optional<uint64_t> round_number = std::nullopt) = 0;
    virtual void finalize(uint64_t block_number, uint64_t round_number) = 0;
    virtual void update_verified_block(uint64_t block_number) = 0;

    virtual void commit(
        StateDeltas const &, Code const &, MonadConsensusBlockHeader const &,
        std::span<Transaction const> = {}, std::span<TxnExecOutput const> = {},
        std::span<BlockHeader const> ommers = {},
        std::optional<std::span<Withdrawal const>> = std::nullopt) = 0;

    virtual std::string print_stats()
    {
        return {};
    }
};

MONAD_NAMESPACE_END
