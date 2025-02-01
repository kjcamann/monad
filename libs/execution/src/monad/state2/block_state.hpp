#pragma once

#include <monad/config.hpp>
#include <monad/core/bytes.hpp>
#include <monad/db/db.hpp>
#include <monad/execution/code_analysis.hpp>
#include <monad/state2/state_deltas.hpp>
#include <monad/types/incarnation.hpp>

#include <memory>
#include <optional>
#include <span>

MONAD_NAMESPACE_BEGIN

struct BlockHeader;
class State;
struct Transaction;
struct TxnExecOutput;
struct Withdrawal;

class BlockState final
{
    Db &db_;
    StateDeltas state_{};
    Code code_{};

public:
    BlockState(Db &);

    std::optional<Account> read_account(Address const &);

    bytes32_t read_storage(Address const &, Incarnation, bytes32_t const &key);

    std::shared_ptr<CodeAnalysis> read_code(bytes32_t const &);

    bool can_merge(State const &);

    void merge(State const &);

    // TODO: remove round_number parameter, retrieve it from header instead once
    // we add the monad fields in BlockHeader
    void commit(
        MonadConsensusBlockHeader const &, std::span<Transaction const>,
        std::span<TxnExecOutput const>, std::span<BlockHeader const> ommers,
        std::optional<std::span<Withdrawal const>>);

    void log_debug();
};

MONAD_NAMESPACE_END
