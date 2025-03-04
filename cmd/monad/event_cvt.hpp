#pragma once

#include <monad/config.hpp>
#include <monad/core/address.hpp>
#include <monad/core/bytes.hpp>
#include <monad/core/int.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <span>
#include <vector>

struct monad_exec_proposal_metadata;

MONAD_NAMESPACE_BEGIN

struct BlockHeader;
struct CallFrame;
struct MonadConsensusBlockHeader;
struct MonadVote;
struct Receipt;
class State;
struct Transaction;

namespace event_cross_validation_test
{
    class ExpectedDataRecorder
    {
    public:
        explicit ExpectedDataRecorder(std::filesystem::path const &);
        ~ExpectedDataRecorder();

        void record_execution(
            bytes32_t const &bft_block_id, uint256_t const &chain_id,
            bytes32_t const &eth_block_hash,
            MonadConsensusBlockHeader const &input_header,
            BlockHeader const &output_header, std::span<Transaction const>,
            std::span<Receipt const>, std::span<Address const> senders,
            std::span<std::vector<CallFrame> const> call_frames,
            std::span<State const> txn_states, State const &prologue,
            State const &epilogue);

        void record_vote(monad_exec_proposal_metadata const &);

        void record_finalization(
            bytes32_t const &bft_block_id, uint64_t block_number);

        void record_verification(uint64_t block_number);

    private:
        std::FILE *file_;
        size_t array_size_;
        std::map<uint64_t, std::vector<monad_exec_proposal_metadata>>
            pending_proposal_map_;
    };
} // namespace event_round_trip_test

MONAD_NAMESPACE_END
