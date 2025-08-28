#pragma once

#include <category/core/bytes.hpp>
#include <category/core/config.hpp>
#include <category/core/int.hpp>
#include <category/execution/ethereum/core/address.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <vector>

struct monad_exec_block_qc;
struct monad_exec_block_tag;

MONAD_NAMESPACE_BEGIN

struct BlockHeader;
struct CallFrame;
struct Receipt;
class State;
struct Transaction;

namespace event_cross_validation_test
{
    enum UpdateVersion
    {
        V1, // Old Rust API
        V2 // New Rust API
    };

    class ExpectedDataRecorder
    {
    public:
        ExpectedDataRecorder();
        ~ExpectedDataRecorder();

        static std::unique_ptr<ExpectedDataRecorder>
        create(UpdateVersion, std::filesystem::path const &);

        void record_execution(
            bytes32_t const &bft_block_id, uint256_t const &chain_id,
            bytes32_t const &eth_block_hash, BlockHeader const &output_header,
            std::span<Transaction const>, std::span<Receipt const>,
            std::span<Address const> senders,
            std::span<std::vector<CallFrame> const> call_frames,
            std::span<State const> txn_states, State const &prologue,
            State const &epilogue);

        void record_vote(monad_exec_block_qc const &);

        void record_finalization(monad_exec_block_tag const &);

        void record_verification(uint64_t block_number);

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
} // namespace event_round_trip_test

MONAD_NAMESPACE_END
