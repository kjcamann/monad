#pragma once

#include <category/core/bytes.hpp>
#include <category/core/config.hpp>
#include <category/core/int.hpp>
#include <category/execution/ethereum/core/address.hpp>
#include <category/execution/ethereum/trace/call_tracer.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
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

    class CVTCallTracer;

    class ExpectedDataRecorder
    {
    public:
        ExpectedDataRecorder();
        ~ExpectedDataRecorder();

        static std::unique_ptr<ExpectedDataRecorder>
        create(UpdateVersion, std::filesystem::path const &);

        void visit_transaction_state(unsigned txn_num, State const &);

        void visit_prologue_state(State const &);

        void visit_epilogue_state(State const &);

        void record_execution(
            bytes32_t const &bft_block_id, uint256_t const &chain_id,
            bytes32_t const &eth_block_hash, BlockHeader const &output_header,
            std::span<Transaction const>, std::span<Address const> senders,
            std::span<Receipt const>);

        void record_vote(monad_exec_block_qc const &);

        void record_finalization(monad_exec_block_tag const &);

        void record_verification(uint64_t block_number);

    private:
        friend class CVTCallTracer;
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

    class CVTCallTracer : public CallTracer
    {
    public:
        CVTCallTracer(
            Transaction const &, std::vector<CallFrame> &, unsigned txn_num,
            ExpectedDataRecorder *);

        virtual void on_finish(uint64_t const gas_used) override;

    private:
        unsigned txn_num_;
        ExpectedDataRecorder *cvt_recorder_;
    };

} // namespace event_round_trip_test

MONAD_NAMESPACE_END
