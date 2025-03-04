#include "event_cvt.hpp"

#include <monad/config.hpp>
#include <monad/core/account.hpp>
#include <monad/core/address.hpp>
#include <monad/core/assert.h>
#include <monad/core/byte_string.hpp>
#include <monad/core/bytes.hpp>
#include <monad/core/exec_event_ctypes.h>
#include <monad/core/fmt/address_fmt.hpp>
#include <monad/core/fmt/bytes_fmt.hpp>
#include <monad/core/int.hpp>
#include <monad/core/keccak.hpp>
#include <monad/core/receipt.hpp>
#include <monad/core/rlp/transaction_rlp.hpp>
#include <monad/core/signature.hpp>
#include <monad/core/transaction.hpp>
#include <monad/execution/trace/call_frame.hpp>
#include <monad/state3/account_state.hpp>
#include <monad/state3/state.hpp>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <errno.h>
#include <signal.h>
#include <string.h>

#include <nlohmann/json.hpp>
#include <quill/Quill.h>

namespace fs = std::filesystem;
using monad::event_cross_validation_test::ExpectedDataRecorder;

extern sig_atomic_t volatile stop;

template <typename T, size_t Extent>
static std::string as_hex_string(std::span<T const, Extent> s)
{
    return fmt::format("0x{:02x}", fmt::join(std::as_bytes(s), ""));
}

static std::string as_hex_string(monad::byte_string const &bs)
{
    return as_hex_string(std::span{bs});
}

template <size_t N>
static std::string as_hex_string(monad::byte_string_fixed<N> const &b)
{
    return as_hex_string(std::span{b});
}

static std::string as_hex_string(monad::uint256_t const &u)
{
    return fmt::format("0x{}", to_string(u, 16));
}

MONAD_NAMESPACE_BEGIN

struct StorageSlot
{
    bytes32_t original_value;
    std::optional<bytes32_t> modified_value;

    bytes32_t current_value() const
    {
        return modified_value.value_or(original_value);
    }
};

struct BlockAccountInfo
{
    using storage_map = std::unordered_map<bytes32_t, StorageSlot>;

    Address address;
    uint64_t original_nonce;
    std::optional<uint64_t> modified_nonce;
    uint256_t original_balance;
    std::optional<uint256_t> modified_balance;
    bytes32_t code_hash;
    storage_map storage_accesses;
    storage_map transient_accesses;

    uint64_t current_nonce() const
    {
        return modified_nonce.value_or(original_nonce);
    }

    uint256_t current_balance() const
    {
        return modified_balance.value_or(original_balance);
    }
};

static void update_storage_slots(
    AccountState::Map<bytes32_t, bytes32_t> const *prestate_storage,
    AccountState::Map<bytes32_t, bytes32_t> const *modified_storage,
    BlockAccountInfo::storage_map *merged_map)
{
    for (auto const &[key, value] : *prestate_storage) {
        auto const [i_slot, inserted] = merged_map->try_emplace(
            key,
            StorageSlot{
                .original_value = value, .modified_value = std::nullopt});
        if (modified_storage) {
            if (auto const i_modified = modified_storage->find(key);
                i_modified != end(*modified_storage) &&
                i_modified->second != i_slot->second.current_value()) {
                i_slot->second.modified_value = i_modified->second;
            }
        }
    }
}

static void update_block_account_info(
    State const &state,
    std::unordered_map<Address, BlockAccountInfo> &account_map)
{
    state.visit_accounts([&account_map](
                             Address const *addr,
                             AccountState const *prestate,
                             AccountState const *modified_state) {
        auto const [i_account, inserted] = account_map.try_emplace(*addr);
        BlockAccountInfo &account_info = i_account->second;
        if (inserted) {
            account_info.address = *addr;
        }
        if (inserted) {
            Account const &account =
                prestate->account_ ? *prestate->account_ : Account{};

            // The first time we see it, copy it. Otherwise, we only
            // change it when it's modified
            account_info.original_nonce = account.nonce;
            account_info.original_balance = account.balance;
            account_info.code_hash = account.code_hash;
        }
        if (modified_state) {
            uint64_t modified_nonce;
            uint256_t modified_balance;

            if (is_dead(modified_state->account_)) {
                modified_nonce = 0;
                modified_balance = 0;
            }
            else {
                modified_nonce = modified_state->account_->nonce;
                modified_balance = modified_state->account_->balance;
            }

            if (modified_nonce != account_info.current_nonce()) {
                account_info.modified_nonce = modified_nonce;
            }
            if (modified_balance != account_info.current_balance()) {
                account_info.modified_balance = modified_balance;
            }
        }

        auto const *const post_state_storage_map =
            modified_state ? &modified_state->storage_ : nullptr;
        auto const *const post_state_transient_map =
            modified_state ? &modified_state->transient_storage_ : nullptr;

        update_storage_slots(
            &prestate->storage_,
            post_state_storage_map,
            &account_info.storage_accesses);
        update_storage_slots(
            &prestate->transient_storage_,
            post_state_transient_map,
            &account_info.transient_accesses);
    });
}

static nlohmann::json make_storage_access_json(
    AccountState::Map<bytes32_t, bytes32_t> const *prestate_storage,
    AccountState::Map<bytes32_t, bytes32_t> const *modified_storage)
{
    nlohmann::json account_map = nlohmann::json::object();

    for (auto const &[key, value] : *prestate_storage) {
        nlohmann::json storage_slot_json;
        storage_slot_json["original_value"] = fmt::to_string(value);
        storage_slot_json["modified_value"] = nullptr;
        if (modified_storage) {
            if (auto const i = modified_storage->find(key);
                i != end(*modified_storage) && i->second != value) {
                storage_slot_json["modified_value"] = fmt::to_string(i->second);
            }
        }
        account_map[fmt::to_string(key)] = std::move(storage_slot_json);
    }

    return account_map;
}

static nlohmann::json state_to_json(State const &state)
{
    nlohmann::json accounts_object = nlohmann::json::object();
    state.visit_accounts([&accounts_object](
                             Address const *addr,
                             AccountState const *prestate,
                             AccountState const *modified_state) {
        nlohmann::json account_json;

        uint64_t original_nonce = 0;
        uint256_t original_balance = 0;
        bytes32_t code_hash{NULL_HASH};

        if (!is_dead(prestate->account_)) {
            Account const &original_account = *prestate->account_;
            original_nonce = original_account.nonce;
            original_balance = original_account.balance;
            code_hash = original_account.code_hash;
        }

        account_json["original_nonce"] = original_nonce;
        account_json["original_balance"] = as_hex_string(original_balance);
        account_json["code_hash"] = fmt::to_string(code_hash);

        uint64_t modified_nonce;
        uint256_t modified_balance;

        if (modified_state) {
            modified_nonce = is_dead(modified_state->account_)
                                 ? 0
                                 : modified_state->account_->nonce;
            modified_balance = is_dead(modified_state->account_)
                                   ? 0
                                   : modified_state->account_->balance;
        }
        else {
            modified_nonce = original_nonce;
            modified_balance = original_balance;
        }

        if (modified_nonce != original_nonce) {
            account_json["modified_nonce"] = modified_nonce;
        }
        else {
            account_json["modified_nonce"] = nullptr;
        }

        if (modified_balance != original_balance) {
            account_json["modified_balance"] = as_hex_string(modified_balance);
        }
        else {
            account_json["modified_balance"] = nullptr;
        }

        auto const *const post_state_storage_map =
            modified_state ? &modified_state->storage_ : nullptr;
        auto const *const post_state_transient_map =
            modified_state ? &modified_state->transient_storage_ : nullptr;

        account_json["storage_accesses"] = make_storage_access_json(
            &prestate->storage_, post_state_storage_map);
        account_json["transient_accesses"] = make_storage_access_json(
            &prestate->transient_storage_, post_state_transient_map);

        accounts_object[fmt::to_string(*addr)] = std::move(account_json);
    });
    return accounts_object;
}

static nlohmann::json to_json(BlockAccountInfo::storage_map const &map)
{
    nlohmann::json map_json = nlohmann::json::object();
    for (auto const &[key, slot] : map) {
        auto const &[original_value, opt_modified_value] = slot;
        nlohmann::json slot_json;
        slot_json["original_value"] = fmt::to_string(original_value);
        if (opt_modified_value) {
            slot_json["modified_value"] = fmt::to_string(*opt_modified_value);
        }
        else {
            slot_json["modified_value"] = nullptr;
        }
        map_json[fmt::to_string(key)] = std::move(slot_json);
    }
    return map_json;
}

static nlohmann::json
to_json(std::unordered_map<Address, BlockAccountInfo> const &m)
{
    nlohmann::json account_map = nlohmann::json::object();

    for (auto const &[addr, account_info] : m) {
        nlohmann::json account_json;

        account_json["original_nonce"] = account_info.original_nonce;
        if (account_info.modified_nonce) {
            account_json["modified_nonce"] = *account_info.modified_nonce;
        }
        else {
            account_json["modified_nonce"] = nullptr;
        }
        account_json["original_balance"] =
            as_hex_string(account_info.original_balance);
        if (account_info.modified_balance) {
            account_json["modified_balance"] =
                as_hex_string(*account_info.modified_balance);
        }
        else {
            account_json["modified_balance"] = nullptr;
        }
        account_json["code_hash"] = fmt::to_string(account_info.code_hash);
        account_json["storage_accesses"] =
            to_json(account_info.storage_accesses);
        account_json["transient_accesses"] =
            to_json(account_info.transient_accesses);

        account_map[fmt::to_string(addr)] = std::move(account_json);
    }

    return account_map;
}

static nlohmann::json to_json(monad_exec_proposal_metadata const &pm)
{
    nlohmann::json j;
    j["round"] = pm.round;
    j["epoch"] = pm.epoch;
    j["block_number"] = pm.block_number;
    j["id"] = fmt::to_string(pm.id);
    j["parent_round"] = pm.parent_round;
    j["parent_id"] = fmt::to_string(pm.parent_id);
    return j;
}

ExpectedDataRecorder::ExpectedDataRecorder(fs::path const &file_path)
    : array_size_{0}
{
    file_ = std::fopen(file_path.c_str(), "w");
    if (file_ == nullptr) {
        MONAD_ABORT_PRINTF(
            "ExpectedDataRecorder cannot continue without "
            "file %s: %d (%s)",
            file_path.c_str(),
            errno,
            strerror(errno));
    }
    // Open the array
    fmt::print(file_, "[");
}

ExpectedDataRecorder::~ExpectedDataRecorder()
{
    fmt::println(file_, "\n]");
    std::fclose(file_);
}

void ExpectedDataRecorder::record_execution(
    bytes32_t const &bft_block_id, uint256_t const &chain_id,
    bytes32_t const &eth_block_hash,
    MonadConsensusBlockHeader const &input_header,
    BlockHeader const &output_header, std::span<Transaction const> txns,
    std::span<Receipt const> receipts, std::span<Address const> senders,
    std::span<std::vector<CallFrame> const> call_frames,
    std::span<State const> txn_states, State const &prologue,
    State const &epilogue)
{
    nlohmann::json eth_header_json;

    if (stop == 1) {
        return;
    }

    eth_header_json["parentHash"] = fmt::to_string(output_header.parent_hash);
    eth_header_json["sha3Uncles"] = fmt::to_string(output_header.ommers_hash);
    eth_header_json["miner"] = fmt::to_string(output_header.beneficiary);
    eth_header_json["stateRoot"] = fmt::to_string(output_header.state_root);
    eth_header_json["transactionsRoot"] =
        fmt::to_string(output_header.transactions_root);
    eth_header_json["receiptsRoot"] =
        fmt::to_string(output_header.receipts_root);
    eth_header_json["logsBloom"] = as_hex_string(output_header.logs_bloom);
    eth_header_json["difficulty"] = as_hex_string(output_header.difficulty);
    eth_header_json["number"] = output_header.number;
    eth_header_json["gasLimit"] = output_header.gas_limit;
    eth_header_json["gasUsed"] = output_header.gas_used;
    eth_header_json["timestamp"] = output_header.timestamp;
    eth_header_json["extraData"] = as_hex_string(output_header.extra_data);
    eth_header_json["mixHash"] = fmt::to_string(output_header.prev_randao);
    eth_header_json["nonce"] = as_hex_string(output_header.nonce);
    if (output_header.base_fee_per_gas) {
        eth_header_json["baseFeePerGas"] =
            as_hex_string(*output_header.base_fee_per_gas);
    }
    if (output_header.withdrawals_root) {
        eth_header_json["withdrawalsRoot"] =
            fmt::to_string(*output_header.withdrawals_root);
    }

    uint64_t cumulative_gas_used = 0;
    nlohmann::json txn_array_json = nlohmann::json::array();
    for (size_t i = 0; i < size(txns); ++i) {
        Transaction const &txn = txns[i];
        Receipt const &receipt = receipts[i];
        std::vector<CallFrame> const &txn_call_frames = call_frames[i];

        nlohmann::json txn_header_json;
        txn_header_json["type"] = std::to_underlying(txn.type);
        if (txn.sc.chain_id) {
            txn_header_json["chainId"] =
                static_cast<uint64_t>(*txn.sc.chain_id);
        }
        txn_header_json["nonce"] = txn.nonce;
        txn_header_json["gasLimit"] = txn.gas_limit;
        if (txn.to) {
            txn_header_json["to"] = fmt::to_string(*txn.to);
        }
        else {
            txn_header_json["to"] = nullptr;
        }
        txn_header_json["value"] = as_hex_string(txn.value);
        txn_header_json["r"] = as_hex_string(txn.sc.r);
        txn_header_json["s"] = as_hex_string(txn.sc.s);
        txn_header_json["input"] = as_hex_string(txn.data);
        txn_header_json["hash"] = fmt::to_string(
            std::bit_cast<bytes32_t>(keccak256(rlp::encode_transaction(txn))));

        switch (txn.type) {
        case TransactionType::legacy:
            [[fallthrough]];
        case TransactionType::eip2930:
            txn_header_json["gasPrice"] =
                static_cast<uint64_t>(txn.max_fee_per_gas);
            break;

        case TransactionType::eip1559:
            txn_header_json["maxFeePerGas"] =
                static_cast<uint64_t>(txn.max_fee_per_gas);
            txn_header_json["maxPriorityFeePerGas"] =
                static_cast<uint64_t>(txn.max_priority_fee_per_gas);
            break;

        default:
            MONAD_ABORT_PRINTF(
                "unrecognized transaction type %hhu",
                std::to_underlying(txn.type));
        }

        if (txn.type == TransactionType::legacy) {
            txn_header_json["v"] = static_cast<uint64_t>(get_v(txn.sc));
        }
        else {
            // TODO(ken): we don't produce this currently in the event
            // system
            txn_header_json["accessList"] = nlohmann::json::array();
            txn_header_json["yParity"] = txn.sc.odd_y_parity ? 1 : 0;
            txn_header_json["v"] = txn.sc.odd_y_parity ? 1 : 0;
        }

        nlohmann::json logs_array_json = nlohmann::json::array();
        for (Receipt::Log const &log : receipt.logs) {
            nlohmann::json log_json;
            log_json["address"] = fmt::to_string(log.address);
            nlohmann::json topics_array_json = nlohmann::json::array();
            for (bytes32_t const &t : log.topics) {
                topics_array_json.push_back(fmt::to_string(t));
            }
            log_json["topics"] = std::move(topics_array_json);
            log_json["data"] = as_hex_string(log.data);
            logs_array_json.push_back(std::move(log_json));
        }

        nlohmann::json call_frames_array_json = nlohmann::json::array();
        for (CallFrame const &call_frame : txn_call_frames) {
            nlohmann::json call_frame_json;
            call_frame_json["opcode"] =
                get_call_frame_opcode(call_frame.type, call_frame.flags);
            call_frame_json["caller"] = fmt::to_string(call_frame.from);
            call_frame_json["call_target"] = fmt::to_string(*call_frame.to);
            call_frame_json["value"] = as_hex_string(call_frame.value);
            call_frame_json["gas"] = call_frame.gas;
            call_frame_json["gas_used"] = call_frame.gas_used;
            call_frame_json["evmc_status_code"] =
                std::to_underlying(call_frame.status);
            call_frame_json["depth"] = call_frame.depth;
            call_frame_json["input"] = as_hex_string(call_frame.input);
            call_frame_json["return_value"] = as_hex_string(call_frame.output);
            call_frames_array_json.push_back(std::move(call_frame_json));
        }

        nlohmann::json receipt_json;
        receipt_json["status"] = receipt.status;
        receipt_json["cumulativeGasUsed"] = receipt.gas_used;
        receipt_json["logs"] = std::move(logs_array_json);

        nlohmann::json txn_json;
        txn_json["txn_index"] = i;
        txn_json["txn_envelope"] = std::move(txn_header_json);
        txn_json["sender"] = fmt::to_string(senders[i]);
        txn_json["receipt"] = std::move(receipt_json);
        txn_json["txn_gas_used"] = receipt.gas_used - cumulative_gas_used;
        txn_json["call_frames"] = std::move(call_frames_array_json);
        txn_json["account_accesses"] = state_to_json(txn_states[i]);

        cumulative_gas_used = receipt.gas_used;
        txn_array_json.push_back(std::move(txn_json));
    }

    std::unordered_map<Address, BlockAccountInfo> block_account_map;
    update_block_account_info(prologue, block_account_map);
    for (State const &s : txn_states) {
        update_block_account_info(s, block_account_map);
    }
    update_block_account_info(epilogue, block_account_map);

    monad_exec_proposal_metadata const proposal = {
        .round = input_header.round,
        .epoch = input_header.epoch,
        .block_number = input_header.seqno,
        .id = bft_block_id,
        .parent_round = input_header.parent_round(),
        .parent_id = input_header.parent_id()};

    nlohmann::json j;
    j["consensus_state"] = "Proposed";
    j["proposal_meta"] = to_json(proposal);
    j["chain_id"] = static_cast<uint64_t>(chain_id);
    j["eth_header"] = std::move(eth_header_json);
    j["eth_block_hash"] = fmt::to_string(eth_block_hash);
    j["transactions"] = std::move(txn_array_json);
    j["prologue_account_accesses"] = state_to_json(prologue);
    j["epilogue_account_accesses"] = state_to_json(epilogue);
    j["all_account_accesses"] = to_json(block_account_map);

    if (array_size_++ > 0) {
        fmt::print(file_, ",");
    }
    fmt::print(file_, "\n{{\"Executed\":{0}}}", j.dump());

    auto [i_pending, _] = pending_proposal_map_.emplace(
        input_header.seqno, std::vector<monad_exec_proposal_metadata>());
    std::vector<monad_exec_proposal_metadata> &proposals = i_pending->second;
    proposals.push_back(std::move(proposal));
}

void ExpectedDataRecorder::record_vote(
    monad_exec_proposal_metadata const &proposal_meta)
{
    if (stop == 1) {
        return;
    }

    nlohmann::json j;
    std::string_view update_name;

    auto const i_pending =
        pending_proposal_map_.find(proposal_meta.block_number);
    if (i_pending != pending_proposal_map_.end()) {
        update_name = "Referendum";
        j["proposal_meta"] = to_json(proposal_meta);
        j["outcome"] = "QC";
        j["superseded_proposals"] = nlohmann::json::array();
    }
    else {
        update_name = "UnknownProposal";
        j["block_number"] = proposal_meta.block_number;
        j["block_id"] = fmt::to_string(proposal_meta.id);
        j["consensus_state"] = "QC";
    }

    if (array_size_++ > 0) {
        fmt::print(file_, ",");
    }
    fmt::print(file_, "\n{{\"{0}\":{1}}}", update_name, j.dump());
}

void ExpectedDataRecorder::record_finalization(
    bytes32_t const &bft_block_id, uint64_t block_number)
{
    if (stop == 1) {
        return;
    }

    std::optional<monad_exec_proposal_metadata> finalized;
    nlohmann::json abandoned = nlohmann::json::array();

    auto const i_pending = pending_proposal_map_.find(block_number);
    if (i_pending != end(pending_proposal_map_)) {
        MONAD_ASSERT(array_size_ > 0);
        std::vector<monad_exec_proposal_metadata> candidate_proposals =
            std::move(i_pending->second);
        // Sort candidate block IDs so that abandoned events happen in
        // a well-defined order
        std::ranges::sort(
            candidate_proposals, {}, &monad_exec_proposal_metadata::id);

        for (monad_exec_proposal_metadata const &p : candidate_proposals) {
            if (p.id != bft_block_id) {
                // Proposed block that is different from the one being
                // finalized, but with the same sequence number; this is
                // abandoned
                abandoned.emplace_back(to_json(p));
            }
            else {
                finalized = p;
            }
        }

        if (!finalized) {
            pending_proposal_map_.erase(i_pending);
        }
        else {
            // Keep it around, for verification
            i_pending->second.clear();
            i_pending->second.emplace_back(*finalized);
        }
    }

    nlohmann::json j;
    std::string_view update_name;
    if (finalized) {
        update_name = "Referendum";
        j["proposal_meta"] = to_json(*finalized);
        j["outcome"] = "Finalized";
        j["superseded_proposals"] = std::move(abandoned);
    }
    else {
        update_name = "UnknownProposal";
        j["block_number"] = block_number;
        j["block_id"] = fmt::to_string(bft_block_id);
        j["consensus_state"] = "Finalized";
    }

    if (array_size_++ > 0) {
        fmt::print(file_, ",");
    }
    fmt::print(file_, "\n{{\"{0}\":{1}}}", update_name, j.dump());
}

void ExpectedDataRecorder::record_verification(uint64_t block_number)
{
    if (stop == 1) {
        return;
    }

    nlohmann::json j;
    std::string_view update_name;

    auto i_pending = pending_proposal_map_.find(block_number);
    if (i_pending == end(pending_proposal_map_)) {
        update_name = "UnknownProposal";
        j["block_number"] = block_number;
        j["block_id"] = fmt::to_string(bytes32_t{});
        j["consensus_state"] = "Verified";
        // TODO(ken): for now, don't finish recording these, since
        //   Rust can't figure them out. It only knows how to find
        //   verified proposals through a small buffer in the
        //   event stream
        return;
    }

    std::vector<monad_exec_proposal_metadata> const &proposals =
        i_pending->second;
    MONAD_ASSERT(size(proposals) == 1);
    update_name = "Referendum";
    j["proposal_meta"] = to_json(proposals[0]);
    j["outcome"] = "Verified";
    j["superseded_proposals"] = nlohmann::json::array();
    pending_proposal_map_.erase(i_pending);

    if (array_size_++ > 0) {
        fmt::print(file_, ",");
    }
    fmt::print(file_, "\n{{\"{0}\":{1}}}", update_name, j.dump());
}

MONAD_NAMESPACE_END
