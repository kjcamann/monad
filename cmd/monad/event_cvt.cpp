#include "event_cvt.hpp"

#include <category/core/assert.h>
#include <category/core/byte_string.hpp>
#include <category/core/bytes.hpp>
#include <category/core/config.hpp>
#include <category/core/int.hpp>
#include <category/core/keccak.hpp>
#include <category/execution/ethereum/core/account.hpp>
#include <category/execution/ethereum/core/address.hpp>
#include <category/execution/ethereum/core/block.hpp>
#include <category/execution/ethereum/core/fmt/address_fmt.hpp>
#include <category/execution/ethereum/core/fmt/bytes_fmt.hpp>
#include <category/execution/ethereum/core/receipt.hpp>
#include <category/execution/ethereum/core/rlp/transaction_rlp.hpp>
#include <category/execution/ethereum/core/signature.hpp>
#include <category/execution/ethereum/core/transaction.hpp>
#include <category/execution/ethereum/event/exec_event_ctypes.h>
#include <category/execution/ethereum/state3/account_state.hpp>
#include <category/execution/ethereum/state3/state.hpp>
#include <category/execution/ethereum/trace/call_frame.hpp>
#include <category/execution/monad/core/monad_block.hpp>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <errno.h>
#include <signal.h>
#include <string.h>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

using namespace monad;
using namespace monad::event_cross_validation_test;

extern sig_atomic_t volatile stop;

MONAD_ANONYMOUS_NAMESPACE_BEGIN

/*
 * JSON serialization helpers for basic types
 */

template <typename T, size_t Extent>
std::string as_hex_string(std::span<T const, Extent> s)
{
    return fmt::format("0x{:02x}", fmt::join(std::as_bytes(s), ""));
}

std::string as_hex_string(monad::byte_string const &bs)
{
    return as_hex_string(std::span{bs});
}

template <size_t N>
std::string as_hex_string(monad::byte_string_fixed<N> const &b)
{
    return as_hex_string(std::span{b});
}

std::string as_hex_string(monad::uint256_t const &u)
{
    return fmt::format("0x{}", to_string(u, 16));
}

/*
 * to_alloy_json overloads: serialize Ethereum structures in the same format
 * as Rust alloy libraries do
 */

nlohmann::json to_alloy_json(BlockHeader const &eth_header)
{
    nlohmann::json j;

    j["parentHash"] = fmt::to_string(eth_header.parent_hash);
    j["sha3Uncles"] = fmt::to_string(eth_header.ommers_hash);
    j["miner"] = fmt::to_string(eth_header.beneficiary);
    j["stateRoot"] = fmt::to_string(eth_header.state_root);
    j["transactionsRoot"] = fmt::to_string(eth_header.transactions_root);
    j["receiptsRoot"] = fmt::to_string(eth_header.receipts_root);
    j["logsBloom"] = as_hex_string(eth_header.logs_bloom);
    j["difficulty"] = as_hex_string(eth_header.difficulty);
    j["number"] = eth_header.number;
    j["gasLimit"] = eth_header.gas_limit;
    j["gasUsed"] = eth_header.gas_used;
    j["timestamp"] = eth_header.timestamp;
    j["extraData"] = as_hex_string(eth_header.extra_data);
    j["mixHash"] = fmt::to_string(eth_header.prev_randao);
    j["nonce"] = as_hex_string(eth_header.nonce);
    if (eth_header.base_fee_per_gas) {
        j["baseFeePerGas"] = as_hex_string(*eth_header.base_fee_per_gas);
    }
    if (eth_header.withdrawals_root) {
        j["withdrawalsRoot"] = fmt::to_string(*eth_header.withdrawals_root);
    }

    return j;
}

nlohmann::json to_alloy_json(Transaction const &txn)
{
    nlohmann::json j;

    nlohmann::json txn_header_json;
    j["type"] = std::to_underlying(txn.type);
    if (txn.sc.chain_id) {
        j["chainId"] = static_cast<uint64_t>(*txn.sc.chain_id);
    }
    j["nonce"] = txn.nonce;
    j["gasLimit"] = txn.gas_limit;
    if (txn.to) {
        j["to"] = fmt::to_string(*txn.to);
    }
    else {
        j["to"] = nullptr;
    }
    j["value"] = as_hex_string(txn.value);
    j["r"] = as_hex_string(txn.sc.r);
    j["s"] = as_hex_string(txn.sc.s);
    j["input"] = as_hex_string(txn.data);
    j["hash"] = fmt::to_string(
        std::bit_cast<bytes32_t>(keccak256(rlp::encode_transaction(txn))));

    switch (txn.type) {
    case TransactionType::legacy:
        [[fallthrough]];
    case TransactionType::eip2930:
        j["gasPrice"] = static_cast<uint64_t>(txn.max_fee_per_gas);
        break;

    case TransactionType::eip1559:
        j["maxFeePerGas"] = static_cast<uint64_t>(txn.max_fee_per_gas);
        j["maxPriorityFeePerGas"] =
            static_cast<uint64_t>(txn.max_priority_fee_per_gas);
        break;

    default:
        MONAD_ABORT_PRINTF(
            "unrecognized transaction type %hhu", std::to_underlying(txn.type));
    }

    if (txn.type == TransactionType::legacy) {
        j["v"] = static_cast<uint64_t>(get_v(txn.sc));
    }
    else {
        auto access_list_json = nlohmann::json::array();
        for (AccessEntry const &entry : txn.access_list) {
            nlohmann::json &entry_json = access_list_json.emplace_back();
            entry_json["address"] = fmt::to_string(entry.a);
            auto storage_keys_json = nlohmann::json::array();
            for (bytes32_t const &k : entry.keys) {
                storage_keys_json.emplace_back(fmt::to_string(k));
            }
            entry_json["storageKeys"] = std::move(storage_keys_json);
        }
        j["accessList"] = std::move(access_list_json);
        j["yParity"] = txn.sc.y_parity ? 1 : 0;
    }

    if (txn.type == TransactionType::eip7702) {
        auto authorization_list_json = nlohmann::json::array();
        for (AuthorizationEntry const &entry : txn.authorization_list) {
            nlohmann::json &entry_json = authorization_list_json.emplace_back();
            entry_json["chainId"] = static_cast<uint64_t>(*entry.sc.chain_id);
            entry_json["address"] = fmt::to_string(entry.address);
            entry_json["nonce"] = as_hex_string(entry.nonce);
            entry_json["yParity"] = entry.sc.y_parity ? 1 : 0;
            entry_json["r"] = as_hex_string(entry.sc.r);
            entry_json["s"] = as_hex_string(entry.sc.s);
        }
        j["authorizationList"] = std::move(authorization_list_json);
    }

    return j;
}

nlohmann::json to_alloy_json(Receipt::Log const &log)
{
    nlohmann::json j;

    j["address"] = fmt::to_string(log.address);
    nlohmann::json topics_array_json = nlohmann::json::array();
    for (bytes32_t const &t : log.topics) {
        topics_array_json.push_back(fmt::to_string(t));
    }
    j["topics"] = std::move(topics_array_json);
    j["data"] = as_hex_string(log.data);

    return j;
}

nlohmann::json to_alloy_json(CallFrame const &call_frame)
{
    nlohmann::json j;

    j["opcode"] = get_call_frame_opcode(call_frame.type, call_frame.flags);
    j["caller"] = fmt::to_string(call_frame.from);
    j["call_target"] = fmt::to_string(*call_frame.to);
    j["value"] = as_hex_string(call_frame.value);
    j["gas"] = call_frame.gas;
    j["gas_used"] = call_frame.gas_used;
    j["evmc_status_code"] = std::to_underlying(call_frame.status);
    j["depth"] = call_frame.depth;
    j["input"] = as_hex_string(call_frame.input);
    j["return_value"] = as_hex_string(call_frame.output);

    return j;
}

nlohmann::json to_json(monad_exec_block_tag const &tag)
{
    nlohmann::json j;
    j["id"] = fmt::to_string(tag.id);
    j["block_number"] = tag.block_number;
    return j;
}

/*
 * State serialization helpers, including computing the block storage delta
 * from all the State objects
 */

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

void update_storage_slots(
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

void update_block_account_info(
    State const &state,
    std::unordered_map<Address, BlockAccountInfo> &account_map)
{

    auto const &modified_state_map = state.current();
    for (auto const &[addr, original_acct_state] : state.original()) {
        auto const [i_account, inserted] = account_map.try_emplace(addr);
        BlockAccountInfo &account_info = i_account->second;
        if (inserted) {
            account_info.address = addr;
        }
        if (inserted) {
            Account const &account = original_acct_state.account_
                                         ? *original_acct_state.account_
                                         : Account{};

            // The first time we see it, copy it. Otherwise, we only
            // change it when it's modified
            account_info.original_nonce = account.nonce;
            account_info.original_balance = account.balance;
            account_info.code_hash = account.code_hash;
        }

        AccountState const *modified_state = nullptr;
        if (auto const it = modified_state_map.find(addr);
            it != std::end(modified_state_map)) {
            modified_state = std::addressof(it->second.recent());
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
            &original_acct_state.storage_,
            post_state_storage_map,
            &account_info.storage_accesses);
        update_storage_slots(
            &original_acct_state.transient_storage_,
            post_state_transient_map,
            &account_info.transient_accesses);
    }
}

nlohmann::json make_storage_access_json(
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

nlohmann::json state_to_json(State const &state)
{
    nlohmann::json accounts_object = nlohmann::json::object();

    auto const &modified_state_map = state.current();
    for (auto const &[addr, original_acct_state] : state.original()) {
        nlohmann::json account_json;

        uint64_t original_nonce = 0;
        uint256_t original_balance = 0;
        bytes32_t code_hash{NULL_HASH};

        if (!is_dead(original_acct_state.account_)) {
            Account const &original_account = *original_acct_state.account_;
            original_nonce = original_account.nonce;
            original_balance = original_account.balance;
            code_hash = original_account.code_hash;
        }

        account_json["original_nonce"] = original_nonce;
        account_json["original_balance"] = as_hex_string(original_balance);
        account_json["code_hash"] = fmt::to_string(code_hash);

        uint64_t modified_nonce;
        uint256_t modified_balance;

        AccountState const *modified_state = nullptr;
        if (auto const it = modified_state_map.find(addr);
            it != std::end(modified_state_map)) {
            modified_state = std::addressof(it->second.recent());
        }
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
            &original_acct_state.storage_, post_state_storage_map);
        account_json["transient_accesses"] = make_storage_access_json(
            &original_acct_state.transient_storage_, post_state_transient_map);

        accounts_object[fmt::to_string(addr)] = std::move(account_json);
    }
    return accounts_object;
}

nlohmann::json to_json(BlockAccountInfo::storage_map const &map)
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

nlohmann::json to_json(std::unordered_map<Address, BlockAccountInfo> const &m)
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

MONAD_ANONYMOUS_NAMESPACE_END

struct ExpectedDataRecorder::Impl
{
    UpdateVersion update_version;
    std::FILE *file;
    size_t array_size;
    std::map<uint64_t, std::vector<monad_exec_block_tag>> pending_proposal_map;
};

ExpectedDataRecorder::ExpectedDataRecorder()
    : impl_{std::make_unique<Impl>()}
{
}

std::unique_ptr<ExpectedDataRecorder> ExpectedDataRecorder::create(
    UpdateVersion update_version, std::filesystem::path const &file_path)
{
    auto cvt_recorder = std::make_unique<ExpectedDataRecorder>();
    cvt_recorder->impl_->update_version = update_version;
    cvt_recorder->impl_->file = std::fopen(file_path.c_str(), "w");
    if (cvt_recorder->impl_->file == nullptr) {
        MONAD_ABORT_PRINTF(
            "ExpectedDataRecorder cannot continue without "
            "file %s: %d (%s)",
            file_path.c_str(),
            errno,
            strerror(errno));
    }
    // Open the array
    std::print(cvt_recorder->impl_->file, "[");
    return cvt_recorder;
}

ExpectedDataRecorder::~ExpectedDataRecorder()
{
    std::println(impl_->file, "\n]");
    std::fclose(impl_->file);
}

void ExpectedDataRecorder::record_execution(
    bytes32_t const &bft_block_id, uint256_t const &chain_id,
    bytes32_t const &eth_block_hash, BlockHeader const &output_header,
    std::span<Transaction const> txns, std::span<Receipt const> receipts,
    std::span<Address const> senders,
    std::span<std::vector<CallFrame> const> call_frames,
    std::span<State const> txn_states, State const &prologue,
    State const &epilogue)
{
    if (stop == 1) {
        return;
    }

    uint64_t cumulative_gas_used = 0;
    nlohmann::json txn_array_json = nlohmann::json::array();
    for (size_t i = 0; i < size(txns); ++i) {
        Transaction const &txn = txns[i];
        Receipt const &receipt = receipts[i];
        std::vector<CallFrame> const &txn_call_frames = call_frames[i];

        nlohmann::json logs_array_json = nlohmann::json::array();
        for (Receipt::Log const &log : receipt.logs) {
            logs_array_json.push_back(to_alloy_json(log));
        }

        nlohmann::json receipt_json;
        receipt_json["status"] = receipt.status;
        receipt_json["cumulativeGasUsed"] = receipt.gas_used;
        receipt_json["logs"] = std::move(logs_array_json);

        nlohmann::json txn_json;
        txn_json["txn_index"] = i;
        txn_json["txn_envelope"] = to_alloy_json(txn);
        txn_json["sender"] = fmt::to_string(senders[i]);
        txn_json["receipt"] = std::move(receipt_json);
        txn_json["txn_gas_used"] = receipt.gas_used - cumulative_gas_used;
        if (impl_->update_version == UpdateVersion::V1) {
            nlohmann::json call_frames_array_json = nlohmann::json::array();
            for (CallFrame const &call_frame : txn_call_frames) {
                call_frames_array_json.push_back(to_alloy_json(call_frame));
            }
            txn_json["call_frames"] = std::move(call_frames_array_json);
            txn_json["account_accesses"] = state_to_json(txn_states[i]);
        }

        cumulative_gas_used = receipt.gas_used;
        txn_array_json.push_back(std::move(txn_json));
    }

    std::unordered_map<Address, BlockAccountInfo> block_account_map;
    if (impl_->update_version == UpdateVersion::V1) {
        update_block_account_info(prologue, block_account_map);
        for (State const &s : txn_states) {
            update_block_account_info(s, block_account_map);
        }
        update_block_account_info(epilogue, block_account_map);
    }

    monad_exec_block_tag block_tag = {
        .id = bft_block_id, .block_number = output_header.number};

    nlohmann::json j;
    auto const &consensus_state_key = impl_->update_version == UpdateVersion::V1
                                          ? "consensus_state"
                                          : "commit_state";
    j[consensus_state_key] = "Proposed";
    j["block_tag"] = to_json(block_tag);
    j["chain_id"] = static_cast<uint64_t>(chain_id);
    j["eth_header"] = to_alloy_json(output_header);
    j["eth_block_hash"] = fmt::to_string(eth_block_hash);
    j["transactions"] = std::move(txn_array_json);
    if (impl_->update_version == UpdateVersion::V1) {
        j["prologue_account_accesses"] = state_to_json(prologue);
        j["epilogue_account_accesses"] = state_to_json(epilogue);
        j["all_account_accesses"] = to_json(block_account_map);
    }

    if (impl_->array_size++ > 0) {
        std::print(impl_->file, ",");
    }
    std::print(impl_->file, "\n{{\"Executed\":{0}}}", j.dump());

    auto [i_pending, _] = impl_->pending_proposal_map.emplace(
        output_header.number, std::vector<monad_exec_block_tag>());
    std::vector<monad_exec_block_tag> &proposals = i_pending->second;
    proposals.push_back(std::move(block_tag));
}

void ExpectedDataRecorder::record_vote(monad_exec_block_qc const &qc)
{
    if (stop == 1) {
        return;
    }

    nlohmann::json j;
    std::string_view update_name;

    auto const i_pending =
        impl_->pending_proposal_map.find(qc.block_tag.block_number);
    if (i_pending != impl_->pending_proposal_map.end()) {
        update_name = "Referendum";
        j["block_tag"] = to_json(qc.block_tag);
        j["outcome"] =
            impl_->update_version == UpdateVersion::V1 ? "QC" : "Voted";
        j["superseded_proposals"] = nlohmann::json::array();
    }
    else if (impl_->update_version == UpdateVersion::V1) {
        update_name = "UnknownProposal";
        j["block_number"] = qc.block_tag.block_number;
        j["block_id"] = fmt::to_string(qc.block_tag.id);
        j["consensus_state"] = "QC";
    }
    else {
        MONAD_ASSERT(impl_->update_version == UpdateVersion::V2);
        return;
    }

    if (impl_->array_size++ > 0) {
        std::print(impl_->file, ",");
    }
    std::print(impl_->file, "\n{{\"{0}\":{1}}}", update_name, j.dump());
}

void ExpectedDataRecorder::record_finalization(
    monad_exec_block_tag const &block_tag)
{
    if (stop == 1) {
        return;
    }

    std::optional<monad_exec_block_tag> finalized;
    nlohmann::json abandoned = nlohmann::json::array();

    auto const i_pending =
        impl_->pending_proposal_map.find(block_tag.block_number);
    if (i_pending != end(impl_->pending_proposal_map)) {
        MONAD_ASSERT(impl_->array_size > 0);
        std::vector<monad_exec_block_tag> candidate_proposals =
            std::move(i_pending->second);
        // Sort candidate block IDs so that abandoned events happen in
        // a well-defined order
        std::ranges::sort(candidate_proposals, {}, &monad_exec_block_tag::id);

        for (monad_exec_block_tag const &p : candidate_proposals) {
            if (p.id != block_tag.id) {
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
            impl_->pending_proposal_map.erase(i_pending);
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
        j["block_tag"] = to_json(*finalized);
        j["outcome"] = "Finalized";
        j["superseded_proposals"] = std::move(abandoned);
    }
    else if (impl_->update_version == UpdateVersion::V1) {
        update_name = "UnknownProposal";
        j["block_number"] = block_tag.block_number;
        j["block_id"] = fmt::to_string(block_tag.id);
        j["consensus_state"] = "Finalized";
    }
    else {
        MONAD_ASSERT(impl_->update_version == UpdateVersion::V2);
        return;
    }

    if (impl_->array_size++ > 0) {
        std::print(impl_->file, ",");
    }
    std::print(impl_->file, "\n{{\"{0}\":{1}}}", update_name, j.dump());
}

void ExpectedDataRecorder::record_verification(uint64_t block_number)
{
    if (stop == 1) {
        return;
    }

    nlohmann::json j;
    std::string_view update_name;

    auto i_pending = impl_->pending_proposal_map.find(block_number);
    if (i_pending == end(impl_->pending_proposal_map)) {
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

    std::vector<monad_exec_block_tag> const &proposals = i_pending->second;
    MONAD_ASSERT(size(proposals) == 1);
    update_name = "Referendum";
    j["block_tag"] = to_json(proposals[0]);
    j["outcome"] = "Verified";
    j["superseded_proposals"] = nlohmann::json::array();
    impl_->pending_proposal_map.erase(i_pending);

    if (impl_->array_size++ > 0) {
        std::print(impl_->file, ",");
    }
    std::print(impl_->file, "\n{{\"{0}\":{1}}}", update_name, j.dump());
}
