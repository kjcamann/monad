#include <blockchain_test.hpp>
#include <ethereum_test.hpp>
#include <from_json.hpp>

#include <monad/chain/ethereum_mainnet.hpp>
#include <monad/core/address.hpp>
#include <monad/core/assert.h>
#include <monad/core/block.hpp>
#include <monad/core/byte_string.hpp>
#include <monad/core/bytes.hpp>
#include <monad/core/int.hpp>
#include <monad/core/keccak.hpp>
#include <monad/core/receipt.hpp>
#include <monad/core/result.hpp>
#include <monad/core/rlp/block_rlp.hpp>
#include <monad/core/rlp/int_rlp.hpp>
#include <monad/core/rlp/transaction_rlp.hpp>
#include <monad/db/util.hpp>
#include <monad/execution/block_hash_buffer.hpp>
#include <monad/execution/execute_block.hpp>
#include <monad/execution/execute_transaction.hpp>
#include <monad/execution/genesis.hpp>
#include <monad/execution/switch_evmc_revision.hpp>
#include <monad/execution/txn_exec_output.hpp>
#include <monad/execution/validate_block.hpp>
#include <monad/fiber/priority_pool.hpp>
#include <monad/mpt/nibbles_view.hpp>
#include <monad/rlp/encode2.hpp>
#include <monad/state2/block_state.hpp>
#include <monad/state3/state.hpp>
#include <monad/test/config.hpp>

#include <evmc/evmc.h>
#include <evmc/evmc.hpp>

#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>

#include <quill/bundled/fmt/core.h>
#include <quill/bundled/fmt/format.h>
#include <quill/detail/LogMacros.h>

#include <boost/outcome/try.hpp>

#include <gtest/gtest.h>

#include <test_resource_data.h>

#include <algorithm>
#include <bit>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <vector>

MONAD_TEST_NAMESPACE_BEGIN

template <evmc_revision rev>
Result<std::vector<TxnExecOutput>> BlockchainTest::execute(
    Block &block, test::db_t &db, BlockHashBuffer const &block_hash_buffer)
{
    using namespace monad::test;

    BOOST_OUTCOME_TRY(static_validate_block<rev>(block));

    BlockState block_state(db);
    EthereumMainnet const chain;
    BOOST_OUTCOME_TRY(
        auto txn_exec_outputs,
        execute_block<rev>(
            chain, block, block_state, block_hash_buffer, *pool_));

    block_state.log_debug();
    block_state.commit(
        MonadConsensusBlockHeader::from_eth_header(block.header),
        block.transactions,
        txn_exec_outputs,
        block.ommers,
        block.withdrawals);
    db.finalize(block.header.number, block.header.number);

    auto output_header = db.read_eth_header();
    BOOST_OUTCOME_TRY(
        chain.validate_output_header(block.header, output_header));

    return txn_exec_outputs;
}

Result<std::vector<TxnExecOutput>> BlockchainTest::execute_dispatch(
    evmc_revision const rev, Block &block, test::db_t &db,
    BlockHashBuffer const &block_hash_buffer)
{
    MONAD_ASSERT(rev != EVMC_CONSTANTINOPLE);
    SWITCH_EVMC_REVISION(execute, block, db, block_hash_buffer);
    MONAD_ASSERT(false);
}

void BlockchainTest::validate_post_state(
    nlohmann::json const &json, nlohmann::json const &db)
{
    EXPECT_EQ(db.size(), json.size());

    for (auto const &[addr, j_account] : json.items()) {
        nlohmann::json const addr_json = addr;
        auto const addr_bytes = addr_json.get<Address>();
        auto const hashed_account = to_bytes(keccak256(addr_bytes.bytes));
        auto const db_addr_key = fmt::format("{}", hashed_account);

        ASSERT_TRUE(db.contains(db_addr_key)) << db_addr_key;
        auto const &db_account = db.at(db_addr_key);

        auto const expected_balance =
            fmt::format("{}", j_account.at("balance").get<uint256_t>());
        auto const expected_nonce = fmt::format(
            "0x{:x}", integer_from_json<uint64_t>(j_account.at("nonce")));
        auto const code = j_account.contains("code")
                              ? j_account.at("code").get<monad::byte_string>()
                              : monad::byte_string{};
        auto const expected_code = fmt::format(
            "0x{:02x}", fmt::join(std::as_bytes(std::span(code)), ""));

        EXPECT_EQ(db_account.at("balance").get<std::string>(), expected_balance)
            << db_addr_key;
        EXPECT_EQ(db_account.at("nonce").get<std::string>(), expected_nonce)
            << db_addr_key;
        EXPECT_EQ(db_account.at("code").get<std::string>(), expected_code)
            << db_addr_key;

        auto const &db_storage = db_account.at("storage");
        EXPECT_EQ(db_storage.size(), j_account.at("storage").size())
            << db_addr_key;
        for (auto const &[key, j_value] : j_account.at("storage").items()) {
            nlohmann::json const key_json = key;
            auto const key_bytes = key_json.get<bytes32_t>();
            auto const db_storage_key =
                fmt::format("{}", to_bytes(keccak256(key_bytes.bytes)));
            ASSERT_TRUE(db_storage.contains(db_storage_key)) << db_storage_key;
            auto const expected_value =
                fmt::format("{}", j_value.get<bytes32_t>());
            EXPECT_EQ(db_storage.at(db_storage_key).at("value"), expected_value)
                << db_storage_key;
        }
    }
}

fiber::PriorityPool *BlockchainTest::pool_ = nullptr;

void BlockchainTest::SetUpTestSuite()
{
    pool_ = new fiber::PriorityPool{1, 1};
}

void BlockchainTest::TearDownTestSuite()
{
    delete pool_;
    pool_ = nullptr;
}

void BlockchainTest::TestBody()
{
    std::ifstream f{file_};

    auto const json = nlohmann::json::parse(f);
    bool executed = false;
    for (auto const &[name, j_contents] : json.items()) {
        auto const network = j_contents.at("network").get<std::string>();
        if (!revision_map.contains(network)) {
            LOG_ERROR(
                "Skipping {} due to missing support for network {}",
                name,
                network);
            continue;
        }

        auto const rev = revision_map.at(network);
        if (revision_.has_value() && rev != revision_) {
            continue;
        }

        executed = true;

        InMemoryMachine machine;
        mpt::Db db{machine};
        db_t tdb{db};
        {
            auto const genesisJson = j_contents.at("genesisBlockHeader");
            auto header = read_genesis_blockheader(genesisJson);
            ASSERT_EQ(
                NULL_ROOT,
                evmc::from_hex<bytes32_t>(
                    genesisJson.at("transactionsTrie").get<std::string>())
                    .value());
            ASSERT_EQ(
                NULL_ROOT,
                evmc::from_hex<bytes32_t>(
                    genesisJson.at("receiptTrie").get<std::string>())
                    .value());
            ASSERT_EQ(
                NULL_LIST_HASH,
                evmc::from_hex<bytes32_t>(
                    genesisJson.at("uncleHash").get<std::string>())
                    .value());
            ASSERT_EQ(
                bytes32_t{},
                evmc::from_hex<bytes32_t>(
                    genesisJson.at("parentHash").get<std::string>())
                    .value());

            std::optional<std::vector<Withdrawal>> withdrawals;
            if (rev >= EVMC_SHANGHAI) {
                ASSERT_EQ(
                    NULL_ROOT,
                    evmc::from_hex<bytes32_t>(
                        genesisJson.at("withdrawalsRoot").get<std::string>())
                        .value());
                withdrawals.emplace(std::vector<Withdrawal>{});
            }

            BlockState bs{tdb};
            State state{bs, Incarnation{0, 0}};
            load_state_from_json(j_contents.at("pre"), state);
            bs.merge(state);
            bs.commit(
                MonadConsensusBlockHeader::from_eth_header(header),
                {} /* transactions */,
                {} /* txn_exec_outputs */,
                {} /* ommers */,
                withdrawals);
            tdb.finalize(0, 0);
            ASSERT_EQ(
                to_bytes(
                    keccak256(rlp::encode_block_header(tdb.read_eth_header()))),
                evmc::from_hex<bytes32_t>(
                    genesisJson.at("hash").get<std::string>())
                    .value());
        }
        auto db_post_state = tdb.to_json();

        BlockHashBufferFinalized block_hash_buffer;
        for (auto const &j_block : j_contents.at("blocks")) {

            auto const block_rlp = j_block.at("rlp").get<byte_string>();
            byte_string_view block_rlp_view{block_rlp};
            auto block = rlp::decode_block(block_rlp_view);
            if (block.has_error() || !block_rlp_view.empty()) {
                EXPECT_TRUE(j_block.contains("expectException")) << name;
                continue;
            }

            if (block.value().header.number == 0) {
                EXPECT_TRUE(j_block.contains("expectException"));
                continue;
            }
            if (j_block.contains("blocknumber") &&
                block.value().header.number !=
                    std::stoull(j_block.at("blocknumber").get<std::string>())) {
                EXPECT_TRUE(j_block.contains("expectException"));
                continue;
            }

            block_hash_buffer.set(
                block.value().header.number - 1,
                block.value().header.parent_hash);

            uint64_t const curr_block_number = block.value().header.number;
            auto const result =
                execute_dispatch(rev, block.value(), tdb, block_hash_buffer);
            if (!result.has_error()) {
                db_post_state = tdb.to_json();
                EXPECT_FALSE(j_block.contains("expectException"));
                EXPECT_EQ(tdb.state_root(), block.value().header.state_root)
                    << name;
                EXPECT_EQ(
                    tdb.transactions_root(),
                    block.value().header.transactions_root)
                    << name;
                EXPECT_EQ(
                    tdb.withdrawals_root(),
                    block.value().header.withdrawals_root)
                    << name;
                auto const encoded_ommers_res = db.get(
                    mpt::concat(FINALIZED_NIBBLE, OMMER_NIBBLE),
                    curr_block_number);
                EXPECT_TRUE(encoded_ommers_res.has_value());
                EXPECT_EQ(
                    to_bytes(keccak256(encoded_ommers_res.value())),
                    block.value().header.ommers_hash);
                if (rev >= EVMC_BYZANTIUM) {
                    EXPECT_EQ(
                        tdb.receipts_root(), block.value().header.receipts_root)
                        << name;
                }
                EXPECT_EQ(
                    result.value().size(), block.value().transactions.size())
                    << name;
                { // verify block header is stored correctly
                    auto res = db.get(
                        mpt::concat(FINALIZED_NIBBLE, BLOCKHEADER_NIBBLE),
                        curr_block_number);
                    EXPECT_TRUE(res.has_value());
                    auto const decode_res =
                        rlp::decode_block_header(res.value());
                    EXPECT_TRUE(decode_res.has_value());
                    auto const decoded_block_header = decode_res.value();
                    EXPECT_EQ(decode_res.value(), block.value().header);
                }
                { // look up block hash
                    auto const block_hash = keccak256(
                        rlp::encode_block_header(block.value().header));
                    auto res = db.get(
                        mpt::concat(
                            FINALIZED_NIBBLE,
                            BLOCK_HASH_NIBBLE,
                            mpt::NibblesView{block_hash}),
                        curr_block_number);
                    EXPECT_TRUE(res.has_value());
                    auto const decoded_number =
                        rlp::decode_unsigned<uint64_t>(res.value());
                    EXPECT_TRUE(decoded_number.has_value());
                    EXPECT_EQ(decoded_number.value(), curr_block_number);
                }
                // verify tx hash
                for (unsigned i = 0; i < block.value().transactions.size();
                     ++i) {
                    auto const &tx = block.value().transactions[i];
                    auto const hash = keccak256(rlp::encode_transaction(tx));
                    auto tx_hash_res = db.get(
                        mpt::concat(
                            FINALIZED_NIBBLE,
                            TX_HASH_NIBBLE,
                            mpt::NibblesView{hash}),
                        curr_block_number);
                    EXPECT_TRUE(tx_hash_res.has_value());
                    EXPECT_EQ(
                        tx_hash_res.value(),
                        rlp::encode_list2(
                            rlp::encode_unsigned(curr_block_number),
                            rlp::encode_unsigned(i)));
                }
            }
            else {
                EXPECT_TRUE(j_block.contains("expectException"))
                    << result.error().message().c_str();
            }
        }

        bool const has_post_state = j_contents.contains("postState");
        bool const has_post_state_hash = j_contents.contains("postStateHash");
        MONAD_DEBUG_ASSERT(has_post_state || has_post_state_hash);

        if (has_post_state_hash) {
            EXPECT_EQ(
                tdb.state_root(),
                j_contents.at("postStateHash").get<bytes32_t>());
        }

        if (has_post_state) {
            validate_post_state(j_contents.at("postState"), db_post_state);
        }
        LOG_DEBUG("post_state: {}", db_post_state.dump());
    }

    if (!executed) {
        MONAD_ASSERT(revision_.has_value());
        GTEST_SKIP() << "no test cases found revision=" << revision_.value();
    }
}

void register_blockchain_tests(std::optional<evmc_revision> const &revision)
{
    namespace fs = std::filesystem;

    // skip slow tests
    testing::FLAGS_gtest_filter +=
        ":-:BlockchainTests.GeneralStateTests/stTimeConsuming/*:"
        "BlockchainTests.GeneralStateTests/VMTests/vmPerformance/*:"
        "BlockchainTests.GeneralStateTests/stQuadraticComplexityTest/"
        "Call50000_sha256.json:"
        "BlockchainTests.ValidBlocks/bcForkStressTest/ForkStressTest.json";

    constexpr auto suite = "BlockchainTests";
    auto const root = test_resource::ethereum_tests_dir / suite;
    for (auto const &entry : fs::recursive_directory_iterator{root}) {
        auto const path = entry.path();
        if (path.extension() == ".json") {
            MONAD_ASSERT(entry.is_regular_file());

            // get rid of minus signs, which is a special symbol when used in //
            // filtering
            auto test = fmt::format("{}", fs::relative(path, root).string());
            std::ranges::replace(test, '-', '_');

            testing::RegisterTest(
                suite,
                test.c_str(),
                nullptr,
                nullptr,
                path.string().c_str(),
                0,
                [=] { return new BlockchainTest(path, revision); });
        }
    }
}

MONAD_TEST_NAMESPACE_END
