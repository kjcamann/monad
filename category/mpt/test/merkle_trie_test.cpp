// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "gtest/gtest.h"

#include "test_fixtures_base.hpp"
#include "test_fixtures_gtest.hpp"

#include <category/core/byte_string.hpp>
#include <category/mpt/node.hpp>
#include <category/mpt/trie.hpp>
#include <category/mpt/update.hpp>
#include <category/mpt/util.hpp>

#include <category/core/test_util/gtest_signal_stacktrace_printer.hpp> // NOLINT

#include <algorithm>
#include <cstdint>
#include <deque>
#include <iterator>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

using namespace ::monad::test;

template <typename TFixture>
struct TrieTest : public TFixture
{
};

using TrieTypes =
    ::testing::Types<InMemoryMerkleTrieGTest, OnDiskMerkleTrieGTest>;
TYPED_TEST_SUITE(TrieTest, TrieTypes);

template <typename TFixture>
struct EraseTrieTest : public TFixture
{
};

using EraseTrieType = ::testing::Types<
    EraseFixture<InMemoryMerkleTrieGTest>, EraseFixture<OnDiskMerkleTrieGTest>>;
TYPED_TEST_SUITE(EraseTrieTest, EraseTrieType);

TYPED_TEST(TrieTest, nested_leave_one_child_on_branch_with_leaf)
{
    auto const key1 = 0x123456_bytes;
    auto const subkey2 = 0x1234_bytes;
    auto const subkey3 = 0x2345_bytes;
    auto const value = 0xdeadbeef_bytes;

    {
        UpdateList next;
        Update sub2 = make_update(subkey2, value);
        Update sub3 = make_update(subkey3, value);
        next.push_front(sub2);
        next.push_front(sub3);
        this->root = upsert_updates(
            this->aux,
            *this->sm,
            {},
            make_update(key1, value, false, std::move(next)));
    }

    {
        UpdateList next;
        Update sub2 = make_erase(subkey2);
        next.push_front(sub2);
        this->root = upsert_updates(
            this->aux,
            *this->sm,
            std::move(this->root),
            make_update(key1, value, false, std::move(next)));
    }

    EXPECT_EQ(
        this->root_hash(),
        0xeefbd82ec11d1d2d83a23d661a8eece950f1e29fa72665f07b57fc9a903257cc_bytes);
}

// Test Starts
TYPED_TEST(TrieTest, insert_one_element)
{
    // keys are the same
    auto const key =
        0x1234567812345678123456781234567812345678123456781234567812345678_bytes;
    auto const val1 =
        0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_bytes;
    auto const val2 =
        0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead_bytes;

    // single update
    this->root =
        upsert_updates(this->aux, *this->sm, {}, make_update(key, val1));
    EXPECT_EQ(
        this->root_hash(),
        0xa1aa368afa323866e03c21927db548afda3da793f4d3c646d7dd8109477b907e_bytes);

    // update again
    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_update(key, val2));
    EXPECT_EQ(
        this->root_hash(),
        0x5d225e3b0f1f386171899d343211850f102fa15de6e808c6f614915333a4f3ab_bytes);
}

TYPED_TEST(TrieTest, simple_inserts)
{
    auto const &kv = fixed_updates::kv;

    this->root = upsert_updates(
        this->aux,
        *this->sm,
        {},
        make_update(kv[0].first, kv[0].second),
        make_update(kv[1].first, kv[1].second));
    EXPECT_EQ(
        this->root_hash(),
        0x05a697d6698c55ee3e4d472c4907bca2184648bcfdd0e023e7ff7089dc984e7e_bytes);

    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[2].first, kv[2].second),
        make_update(kv[3].first, kv[3].second));
    EXPECT_EQ(
        this->root_hash(),
        0x22f3b7fc4b987d8327ec4525baf4cb35087a75d9250a8a3be45881dd889027ad_bytes);
}

TYPED_TEST(TrieTest, upsert_fixed_key_length)
{
    auto const &kv = var_len_values::kv;
    // insert kv 0,1
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        {},
        make_update(kv[0].first, kv[0].second),
        make_update(kv[1].first, kv[1].second));
    EXPECT_EQ(
        this->root_hash(),
        0xb28f388f1d98e9f2fc9daa80988cb324e0d517a86fb1f46b0bf8670728143001_bytes);

    // insert kv 2,3
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[2].first, kv[2].second),
        make_update(kv[3].first, kv[3].second));
    EXPECT_EQ(
        this->root_hash(),
        0x30175d933b55cc3528abc7083210296967ea3ccb2afeb12d966a7789e8d0fc1f_bytes);

    // insert kv 4,5,6
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[4].first, kv[4].second),
        make_update(kv[5].first, kv[5].second),
        make_update(kv[6].first, kv[6].second));
    EXPECT_EQ(
        this->root_hash(),
        0x399580bb7585999a086e9bc6f29af647019826b49ef9d84004b0b03323ddb212_bytes);

    // erases
    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_erase(kv[4].first));
    EXPECT_EQ(
        this->root_hash(),
        0x3467f96b8c7a1f9646cbee98500111b37d160ec0f02844b2bdcb89c8bcd3878a_bytes);

    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_erase(kv[6].first));
    EXPECT_EQ(
        this->root_hash(),
        0xdba3fae4737cde5014f6200508d7659ccc146b760e3a2ded47d7c422372b6b6c_bytes);

    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_erase(kv[2].first),
        make_erase(kv[3].first),
        make_erase(kv[5].first));
    EXPECT_EQ(
        this->root_hash(),
        0xb28f388f1d98e9f2fc9daa80988cb324e0d517a86fb1f46b0bf8670728143001_bytes);

    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_erase(kv[1].first));
    EXPECT_EQ(
        this->root_hash(),
        0x065ed1753a679bbde2ce3ba5af420292b86acd3fdc2ad74215d54cc10b2add72_bytes);

    // erase the last one
    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_erase(kv[0].first));
    EXPECT_EQ(this->root, nullptr);
}

TYPED_TEST(TrieTest, insert_unrelated_leaves_then_read)
{
    constexpr uint64_t version = 0;
    auto const &kv = unrelated_leaves::kv;

    this->root = upsert_updates(
        this->aux,
        *this->sm,
        {},
        make_update(kv[0].first, kv[0].second),
        make_update(kv[1].first, kv[1].second));
    EXPECT_EQ(
        this->root_hash(),
        0xc2cbdf038f464a595ac12a257d48cc2a36614f0adfd2e9a08b79c5b34b52316a_bytes);

    // two other updates for next batch
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[2].first, kv[2].second),
        make_update(kv[3].first, kv[3].second));
    EXPECT_EQ(
        this->root_hash(),
        0xd339cf4033aca65996859d35da4612b642664cc40734dbdd40738aa47f1e3e44_bytes);

    auto [leaf_it, res] =
        find_blocking(this->aux, this->root, kv[0].first, version);
    EXPECT_EQ(res, monad::mpt::find_result::success);
    EXPECT_EQ(
        (monad::byte_string_view{
            leaf_it.node->value_data(), leaf_it.node->value_len}),
        kv[0].second);
    std::tie(leaf_it, res) =
        find_blocking(this->aux, this->root, kv[1].first, version);
    EXPECT_EQ(res, monad::mpt::find_result::success);
    EXPECT_EQ(
        (monad::byte_string_view{
            leaf_it.node->value_data(), leaf_it.node->value_len}),
        kv[1].second);
    std::tie(leaf_it, res) =
        find_blocking(this->aux, this->root, kv[2].first, version);
    EXPECT_EQ(res, monad::mpt::find_result::success);
    EXPECT_EQ(
        (monad::byte_string_view{
            leaf_it.node->value_data(), leaf_it.node->value_len}),
        kv[2].second);
    std::tie(leaf_it, res) =
        find_blocking(this->aux, this->root, kv[3].first, version);
    EXPECT_EQ(res, monad::mpt::find_result::success);
    EXPECT_EQ(
        (monad::byte_string_view{
            leaf_it.node->value_data(), leaf_it.node->value_len}),
        kv[3].second);
}

TYPED_TEST(TrieTest, inserts_shorter_leaf_data)
{
    std::vector<std::pair<monad::byte_string, monad::byte_string>> const kv{
        {0x1234567812345678123456781234567812345678123456781234567812345678_bytes,
         0xdeadbeef_bytes},
        {0x1234567822345678123456781234567812345678123456781234567812345678_bytes,
         0xdeadbeefcafebabe_bytes},
        {0x1234567832345678123456781234567812345678123456781234567812345671_bytes,
         0xdeadcafe_bytes},
        {0x1234567832345678123456781234567812345678123456781234567812345678_bytes,
         0xdead_bytes}};

    std::vector<Update> update_vec;
    std::ranges::transform(
        kv, std::back_inserter(update_vec), [](auto &su) -> Update {
            auto &[k, v] = su;
            return make_update(k, monad::byte_string_view{v});
        });
    this->root = upsert_vector(this->aux, *this->sm, {}, std::move(update_vec));
    EXPECT_EQ(
        this->root_hash(),
        0xb796133251968233b84f3fcf8af88cdb42eeabe793f27835c10e8b46c91dfa4a_bytes);
}

TYPED_TEST(TrieTest, empty_trie_with_empty_update)
{
    // no update
    this->root = upsert_updates(this->aux, *this->sm, std::move(this->root));
    EXPECT_EQ(
        this->root_hash(),
        0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes);
}

////////////////////////////////////////////////////////////////////
// Erase Trie Tests
////////////////////////////////////////////////////////////////////

TYPED_TEST(EraseTrieTest, none)
{
    EXPECT_EQ(
        this->root_hash(),
        0x22f3b7fc4b987d8327ec4525baf4cb35087a75d9250a8a3be45881dd889027ad_bytes);
}

TYPED_TEST(EraseTrieTest, empty_update_list)
{
    // no update
    this->root = upsert_updates(this->aux, *this->sm, std::move(this->root));
    EXPECT_EQ(
        this->root_hash(),
        0x22f3b7fc4b987d8327ec4525baf4cb35087a75d9250a8a3be45881dd889027ad_bytes);
}

TYPED_TEST(EraseTrieTest, remove_everything)
{
    auto kv = fixed_updates::kv;

    std::vector<Update> update_vec;
    std::ranges::transform(
        kv, std::back_inserter(update_vec), [](auto &su) -> Update {
            auto &[k, v] = su;
            return make_erase(k);
        });
    this->root = upsert_vector(
        this->aux, *this->sm, std::move(this->root), std::move(update_vec));
    EXPECT_EQ(
        this->root_hash(),
        0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes);
}

TYPED_TEST(EraseTrieTest, delete_single_branch)
{
    auto kv = fixed_updates::kv;

    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_erase(kv[2].first),
        make_erase(kv[3].first));
    EXPECT_EQ(
        this->root_hash(),
        0x05a697d6698c55ee3e4d472c4907bca2184648bcfdd0e023e7ff7089dc984e7e_bytes);
}

TYPED_TEST(EraseTrieTest, delete_one_at_a_time)
{
    auto kv = fixed_updates::kv;

    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_erase(kv[2].first));
    EXPECT_EQ(
        this->root_hash(),
        0xd8b34a85db25148b1901459eac9805edadaa20b03f41fecd3b571f3b549e2774_bytes);

    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_erase(kv[1].first));
    EXPECT_EQ(
        this->root_hash(),
        0x107c8dd7bf9e7ca1faaa2c5856b412a8d7fccfa0005ca2500673a86b9c1760de_bytes);

    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_erase(kv[0].first));
    EXPECT_EQ(
        this->root_hash(),
        0x15fa9c02a40994d2d4f9c9b21daba3c4e455985490de5f9ae4889548f34d5873_bytes);

    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_erase(kv[3].first));
    EXPECT_EQ(
        this->root_hash(),
        0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes);
}

TYPED_TEST(TrieTest, nested_fixed_length_tries)
{
    std::vector<std::pair<monad::byte_string, monad::byte_string>> const kv{
        {0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbdd_bytes,
         0x0a0b_bytes},
        {0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbcc_bytes,
         0x1234_bytes}};
    std::vector<std::pair<monad::byte_string, monad::byte_string>> storage_kv{
        {0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbdd_bytes,
         0xbeef_bytes},
        {0xabcdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_bytes,
         0xdeadbeef_bytes},
        {0xabcdeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_bytes,
         0xcafe_bytes}};

    Update a = make_update(storage_kv[0].first, storage_kv[0].second);
    UpdateList storage;
    storage.push_front(a);
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        {},
        make_update(kv[0].first, kv[0].second, false, std::move(storage)),
        make_update(kv[1].first, kv[1].second));
    EXPECT_EQ(
        this->root_hash(),
        0xd02534184b896dd4cb37fb34f176cafb508aa2ebc19a773c332514ca8c65ca10_bytes);

    // update first trie mid leaf data
    // with nested storage changes but doesn't change any value
    auto acc1 = kv[0].first;
    auto new_val = 0x1234_bytes;
    storage.clear(); // NOLINT
    storage.push_front(a);
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(acc1, new_val, false, std::move(storage)));
    EXPECT_EQ(
        this->root_hash(),
        0xe9e9d8bd0c74fe45b27ac36169fd6d58a0ee4eb6573fdf6a8680be814a63d2f5_bytes);

    // update storages
    Update b = make_update(storage_kv[1].first, storage_kv[1].second);
    storage.clear(); // NOLINT
    storage.push_front(b);
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[0].first, std::move(storage)));
    EXPECT_EQ(
        this->root_hash(),
        0xc2f4c0bf52f5b277252ecfe9df3c38b44d1787b3f89febde1d29406eb06e8f93_bytes);

    // update storage again
    Update c = make_update(storage_kv[2].first, storage_kv[2].second);
    storage.clear(); // NOLINT
    storage.push_front(c);
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[0].first, std::move(storage)));
    EXPECT_EQ(
        this->root_hash(),
        0x9050b05948c3aab28121ad71b3298a887cdadc55674a5f234c34aa277fbd0325_bytes);

    // erase some storage
    storage.clear(); // NOLINT
    Update erase_b = make_erase(storage_kv[1].first);
    Update erase_c = make_erase(storage_kv[2].first);
    storage.push_front(erase_b);
    storage.push_front(erase_c);
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[0].first, std::move(storage)));
    EXPECT_EQ(
        this->root_hash(),
        0xe9e9d8bd0c74fe45b27ac36169fd6d58a0ee4eb6573fdf6a8680be814a63d2f5_bytes);

    // incarnation
    storage.clear(); // NOLINT
    storage.push_front(c);
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[0].first, new_val, true, std::move(storage)));
    EXPECT_EQ(
        this->root_hash(),
        0x2667b2bcc7c6a9afcd5a621be863fc06bf76022450e7e2e11ef792d63c7a689c_bytes);

    // insert storages to the second account
    storage.clear(); // NOLINT
    storage.push_front(a);
    storage.push_front(b);
    storage.push_front(c);
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[1].first, std::move(storage)));
    EXPECT_EQ(
        this->root_hash(),
        0x7954fcaa023fb356d6c626119220461c7859b93abd6ea71eac342d8407d7051e_bytes);

    // erase all storages of kv[0].
    storage.clear(); // NOLINT
    storage.push_front(erase_c);
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        std::move(this->root),
        make_update(kv[0].first, std::move(storage)));
    EXPECT_EQ(
        this->root_hash(),
        0x055a9738d15fb121afe470905ca2254da172da7a188d8caa690f279c10422380_bytes);

    // erase whole first account (kv[0])
    this->root = upsert_updates(
        this->aux, *this->sm, std::move(this->root), make_erase(kv[0].first));
    EXPECT_EQ(
        this->root_hash(),
        0x2c077fecb021212686442677ecd59ac2946c34e398b723cf1be431239cb11858_bytes);
}

TYPED_TEST(TrieTest, verify_correct_compute_at_section_edge)
{
    auto const prefix1 = 0x00_bytes;
    auto const prefix2 = 0x01_bytes;
    this->sm = std::make_unique<StateMachineMerkleWithPrefix<2>>();

    auto const key = 0x123456_bytes;
    auto const value = 0xdeadbeef_bytes;

    UpdateList next;
    Update update = make_update(key, value);
    next.push_front(update);

    monad::byte_string_view const empty_value{};
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        {},
        make_update(prefix1, empty_value),
        make_update(prefix2, empty_value, false, std::move(next)));

    EXPECT_EQ(this->root->child_data_len(1), 0);
    EXPECT_EQ(this->root->child_data_len(), 0);

    // leaf is the end of prefix2 section, also root of account trie
    auto &prefix2_leaf = this->root->next(1);
    EXPECT_EQ(prefix2_leaf->has_value(), true);
    EXPECT_EQ(prefix2_leaf->path_nibbles_len(), 0);
    EXPECT_EQ(prefix2_leaf->child_data_len(0), 10);
    EXPECT_EQ(prefix2_leaf->data().size(), 32);
    EXPECT_EQ(
        prefix2_leaf->data(),
        0x82efc3b165cba3705dec8fe0f7d8ec6692ae82605bdea6058d2237535dc6aa9b_bytes);
}

TYPED_TEST(TrieTest, root_data_always_hashed)
{
    auto const key1 = 0x12_bytes;
    auto const key2 = 0x13_bytes;
    auto const value1 = 0xdead_bytes;
    auto const value2 = 0xbeef_bytes;
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        {},
        make_update(key1, value1),
        make_update(key2, value2));

    EXPECT_EQ(
        this->root_hash(),
        0xfb68c0ed148bf387cff736c64cc6acff3e89a6e6d722fba9b2eaf68f24ad5761_bytes);
}

TYPED_TEST(TrieTest, aux_do_update_fixed_history_len)
{
    auto const prefix = 0x00_bytes;
    this->sm = std::make_unique<StateMachineMerkleWithPrefix<2>>();

    auto const &kv = fixed_updates::kv;
    uint64_t const start_block_id = 0x123;

    auto upsert_same_kv_once = [&](uint64_t const block_id) {
        auto u1 = make_update(kv[0].first, kv[0].second);
        auto u2 = make_update(kv[1].first, kv[1].second);
        UpdateList ul;
        ul.push_front(u1);
        ul.push_front(u2);

        auto u_prefix = Update{
            .key = prefix,
            .value = monad::byte_string_view{},
            .incarnation = false,
            .next = std::move(ul)};
        UpdateList ul_prefix;
        ul_prefix.push_front(u_prefix);
        this->root = this->aux.do_update(
            std::move(this->root),
            *this->sm,
            std::move(ul_prefix),
            block_id,
            true /*compaction*/);
        auto [state_it, res] =
            find_blocking(this->aux, this->root, prefix, block_id);
        EXPECT_EQ(res, find_result::success);
        EXPECT_EQ(
            state_it.node->data(),
            0x05a697d6698c55ee3e4d472c4907bca2184648bcfdd0e023e7ff7089dc984e7e_bytes);
        // check db maintain expected historical versions
        if (this->aux.is_on_disk()) {
            if (block_id - start_block_id <
                this->aux.version_history_length()) {
                EXPECT_EQ(
                    this->aux.db_history_max_version() -
                        this->aux.db_history_min_valid_version(),
                    block_id - start_block_id);
            }
            else {
                EXPECT_EQ(
                    this->aux.db_history_max_version() -
                        this->aux.db_history_min_valid_version(),
                    this->aux.version_history_length());
            }
        }
    };
    for (uint64_t i = 0; i < 400; ++i) {
        upsert_same_kv_once(start_block_id + i);
    }
}

TYPED_TEST(TrieTest, variable_length_trie)
{
    constexpr uint64_t version = 0;
    this->sm = std::make_unique<StateMachineAlwaysVarLen>();

    auto const key0 = 0x80_bytes;
    auto const key1 = 0x01_bytes;
    auto const key16 = 0x10_bytes;
    auto const key128 = 0x8180_bytes;
    auto const key256 = 0x820100_bytes;
    auto const keylong = 0x808182_bytes;

    auto const value = 0xbeef_bytes;

    // single element in trie
    this->root =
        upsert_updates(this->aux, *this->sm, {}, make_update(keylong, value));
    EXPECT_EQ(
        this->root_hash(),
        0x82a7b59bf8abe584aef31b580efaadbf19d0eba0e4ea8986e23db14ba9be6cb2_bytes);

    // multiple keys
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        {},
        make_update(key0, value),
        make_update(key1, value),
        make_update(key16, value),
        make_update(key128, value),
        make_update(key256, value),
        make_update(keylong, value));

    EXPECT_EQ(
        this->root_hash(),
        0x162ce2fb5920c8d988691f4e826deb4f41951ea6343d4d8894b6ea3f5fbb4be0_bytes);

    // longer value
    auto const long_value =
        0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_bytes;
    this->root = upsert_updates(
        this->aux,
        *this->sm,
        {},
        make_update(key0, long_value),
        make_update(key1, long_value),
        make_update(key16, long_value),
        make_update(key128, long_value),
        make_update(key256, long_value),
        make_update(keylong, long_value));
    EXPECT_EQ(
        this->root_hash(),
        0x1a904a5579e7f301af64aeebbce5189b9df1e534fd2a4b642e604e92834a7611_bytes);

    // find
    {
        auto [node0, res] = find_blocking(this->aux, this->root, key0, version);
        EXPECT_EQ(res, monad::mpt::find_result::success);
        EXPECT_EQ(node0.node->value(), long_value);
    }

    {
        auto [node_long, res] =
            find_blocking(this->aux, this->root, keylong, version);
        EXPECT_EQ(res, monad::mpt::find_result::success);
        EXPECT_EQ(node_long.node->value(), long_value);
    }
}

TYPED_TEST(TrieTest, variable_length_trie_with_prefix)
{
    constexpr uint64_t version = 0;
    auto const prefix = 0x00_bytes;

    this->sm = std::make_unique<StateMachineVarLenTrieWithPrefix<2>>();

    auto const key0 = 0x80_bytes;
    auto const key1 = 0x01_bytes;
    auto const key16 = 0x10_bytes;
    auto const key128 = 0x8180_bytes;
    auto const key256 = 0x820100_bytes;
    auto const keylong = 0x808182_bytes;
    auto const value =
        0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_bytes;

    std::deque<Update> updates_alloc;
    UpdateList updates;

    updates.push_front(updates_alloc.emplace_back(make_update(key0, value)));
    updates.push_front(updates_alloc.emplace_back(make_update(key1, value)));
    updates.push_front(updates_alloc.emplace_back(make_update(key16, value)));
    updates.push_front(updates_alloc.emplace_back(make_update(key128, value)));
    updates.push_front(updates_alloc.emplace_back(make_update(key256, value)));
    updates.push_front(updates_alloc.emplace_back(make_update(keylong, value)));

    auto u_prefix = make_update(prefix, monad::byte_string_view{});
    u_prefix.next = std::move(updates);
    UpdateList ul_prefix;
    ul_prefix.push_front(u_prefix);
    this->root = upsert(this->aux, 0, *this->sm, {}, std::move(ul_prefix));

    EXPECT_EQ(
        this->root->data(),
        0x1a904a5579e7f301af64aeebbce5189b9df1e534fd2a4b642e604e92834a7611_bytes);

    // find
    {
        auto [node0, res] =
            find_blocking(this->aux, this->root, prefix + key0, version);
        EXPECT_EQ(res, monad::mpt::find_result::success);
        EXPECT_EQ(node0.node->value(), value);
    }

    {
        auto [node_long, res] =
            find_blocking(this->aux, this->root, prefix + keylong, version);
        EXPECT_EQ(res, monad::mpt::find_result::success);
        EXPECT_EQ(node_long.node->value(), value);
    }
}

TYPED_TEST(TrieTest, single_value_variable_length_trie_with_prefix)
{
    auto const prefix = 0x00_bytes;
    this->sm = std::make_unique<StateMachineVarLenTrieWithPrefix<2>>();

    auto const keylong = 0x808182_bytes;
    auto const value = 0xbeef_bytes;

    UpdateList updates;
    Update u = make_update(keylong, value);
    updates.push_front(u);

    auto u_prefix = make_update(prefix, monad::byte_string_view{});
    u_prefix.next = std::move(updates);
    UpdateList ul_prefix;
    ul_prefix.push_front(u_prefix);
    this->root = upsert(this->aux, 0, *this->sm, {}, std::move(ul_prefix));

    EXPECT_EQ(
        this->root->data(),
        0x82a7b59bf8abe584aef31b580efaadbf19d0eba0e4ea8986e23db14ba9be6cb2_bytes);
}
