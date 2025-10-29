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

#include <category/core/int.hpp>
#include <category/execution/ethereum/block_reward.hpp>
#include <category/execution/ethereum/core/account.hpp>
#include <category/execution/ethereum/core/address.hpp>
#include <category/execution/ethereum/core/block.hpp>
#include <category/execution/ethereum/db/trie_db.hpp>
#include <category/execution/ethereum/state2/block_state.hpp>
#include <category/execution/ethereum/state2/state_deltas.hpp>
#include <category/execution/ethereum/state3/state.hpp>
#include <category/vm/evm/traits.hpp>
#include <monad/test/traits_test.hpp>
#include <test_resource_data.h>

#include <evmc/evmc.h>
#include <evmc/evmc.hpp>

#include <intx/intx.hpp>

#include <gtest/gtest.h>

#include <optional>

using namespace monad;
using namespace monad::test;

using db_t = TrieDb;

constexpr auto a{0xbebebebebebebebebebebebebebebebebebebebe_address};
constexpr auto b{0x5353535353535353535353535353535353535353_address};
constexpr auto c{0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5_address};

TYPED_TEST(TraitsTest, apply_block_reward)
{
    InMemoryMachine machine;
    mpt::Db db{machine};
    db_t tdb{db};
    vm::VM vm;
    commit_sequential(
        tdb,
        StateDeltas{{a, StateDelta{.account = {std::nullopt, Account{}}}}},
        Code{},
        BlockHeader{});

    BlockState bs{tdb, vm};
    State as{bs, Incarnation{0, 0}};

    EXPECT_TRUE(as.account_exists(a));

    Block const block{
        .header = {.number = 10, .beneficiary = a},
        .transactions = {},
        .ommers = {
            BlockHeader{.number = 9, .beneficiary = b},
            BlockHeader{.number = 8, .beneficiary = c}}};
    apply_block_reward<typename TestFixture::Trait>(as, block);

    if constexpr (TestFixture::Trait::evm_rev() < EVMC_BYZANTIUM) {
        EXPECT_EQ(
            intx::be::load<uint256_t>(as.get_balance(a)),
            5'312'500'000'000'000'000);
        EXPECT_EQ(
            intx::be::load<uint256_t>(as.get_balance(b)),
            4'375'000'000'000'000'000);
        EXPECT_EQ(
            intx::be::load<uint256_t>(as.get_balance(c)),
            3'750'000'000'000'000'000);
    }
    else if constexpr (TestFixture::Trait::evm_rev() < EVMC_PETERSBURG) {
        EXPECT_EQ(
            intx::be::load<uint256_t>(as.get_balance(a)),
            3'187'500'000'000'000'000);
        EXPECT_EQ(
            intx::be::load<uint256_t>(as.get_balance(b)),
            2'625'000'000'000'000'000);
        EXPECT_EQ(
            intx::be::load<uint256_t>(as.get_balance(c)),
            2'250'000'000'000'000'000);
    }
    else if constexpr (TestFixture::Trait::evm_rev() < EVMC_PARIS) {
        EXPECT_EQ(
            intx::be::load<uint256_t>(as.get_balance(a)),
            2'125'000'000'000'000'000);
        EXPECT_EQ(
            intx::be::load<uint256_t>(as.get_balance(b)),
            1'750'000'000'000'000'000);
        EXPECT_EQ(
            intx::be::load<uint256_t>(as.get_balance(c)),
            1'500'000'000'000'000'000);
    }
    else {
        // No reward since Paris EIP-3675
        EXPECT_EQ(intx::be::load<uint256_t>(as.get_balance(a)), 0u);
        EXPECT_EQ(intx::be::load<uint256_t>(as.get_balance(b)), 0u);
        EXPECT_EQ(intx::be::load<uint256_t>(as.get_balance(c)), 0u);
    }
}
