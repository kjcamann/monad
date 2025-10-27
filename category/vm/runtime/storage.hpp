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

#pragma once

#include <category/vm/core/assert.h>
#include <category/vm/runtime/storage_costs.hpp>
#include <category/vm/runtime/transmute.hpp>
#include <category/vm/runtime/types.hpp>
#include <category/vm/runtime/uint256.hpp>

#include <evmc/evmc.hpp>

#include <array>

namespace monad::vm::runtime
{
    template <Traits traits>
    void sload(Context *ctx, uint256_t *result_ptr, uint256_t const *key_ptr)
    {
        auto key = bytes32_from_uint256(*key_ptr);

        if constexpr (traits::eip_2929_active()) {
            auto const access_status = ctx->host->access_storage(
                ctx->context, &ctx->env.recipient, &key);
            if (access_status == EVMC_ACCESS_COLD) {
                ctx->deduct_gas(traits::cold_storage_cost());
            }
        }

        auto const value =
            ctx->host->get_storage(ctx->context, &ctx->env.recipient, &key);

        *result_ptr = uint256_from_bytes32(value);
    }

    template <Traits traits>
    void sstore(
        Context *ctx, uint256_t const *key_ptr, uint256_t const *value_ptr,
        std::int64_t remaining_block_base_gas)
    {
        if (MONAD_VM_UNLIKELY(ctx->env.evmc_flags & evmc_flags::EVMC_STATIC)) {
            ctx->exit(StatusCode::Error);
        }

        constexpr auto min_gas = minimum_store_gas<traits>();

        // EIP-2200
        if constexpr (traits::evm_rev() >= EVMC_ISTANBUL) {
            if (ctx->gas_remaining + remaining_block_base_gas + min_gas <=
                2300) {
                ctx->exit(StatusCode::OutOfGas);
            }
        }

        auto key = bytes32_from_uint256(*key_ptr);
        auto value = bytes32_from_uint256(*value_ptr);

        auto access_status = EVMC_ACCESS_COLD;
        if constexpr (traits::eip_2929_active()) {
            access_status = ctx->host->access_storage(
                ctx->context, &ctx->env.recipient, &key);
        }

        auto const storage_status = ctx->host->set_storage(
            ctx->context, &ctx->env.recipient, &key, &value);

        auto [gas_used, gas_refund] = store_cost<traits>(storage_status);

        // The code generator has taken care of accounting for the minimum base
        // gas cost of this SSTORE already, but to keep the table of costs
        // readable it encodes the total gas usage of each combination, rather
        // than the amount relative to the minimum gas.
        gas_used -= min_gas;

        if constexpr (traits::eip_2929_active()) {
            if (access_status == EVMC_ACCESS_COLD) {
                gas_used += traits::cold_storage_cost() + min_gas;
            }
        }

        ctx->gas_refund += gas_refund;
        ctx->deduct_gas(gas_used);
    }

    inline void
    tload(Context *ctx, uint256_t *result_ptr, uint256_t const *key_ptr)
    {
        auto key = bytes32_from_uint256(*key_ptr);

        auto const value = ctx->host->get_transient_storage(
            ctx->context, &ctx->env.recipient, &key);

        *result_ptr = uint256_from_bytes32(value);
    }

    inline void
    tstore(Context *ctx, uint256_t const *key_ptr, uint256_t const *val_ptr)
    {
        if (MONAD_VM_UNLIKELY(ctx->env.evmc_flags & evmc_flags::EVMC_STATIC)) {
            ctx->exit(StatusCode::Error);
        }

        auto key = bytes32_from_uint256(*key_ptr);
        auto val = bytes32_from_uint256(*val_ptr);

        ctx->host->set_transient_storage(
            ctx->context, &ctx->env.recipient, &key, &val);
    }

    bool debug_tstore_stack(
        Context const *ctx, uint256_t const *stack, uint64_t stack_size,
        uint64_t offset, uint64_t base_offset);
}
