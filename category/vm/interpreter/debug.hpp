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

#include <category/vm/evm/opcodes.hpp>
#include <category/vm/evm/traits.hpp>
#include <category/vm/interpreter/intercode.hpp>
#include <category/vm/runtime/types.hpp>

#include <evmc/evmc.h>

#include <format>
#include <iostream>

namespace monad::vm::interpreter
{
// Enable opcode tracing - always on for now
constexpr auto debug_enabled = true;

/**
 * Enhanced trace function with full opcode information.
 * This is called before each opcode execution.
 * Template parameter allows us to access the opcode_table for the current traits.
 */
template <Traits traits>
[[gnu::always_inline]]
inline void trace(
    runtime::Context const &ctx,
    Intercode const &analysis,
    std::int64_t gas_remaining_before,
    std::uint8_t const *instr_ptr,
    runtime::uint256_t const *stack_bottom,
    runtime::uint256_t const *stack_top)
{
    if (ctx.opcode_tracer == nullptr) {
        return;
    }

    auto const pc_current = static_cast<std::size_t>(instr_ptr - analysis.code());
    auto const opcode = *instr_ptr;
    auto const stack_size = static_cast<std::size_t>(stack_top - stack_bottom);

    // Get opcode info from the table
    auto const& opcode_info = compiler::opcode_table<traits>[opcode];

    // Calculate gas cost (we use min_gas as the static cost)
    // Note: Dynamic gas costs are harder to determine here without executing the instruction
    auto const gas_cost = static_cast<std::int64_t>(opcode_info.min_gas);

    // Extract context information from runtime environment
    std::uint8_t const* input_data = ctx.env.input_data;
    std::size_t input_data_size = ctx.env.input_data_size;
    std::uint8_t const* return_data = ctx.env.return_data;
    std::size_t return_data_size = ctx.env.return_data_size;


    runtime::OpcodeContext context = {
        .pc = pc_current,
        .opcode = opcode,
        .gas_remaining_before = gas_remaining_before,
        .gas_cost = gas_cost,
        .from_address = ctx.env.sender,
        .to_address = ctx.env.recipient,
        .stack_top = stack_top,
        .stack_size = stack_size,
        .memory = &ctx.memory,
        .input_data = input_data,
        .input_data_size = input_data_size,
        .return_data = return_data,
        .return_data_size = return_data_size,
        .value = ctx.env.value,
        .depth = ctx.env.depth,
    };

    ctx.opcode_tracer->on_opcode(context);
}

/**
 * Legacy trace function for backwards compatibility.
 * This version doesn't have stack access.
 */
[[gnu::always_inline]]
inline void trace(
    Intercode const &analysis,
    std::int64_t gas_remaining,
    std::uint8_t const *instr_ptr)
{
    std::cerr << std::format(
        "offset: 0x{:02x}  opcode: 0x{:x}  gas_left: {}\n",
        instr_ptr - analysis.code(),
        *instr_ptr,
        gas_remaining);
}
}
