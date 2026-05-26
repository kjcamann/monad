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

/**
 * @file
 *
 * Primitive Ethereum vocabulary types that cross C ABI boundaries. These types
 * have a well-defined C layout for the sake of cross-language interoperability,
 * but when hosted in a C++ program behave as type aliases to layout-compatible
 * types with richer interfaces, e.g., monad::uint256_t. The latter occurs only
 * if the headers are available, otherwise we'll get C structures with
 * appropriate size and alignment.
 */

// clang-format off

#ifdef __cplusplus

/*
 * C++ definitions
 */

#include <array>
#include <cstdint>

using monad_c_b64 = std::array<std::uint8_t, 8>;
using monad_c_bloom256 = std::array<std::uint8_t, 256>;

#else // #ifdef __cplusplus

/*
 * C definitions
 */

#include <stdint.h>

typedef struct monad_c_b64
{
    uint8_t bytes[8];
} monad_c_b64;

typedef struct monad_c_bloom256
{
    uint8_t bytes[256];
} monad_c_bloom256;

// clang-format on

#endif // #ifdef __cplusplus
