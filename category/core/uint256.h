// Copyright (C) 2025-26 Category Labs, Inc.
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

#include <stdint.h>

#ifdef __cplusplus
    #include <array>

extern "C"
{
#endif

typedef struct monad_uint256_he
{
#ifdef __cplusplus
    std::array<uint64_t, 4> words_;
#else
    uint64_t words[4];
#endif
} monad_uint256_he;

constexpr monad_uint256_he MONAD_UINT256_ZERO = {};
constexpr monad_uint256_he MONAD_UINT256_ONE = {{1, 0, 0, 0}};

#ifdef __cplusplus
} // extern "C"
#endif
