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

#include <category/core/config.hpp>

#include <evmc/bytes.hpp>
#include <evmc/hex.hpp>

#include <array>
#include <cstddef>

MONAD_NAMESPACE_BEGIN

using byte_string = evmc::bytes;

template <size_t N>
using byte_string_fixed = std::array<unsigned char, N>;

using byte_string_view = evmc::bytes_view;

template <size_t N>
constexpr byte_string_view to_byte_string_view(unsigned char const (&a)[N])
{
    return {&a[0], N};
}

template <class T, size_t N>
constexpr byte_string_view to_byte_string_view(std::array<T, N> const &a)
{
    return {a.data(), N};
}

inline byte_string_view to_byte_string_view(std::string const &s)
{
    return {reinterpret_cast<unsigned char const *>(&s[0]), s.size()};
}

namespace literals
{
    inline byte_string operator""_bytes(char const *s)
    {
        return evmc::from_hex(s).value();
    }
};

MONAD_NAMESPACE_END
