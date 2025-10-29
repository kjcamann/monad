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

#include <category/core/hex.hpp>
#include <category/vm/runtime/base_ctypes.h>

#include <cstddef>
#include <cstring>
#include <format>

#if MONAD_EVENT_HAS_LIBGMP
    #include <category/core/assert.h>
    #include <gmp.h>
    #include <iterator>
    #include <string_view>
#endif

#if !MONAD_EVENT_SDK_EXTERNAL
    #include <category/core/int.hpp>
#endif

template <>
struct std::formatter<monad_c_address>
    : MONAD_NAMESPACE::hexdump_formatter<monad_c_address, true>
{
};

template <>
struct std::formatter<monad_c_bytes32>
    : MONAD_NAMESPACE::hexdump_formatter<monad_c_bytes32, true>
{
};

/// A simple formatter for uint256 values; this is not feature complete and
/// has a number of weaknesses. When the value fits in __uin128_t, this reuses
/// std::formatter<__uint128_t> and as a result, supports the full format
/// specification. When larger, it uses libgmp if that is available, otherwise
/// it prints the hex values of the limb representation.
template <>
struct std::formatter<monad_c_uint256_ne> : std::formatter<__uint128_t>
{
    template <typename FormatContext>
    auto format(monad_c_uint256_ne const &value, FormatContext &ctx) const
    {
        if (value.limbs[2] == 0 && value.limbs[3] == 0) {
            // When the high 128 bits are zero, truncate to __uint128_t and
            // format using the builtin formatter
            __uint128_t v;
            std::memcpy(&v, value.limbs, sizeof v);
            return this->std::formatter<__uint128_t>::format(v, ctx);
        }
#if MONAD_EVENTCAP_HAS_LIBGMP
        // Formatting > uint128_t with the help of libgmp. The ideal way to do
        // this would be:
        //
        //   1. Add a custom parse method that makes a best-efforts translation
        //      of the C++20 <format> argument format specification to its
        //      closest printf equivalent; printf supports a near proper subset
        //      of the <format> features
        //
        //   2. Use gmp_snprintf to produce the output
        //
        // Because step 1 is a lot of work, it is not done here. Instead we use
        // gmp_snprintf with the default settings, which always print as an
        // unsigned decimal and will ignore any width and flag settings.
        //
        // TODO(ken): eventually do what it says above
        char buf[128];
        int const formatted_size = gmp_snprintf(
            buf, sizeof buf, "%Nu", value.limbs, std::size(value.limbs));
        if (formatted_size < 0) {
            return std::format_to(
                ctx.out(), "gmp_snprintf error: {}", formatted_size);
        }
        MONAD_ASSERT(
            static_cast<size_t>(formatted_size) < sizeof buf,
            "overflow possible without a width field?");
        std::string_view const sv{buf, static_cast<size_t>(formatted_size)};
        return std::format_to(ctx.out(), "{}", sv);
#elif !MONAD_EVENT_SDK_EXTERNAL
        // We're compiling as part of execution daemon; use intx
        return std::format_to(ctx.out(), intx::to_string(value, 10));
#else
        return std::format_to(ctx.out(), "{::#x}", value.limbs);
#endif
    }
};
