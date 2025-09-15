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
 * This utility allows arbitrary span<T const> values to be formatted as their
 * underlying bytes in hexidecimal.
 */

#include <charconv>
#include <cstddef>
#include <format>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

#include <alloca.h>

#if __has_include(<category/core/config.hpp>)
    #include <category/core/config.hpp>
#else
    // When used from the execution event SDK, we're outside the execution
    // codebase and do not have config.hpp
    #define MONAD_NAMESPACE_BEGIN                                              \
        namespace monad                                                        \
        {
    #define MONAD_NAMESPACE_END }
    #define MONAD_NAMESPACE ::monad
#endif

MONAD_NAMESPACE_BEGIN

struct hexdump_bytes
{
    std::span<std::byte const> bytes;
};

template <size_t N>
hexdump_bytes as_hex(std::span<std::byte const, N> s)
{
    return {s};
}

template <typename T, size_t N>
hexdump_bytes as_hex(std::span<T const, N> s)
{
    return as_hex(std::as_bytes(s));
}

MONAD_NAMESPACE_END

template <>
struct std::formatter<MONAD_NAMESPACE::hexdump_bytes>
{
    bool alternate_form = false;
    bool uppercase = false;
    std::formatter<std::string_view> underlying_formatter;

    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        auto it = ctx.begin();
        if (it == ctx.end() || *it != '{') {
            return underlying_formatter.parse(ctx);
        }
        ++it; // Consume '{'
        if (it == ctx.end()) {
            throw std::format_error(
                "unexpected end of format string in hexdump near extension");
        }
        while (it != ctx.end() && *it != '}') {
            switch (*it) {
            case '#':
                alternate_form = true;
                break;
            case 'x':
                uppercase = false;
                break;
            case 'X':
                uppercase = true;
                break;
            default:
                throw std::format_error(
                    std::string{"unknown format string component "} + *it);
            }
            ++it;
        }
        if (it == ctx.end() || *it != '}') {
            throw std::format_error(
                "expected '}' after hex presentation specifier");
        }
        ctx.advance_to(++it); // Consume '}' and advance
        return underlying_formatter.parse(ctx);
    }

    template <typename FormatContext>
    auto
    format(MONAD_NAMESPACE::hexdump_bytes const &h, FormatContext &ctx) const
    {
        constexpr size_t MAX_ALLOCA_SIZE = 1UL << 12; // 4 KiB
        // clang-format off
        constexpr char HexdumpDigitsLower[] = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'a', 'b', 'c', 'd', 'e', 'f'};
        constexpr char HexdumpDigitsUpper[] = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'A', 'B', 'C', 'D', 'E', 'F'};
        // clang-format on

        size_t const hexdump_length =
            h.bytes.size() * 2 + (alternate_form ? 2 : 0);
        std::unique_ptr<char[]> heap_buf;
        char *fmtbuf;

        if (hexdump_length < MAX_ALLOCA_SIZE) {
            fmtbuf = static_cast<char *>(alloca(hexdump_length));
        }
        else {
            heap_buf = std::make_unique_for_overwrite<char[]>(hexdump_length);
            fmtbuf = heap_buf.get();
        }

        char *i = fmtbuf;
        if (alternate_form) {
            *i++ = '0';
            *i++ = uppercase ? 'X' : 'x';
        }
        if (uppercase) {
            for (std::byte const b : h.bytes) {
                *i++ = HexdumpDigitsUpper[std::to_underlying(b) >> 4];
                *i++ = HexdumpDigitsUpper[std::to_underlying(b) & 0xF];
            }
        }
        else {
            for (std::byte const b : h.bytes) {
                *i++ = HexdumpDigitsLower[std::to_underlying(b) >> 4];
                *i++ = HexdumpDigitsLower[std::to_underlying(b) & 0xF];
            }
        }

        std::string_view const sv{fmtbuf, static_cast<size_t>(i - fmtbuf)};
        return underlying_formatter.format(sv, ctx);
    }
};

MONAD_NAMESPACE_BEGIN

/// To format an object of type T as a hexdump of its underlying bytes,
/// derive std::formatter<T> from this base clase
template <typename T, bool alternate_form_default>
struct hexdump_formatter : std::formatter<hexdump_bytes>
{
    constexpr hexdump_formatter()
    {
        alternate_form = alternate_form_default;
    }

    template <typename FormatContext>
    auto format(T const &t, FormatContext &ctx) const
    {
        std::span const s{reinterpret_cast<std::byte const *>(&t), sizeof(t)};
        return this->std::formatter<hexdump_bytes>::format(
            hexdump_bytes{s}, ctx);
    }
};

MONAD_NAMESPACE_END
