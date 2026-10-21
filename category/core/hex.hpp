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

#include <category/core/assert.h>
#include <category/core/byte_string.hpp>
#include <category/core/config.hpp>
#include <category/core/hex.h>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

MONAD_NAMESPACE_BEGIN

/// A type that contains a fixed-size `uint8_t bytes[N]` member spanning
/// the entire object (e.g. Address, Hash).  Used to constrain from_hex
/// so it can decode directly into the target's byte array.
template <typename T>
concept FixedBytes = requires(T const &t) {
    t.bytes;
    requires sizeof(T) == sizeof(t.bytes);
    requires std::is_bounded_array_v<
        std::remove_reference_t<decltype(t.bytes)>>;
    requires std::same_as<
        std::remove_extent_t<std::remove_reference_t<decltype(t.bytes)>>,
        uint8_t>;
};

/// Decode a single ASCII hex character ('0'-'9', 'a'-'f', 'A'-'F') to its
/// 4-bit numeric value.  Returns nullopt for non-hex characters.
constexpr std::optional<uint8_t> from_hex_char(char const c) noexcept
{
    uint8_t const n = MONAD_HEX_TO_NIBBLE_TABLE[static_cast<uint8_t>(c)];
    return n > 0 ? std::optional<uint8_t>(n - 1) : std::nullopt;
}

/// Consume the next two hex characters from @p hex and write the decoded byte
/// to @p byte.  Returns false (and does not advance @p hex or write to @p byte)
/// if fewer than two characters remain or either character is not valid hex.
constexpr bool parse_hex_byte(std::string_view &hex, uint8_t &byte) noexcept
{
    if (hex.size() < 2) {
        return false;
    }

    auto const high = from_hex_char(hex[0]);
    auto const low = from_hex_char(hex[1]);
    if (!high.has_value() || !low.has_value()) {
        return false;
    }

    byte = static_cast<uint8_t>((*high << 4) | *low);
    hex.remove_prefix(2);

    return true;
}

/// Return true if @p hex has a leading "0x" or "0X" prefix
constexpr bool has_hex_base_prefix(std::string_view const hex) noexcept
{
    return hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X');
}

/// Decode a hex string into a fixed-size byte type (e.g. Address, Hash).
/// The input may optionally start with "0x" or "0X".  If the decoded length is
/// shorter than sizeof(T), the result is right-aligned (zero-padded on the
/// left). Returns nullopt on odd-length input, excess bytes, or invalid hex.
template <FixedBytes T>
constexpr std::optional<T> from_hex(std::string_view const hex) noexcept
{
    size_t const adjusted_hex_size =
        has_hex_base_prefix(hex) ? hex.size() - 2 : hex.size();
    size_t const input_byte_count = adjusted_hex_size / 2;
    if (input_byte_count > sizeof(T)) {
        return std::nullopt;
    }
    size_t const offset = sizeof(T) - input_byte_count;
    size_t buflen = sizeof(T) - offset;
    auto ret = T{};
    int const rc =
        monad_parse_hex(hex.data(), hex.size(), ret.bytes + offset, &buflen);
    if (rc != 0 || buflen != input_byte_count) {
        return std::nullopt;
    }
    return ret;
}

/// Decode a hex string into a variable-length byte_string.
/// The input may optionally start with "0x" or "0X".  Returns nullopt on
/// odd-length input or invalid hex characters.
constexpr std::optional<byte_string> from_hex(std::string_view const hex)
{
    size_t const adjusted_hex_size =
        has_hex_base_prefix(hex) ? hex.size() - 2 : hex.size();
    size_t buflen = adjusted_hex_size / 2;
    byte_string ret;
    ret.resize(buflen);
    if (monad_parse_hex(hex.data(), hex.size(), ret.data(), &buflen) != 0 ||
        buflen != ret.size()) {
        return std::nullopt;
    }
    return ret;
}

/// Encode a 4-bit value (0-15) as a lowercase hex character.
/// Asserts that @p value < 16.
constexpr char to_hex_char(uint8_t const value) noexcept
{
    MONAD_ASSERT(value < 16);
    return MONAD_HEX_LOWER_DIGITS[value];
}

/// Encode a single byte as a two-character lowercase hex string.
constexpr std::string to_hex(uint8_t const byte)
{
    uint8_t const high = byte >> 4;
    uint8_t const low = byte & 0x0F;
    return std::string{to_hex_char(high), to_hex_char(low)};
}

/// Encode a byte sequence as a contiguous lowercase hex string (no "0x"
/// prefix).
constexpr std::string to_hex(byte_string_view const bytes)
{
    std::string ret;
    ret.resize(bytes.size() * 2);
    // Return value is safe to ignore; neither ERANGE nor EINVAL can happen
    (void)monad_format_hex(
        bytes.data(), bytes.size(), ret.data(), ret.size(), MONAD_HEX_DEFAULT);
    return ret;
}

/// Encode a FixedBytes type (e.g. Address, Hash) as a contiguous lowercase
/// hex string (no "0x" prefix), by delegating to the byte_string_view overload.
template <FixedBytes T>
std::string to_hex(T const &value)
{
    return to_hex(byte_string_view{value.bytes, sizeof(value)});
}

namespace literals
{
    /// User-defined literal for hex-encoded byte strings: `0xdeadbeef_bytes`.
    /// Throws std::bad_optional_access if the input is not valid hex.
    constexpr byte_string operator""_bytes(char const *const s)
    {
        return from_hex(s).value();
    }
}

MONAD_NAMESPACE_END
